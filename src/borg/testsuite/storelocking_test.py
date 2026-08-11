import datetime
import hashlib
import json
import os
import random
import time
from pathlib import Path

import pytest

from borgstore.store import ObjectNotFound, Store

from ..platform import get_process_id, process_alive
from ..storelocking import Lock, NotLocked, LockTimeout

ID1 = "foo", 1, 1
ID2 = "bar", 2, 2


@pytest.fixture()
def free_pid():
    """Return a free PID not used by any process (naturally this is racy)."""
    host, pid, tid = get_process_id()
    while True:
        # PIDs are often restricted to a small range. On Linux the range >32k is by default not used.
        pid = random.randint(33000, 65000)
        if not process_alive(host, pid, tid):
            return pid


@pytest.fixture()
def lockstore(tmp_path):
    store = Store(Path(tmp_path / "lockstore").as_uri(), config={"locks/": {"levels": [0]}})
    store.create()
    with store:
        yield store
    store.destroy()


def write_raw_lock(store, id, *, exclusive, dt, mtime=None):
    """
    Write a lock object like Lock._create_lock does, but with an arbitrary content timestamp <dt>
    (simulating a writer whose clock is skewed against ours). The object's store-side mtime is
    "now" (a real store write), unless <mtime> is given (then the file's mtime is set to it).
    """
    timestamp = dt.isoformat(timespec="milliseconds")
    lock = dict(exclusive=exclusive, hostid=id[0], processid=id[1], threadid=id[2], time=timestamp)
    value = json.dumps(lock).encode("utf-8")
    key = hashlib.sha256(value).hexdigest()
    store.store(f"locks/{key}", value)
    if mtime is not None:
        path = store.backend.base_path / "locks" / key  # posixfs, locks/ nesting levels [0]
        os.utime(path, (mtime, mtime))
    return key


class TestLock:
    def test_cm(self, lockstore):
        with Lock(lockstore, exclusive=True, id=ID1) as lock:
            assert lock.got_exclusive_lock()
        with Lock(lockstore, exclusive=False, id=ID1) as lock:
            assert not lock.got_exclusive_lock()

    def test_got_exclusive_lock(self, lockstore):
        lock = Lock(lockstore, exclusive=True, id=ID1)
        assert not lock.got_exclusive_lock()
        lock.acquire()
        assert lock.got_exclusive_lock()
        lock.release()
        assert not lock.got_exclusive_lock()

    def test_exclusive_lock(self, lockstore):
        # There must not be two exclusive locks.
        with Lock(lockstore, exclusive=True, id=ID1):
            with pytest.raises(LockTimeout):
                Lock(lockstore, exclusive=True, id=ID2).acquire()
        # Acquiring an exclusive lock will time out if the non-exclusive lock does not go away.
        with Lock(lockstore, exclusive=False, id=ID1):
            with pytest.raises(LockTimeout):
                Lock(lockstore, exclusive=True, id=ID2).acquire()

    def test_exclusive_lock_timeout_leaves_no_lock(self, lockstore):
        # When acquiring an exclusive lock times out because a non-exclusive lock does not go away,
        # the not-acquired exclusive lock must not stay behind in the store: it would block all
        # other clients (even on other hosts) until it expired as stale.
        with Lock(lockstore, exclusive=False, id=ID1) as shared_lock:
            with pytest.raises(LockTimeout):
                Lock(lockstore, exclusive=True, id=ID2).acquire()
            locks = shared_lock._get_locks()
            assert len(locks) == 1  # only the non-exclusive lock of ID1 is left
            assert not any(lock["exclusive"] for lock in locks.values())

    def test_double_nonexclusive_lock_succeeds(self, lockstore):
        with Lock(lockstore, exclusive=False, id=ID1):
            with Lock(lockstore, exclusive=False, id=ID2):
                pass

    def test_not_locked(self, lockstore):
        lock = Lock(lockstore, exclusive=True, id=ID1)
        with pytest.raises(NotLocked):
            lock.release()
        lock = Lock(lockstore, exclusive=False, id=ID1)
        with pytest.raises(NotLocked):
            lock.release()

    def test_break_lock(self, lockstore):
        lock = Lock(lockstore, exclusive=True, id=ID1).acquire()
        lock.break_lock()
        with Lock(lockstore, exclusive=True, id=ID2):
            pass
        with Lock(lockstore, exclusive=True, id=ID1):
            pass

    def test_lock_refresh_stale_removal(self, lockstore):
        # stale after 2s, refreshable after 1s
        lock = Lock(lockstore, exclusive=True, id=ID1, stale=2)
        lock.acquire()
        lock_keys_a00 = set(lock._get_locks())
        time.sleep(0.5)
        lock.refresh()  # Should not change locks; existing lock is too young.
        lock_keys_a05 = set(lock._get_locks())
        time.sleep(0.6)
        lock.refresh()  # This should refresh the lock.
        lock_keys_b00 = set(lock._get_locks())
        time.sleep(2.1)
        # now the lock is stale. we never consider the lock we hold ourselves stale,
        # but another client (== another Lock instance) does. a client without a lock object
        # of its own can not confirm staleness in the store's clock domain yet (see #9870),
        # so a plain listing defers the kill:
        other_lock = Lock(lockstore, exclusive=True, id=ID2, stale=2)
        lock_keys_b21 = set(other_lock._get_locks())
        assert lock_keys_a00 == lock_keys_a05  # was too young, no refresh done
        assert len(lock_keys_a00) == 1
        assert lock_keys_a00 != lock_keys_b00  # refresh done, new lock has different key
        assert len(lock_keys_b00) == 1
        assert lock_keys_b21 == lock_keys_b00  # stale, but kill deferred (no store time reference yet)
        # acquire() creates other_lock's own lock object first, then confirms the staleness
        # in the store's clock domain and kills the stale lock:
        other_lock.acquire()
        other_lock.release()
        assert len(list(lock.store.list("locks"))) == 0  # stale lock was removed from store

    def test_release_stale_lock(self, lockstore):
        # even if our own lock became stale (e.g. machine suspended while doing a backup or
        # a long time without repository access), release() must find and remove it instead
        # of removing it as stale and then raising NotLocked, see #9883.
        lock = Lock(lockstore, exclusive=True, id=ID1, stale=2)
        lock.acquire()
        time.sleep(2.1)  # lock is now older than the stale timeout
        lock.release()  # must not raise NotLocked
        assert len(list(lockstore.list("locks"))) == 0

    def test_refresh_stale_lock(self, lockstore):
        # if our own lock became stale, but no other client killed it (it is still present),
        # refresh() must renew it, so the operation can continue safely, see #9883.
        lock = Lock(lockstore, exclusive=True, id=ID1, stale=2)
        lock.acquire()
        old_keys = set(lock._get_locks())
        time.sleep(2.1)  # lock is now older than the stale timeout
        lock.refresh()  # must not raise LockTimeout, must renew the lock
        new_keys = set(lock._get_locks())
        assert len(old_keys) == len(new_keys) == 1
        assert old_keys != new_keys  # refresh done, new lock has different key
        lock.release()

    def test_refresh_killed_lock(self, lockstore):
        # if our own lock is gone (another client considered it stale and killed it),
        # there is no safe way to continue, refresh() must raise LockTimeout.
        lock = Lock(lockstore, exclusive=True, id=ID1, stale=2)
        lock.acquire()
        time.sleep(1.1)  # older than refresh_td (stale // 2), so refresh() checks the store
        Lock(lockstore, exclusive=True, id=ID2, stale=2).break_lock()  # kill it, like another client would
        with pytest.raises(LockTimeout):
            lock.refresh()

    def test_refresh_killed_lock_race(self, lockstore, monkeypatch):
        # if our own lock gets killed by another client *between* refresh() listing it and
        # deleting it (the other client considered it stale and might have acquired its own
        # lock already), refresh() must raise LockTimeout and must not leave its just-created
        # new lock behind (it would needlessly block other clients until it expired as stale).
        lock = Lock(lockstore, exclusive=True, id=ID1, stale=2)
        lock.acquire()
        old_key = lock.my_lock_key
        time.sleep(1.1)  # older than refresh_td (stale // 2), so refresh() will renew the lock

        orig_delete = lockstore.delete

        def delete(name, *args, **kwargs):
            if name == f"locks/{old_key}":
                orig_delete(name)  # another client killed our old lock just before we delete it,
                # so our own deletion attempt below finds it already gone and raises ObjectNotFound:
            return orig_delete(name, *args, **kwargs)

        monkeypatch.setattr(lockstore, "delete", delete)
        with pytest.raises(LockTimeout):
            lock.refresh()
        assert len(list(lockstore.list("locks"))) == 0  # no new lock left behind

    def test_lock_vanished_between_list_and_load(self, lockstore, monkeypatch):
        # another client can delete a lock (e.g. kill it as stale, or its owner releases it)
        # between our listing and our loading of it - such a lock must be skipped, not crash us.
        foreign_key = Lock(lockstore, id=ID1)._create_lock(exclusive=True)

        orig_load = lockstore.load

        def load_vanished(name, *args, **kwargs):
            if name == f"locks/{foreign_key}":
                raise ObjectNotFound(name)
            return orig_load(name, *args, **kwargs)

        monkeypatch.setattr(lockstore, "load", load_vanished)
        lock = Lock(lockstore, exclusive=True, id=ID2)
        assert foreign_key not in lock._get_locks()  # skipped, no exception
        lock.acquire()  # the vanished exclusive lock must not block us
        lock.release()

    def test_skewed_writer_healthy_lock_not_killed(self, lockstore):
        # a lock whose content timestamp looks stale (its writer's clock runs >stale behind ours),
        # but whose store-side mtime shows it was written just now: it must NOT be killed - killing
        # a healthy lock enables compact to delete chunks a running backup references, see #9870.
        dt = datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=40)
        foreign_key = write_raw_lock(lockstore, ID1, exclusive=False, dt=dt)  # store mtime: now
        # a shared lock can coexist with it - and must warn about the skew:
        lock = Lock(lockstore, exclusive=False, id=ID2)
        lock.acquire()
        assert lock.skew_warned
        assert foreign_key in lock._get_locks()  # healthy foreign lock survived
        lock.release()
        # an exclusive lock must NOT be obtainable by killing the healthy shared lock:
        with pytest.raises(LockTimeout):
            Lock(lockstore, exclusive=True, id=ID2).acquire()
        assert f"locks/{foreign_key}" in [f"locks/{k}" for k in Lock(lockstore, id=ID2)._get_locks()]

    def test_stale_lock_killed_when_both_clock_domains_agree(self, lockstore):
        # a lock that is stale in both clock domains (old content timestamp AND old store-side
        # mtime) is really stale and must be killed during acquire().
        dt = datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=40)
        foreign_key = write_raw_lock(lockstore, ID1, exclusive=True, dt=dt, mtime=dt.timestamp())
        lock = Lock(lockstore, exclusive=True, id=ID2)
        lock.acquire()  # must succeed: the stale exclusive lock gets confirmed stale and killed
        assert not lock.skew_warned
        locks = lock._get_locks()
        assert foreign_key not in locks
        assert lock.my_lock_key in locks
        lock.release()

    def test_skew_warning_below_stale_threshold(self, lockstore):
        # a live lock whose writer's clock runs 10 minutes ahead of ours: far from the stale
        # threshold, but still worth a warning (e.g. concurrent manifest writes could produce
        # a spurious RepositoryReplay later), see #9870.
        dt = datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=10)
        write_raw_lock(lockstore, ID1, exclusive=False, dt=dt)  # store mtime: now
        lock = Lock(lockstore, exclusive=False, id=ID2)
        lock.acquire()
        assert lock.skew_warned
        lock.release()

    def test_no_skew_warning_for_small_offsets(self, lockstore):
        # small clock differences (well below MAX_MUTUAL_CLOCK_SKEW) must not warn.
        dt = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=60)
        write_raw_lock(lockstore, ID1, exclusive=False, dt=dt)  # store mtime: now
        lock = Lock(lockstore, exclusive=False, id=ID2)
        lock.acquire()
        assert not lock.skew_warned
        lock.release()

    def test_dead_process_lock_killed_despite_fresh_store_mtime(self, lockstore, free_pid):
        # knowing locally that the lock-owning process (on THIS machine) is dead must not be
        # vetoable by store-side timestamps: a store serving bogus, always-fresh mtimes could
        # otherwise keep an abandoned lock alive forever and block us, see #9870.
        host, _, tid = get_process_id()
        dead_id = (host, free_pid, tid)
        dt = datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=40)
        dead_key = write_raw_lock(lockstore, dead_id, exclusive=True, dt=dt)  # store mtime: now (fresh)
        lock = Lock(lockstore, exclusive=True, id=ID2)
        # killed on a plain listing already - no store time reference of our own needed:
        assert dead_key not in lock._get_locks()
        lock.acquire()  # the exclusive lock must be obtainable
        lock.release()

    def test_stale_kill_legacy_behavior_without_mtime(self, lockstore, monkeypatch):
        # if the backend can not provide store-side mtimes (e.g. rclone, mtime == 0), staleness
        # is judged by the content timestamp alone, like before #9870 - even on a plain listing.
        dt = datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=40)
        foreign_key = write_raw_lock(lockstore, ID1, exclusive=True, dt=dt)

        orig_list = lockstore.list

        def list_no_mtime(name, *args, **kwargs):
            for info in orig_list(name, *args, **kwargs):
                yield info._replace(mtime=0)

        monkeypatch.setattr(lockstore, "list", list_no_mtime)
        lock = Lock(lockstore, exclusive=True, id=ID2)
        locks = lock._get_locks()  # legacy: killed right away, no store-domain cross-check possible
        assert foreign_key not in locks
        assert len(list(orig_list("locks"))) == 0

    def test_migrate_lock(self, lockstore):
        old_id, new_id = ID1, ID2
        assert old_id[1] != new_id[1]  # different PIDs (like when doing daemonize())
        lock = Lock(lockstore, id=old_id).acquire()
        old_locks = lock._find_locks(only_mine=True)
        assert lock.id == old_id  # lock is for old id / PID
        lock.migrate_lock(old_id, new_id)  # fix the lock
        assert lock.id == new_id  # lock corresponds to the new id / PID
        new_locks = lock._find_locks(only_mine=True)
        assert old_locks != new_locks
        assert len(old_locks) == len(new_locks) == 1
        assert old_locks[0]["hostid"] == old_id[0]
        assert new_locks[0]["hostid"] == new_id[0]

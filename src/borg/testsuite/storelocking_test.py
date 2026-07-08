import time
from pathlib import Path

import pytest

from borgstore.store import Store

from ..storelocking import Lock, NotLocked, LockTimeout

ID1 = "foo", 1, 1
ID2 = "bar", 2, 2


@pytest.fixture()
def lockstore(tmp_path):
    store = Store(Path(tmp_path / "lockstore").as_uri(), config={"locks/": {"levels": [0]}})
    store.create()
    with store:
        yield store
    store.destroy()


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
        # but another client (== another Lock instance) does:
        other_lock = Lock(lockstore, exclusive=True, id=ID2, stale=2)
        lock_keys_b21 = set(other_lock._get_locks())  # now the lock should be stale & gone.
        assert lock_keys_a00 == lock_keys_a05  # was too young, no refresh done
        assert len(lock_keys_a00) == 1
        assert lock_keys_a00 != lock_keys_b00  # refresh done, new lock has different key
        assert len(lock_keys_b00) == 1
        assert len(lock_keys_b21) == 0  # stale lock was ignored
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

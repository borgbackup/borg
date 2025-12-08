import time
from pathlib import Path

import pytest

from borgstore.store import Store

from ..storelocking import Lock, NotLocked, LockTimeout

ID1 = "foo", 1, 1
ID2 = "bar", 2, 2


@pytest.fixture()
def lockstore(tmpdir):
    store = Store(Path(tmpdir / "lockstore").as_uri(), levels={"locks/": [0]})
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
        lock_keys_b21 = set(lock._get_locks())  # now the lock should be stale & gone.
        assert lock_keys_a00 == lock_keys_a05  # was too young, no refresh done
        assert len(lock_keys_a00) == 1
        assert lock_keys_a00 != lock_keys_b00  # refresh done, new lock has different key
        assert len(lock_keys_b00) == 1
        assert len(lock_keys_b21) == 0  # stale lock was ignored
        assert len(list(lock.store.list("locks"))) == 0  # stale lock was removed from store

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

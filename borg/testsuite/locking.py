import time

import pytest

from ..locking import get_id, TimeoutTimer, ExclusiveLock, Lock, LockRoster, \
                      ADD, REMOVE, SHARED, EXCLUSIVE, LockTimeout


ID1 = "foo", 1, 1
ID2 = "bar", 2, 2


def test_id():
    hostname, pid, tid = get_id()
    assert isinstance(hostname, str)
    assert isinstance(pid, int)
    assert isinstance(tid, int)
    assert len(hostname) > 0
    assert pid > 0


class TestTimeoutTimer:
    def test_timeout(self):
        timeout = 0.5
        t = TimeoutTimer(timeout).start()
        assert not t.timed_out()
        time.sleep(timeout * 1.5)
        assert t.timed_out()

    def test_notimeout_sleep(self):
        timeout, sleep = None, 0.5
        t = TimeoutTimer(timeout, sleep).start()
        assert not t.timed_out_or_sleep()
        assert time.time() >= t.start_time + 1 * sleep
        assert not t.timed_out_or_sleep()
        assert time.time() >= t.start_time + 2 * sleep


@pytest.fixture()
def lockpath(tmpdir):
    return str(tmpdir.join('lock'))


class TestExclusiveLock:
    def test_checks(self, lockpath):
        with ExclusiveLock(lockpath, timeout=1) as lock:
            assert lock.is_locked() and lock.by_me()

    def test_acquire_break_reacquire(self, lockpath):
        lock = ExclusiveLock(lockpath, id=ID1).acquire()
        lock.break_lock()
        with ExclusiveLock(lockpath, id=ID2):
            pass

    def test_timeout(self, lockpath):
        with ExclusiveLock(lockpath, id=ID1):
            with pytest.raises(LockTimeout):
                ExclusiveLock(lockpath, id=ID2, timeout=0.1).acquire()

    def test_migrate_lock(self, lockpath):
        old_id, new_id = ID1, ID2
        assert old_id[1] != new_id[1]  # different PIDs (like when doing daemonize())
        lock = ExclusiveLock(lockpath, id=old_id).acquire()
        assert lock.id == old_id  # lock is for old id / PID
        old_unique_name = lock.unique_name
        assert lock.by_me()  # we have the lock
        lock.migrate_lock(old_id, new_id)  # fix the lock
        assert lock.id == new_id  # lock corresponds to the new id / PID
        new_unique_name = lock.unique_name
        assert lock.by_me()  # we still have the lock
        assert old_unique_name != new_unique_name  # locking filename is different now


class TestLock:
    def test_shared(self, lockpath):
        lock1 = Lock(lockpath, exclusive=False, id=ID1).acquire()
        lock2 = Lock(lockpath, exclusive=False, id=ID2).acquire()
        assert len(lock1._roster.get(SHARED)) == 2
        assert len(lock1._roster.get(EXCLUSIVE)) == 0
        assert not lock1._roster.empty(SHARED, EXCLUSIVE)
        assert lock1._roster.empty(EXCLUSIVE)
        lock1.release()
        lock2.release()

    def test_exclusive(self, lockpath):
        with Lock(lockpath, exclusive=True, id=ID1) as lock:
            assert len(lock._roster.get(SHARED)) == 0
            assert len(lock._roster.get(EXCLUSIVE)) == 1
            assert not lock._roster.empty(SHARED, EXCLUSIVE)

    def test_upgrade(self, lockpath):
        with Lock(lockpath, exclusive=False) as lock:
            lock.upgrade()
            lock.upgrade()  # NOP
            assert len(lock._roster.get(SHARED)) == 0
            assert len(lock._roster.get(EXCLUSIVE)) == 1
            assert not lock._roster.empty(SHARED, EXCLUSIVE)

    def test_downgrade(self, lockpath):
        with Lock(lockpath, exclusive=True) as lock:
            lock.downgrade()
            lock.downgrade()  # NOP
            assert len(lock._roster.get(SHARED)) == 1
            assert len(lock._roster.get(EXCLUSIVE)) == 0

    def test_got_exclusive_lock(self, lockpath):
        lock = Lock(lockpath, exclusive=True, id=ID1)
        assert not lock.got_exclusive_lock()
        lock.acquire()
        assert lock.got_exclusive_lock()
        lock.release()
        assert not lock.got_exclusive_lock()

    def test_break(self, lockpath):
        lock = Lock(lockpath, exclusive=True, id=ID1).acquire()
        lock.break_lock()
        assert len(lock._roster.get(SHARED)) == 0
        assert len(lock._roster.get(EXCLUSIVE)) == 0
        with Lock(lockpath, exclusive=True, id=ID2):
            pass

    def test_timeout(self, lockpath):
        with Lock(lockpath, exclusive=False, id=ID1):
            with pytest.raises(LockTimeout):
                Lock(lockpath, exclusive=True, id=ID2, timeout=0.1).acquire()
        with Lock(lockpath, exclusive=True, id=ID1):
            with pytest.raises(LockTimeout):
                Lock(lockpath, exclusive=False, id=ID2, timeout=0.1).acquire()
        with Lock(lockpath, exclusive=True, id=ID1):
            with pytest.raises(LockTimeout):
                Lock(lockpath, exclusive=True, id=ID2, timeout=0.1).acquire()

    def test_migrate_lock(self, lockpath):
        old_id, new_id = ID1, ID2
        assert old_id[1] != new_id[1]  # different PIDs (like when doing daemonize())

        lock = Lock(lockpath, id=old_id, exclusive=True).acquire()
        assert lock.id == old_id
        lock.migrate_lock(old_id, new_id)  # fix the lock
        assert lock.id == new_id
        lock.release()

        lock = Lock(lockpath, id=old_id, exclusive=False).acquire()
        assert lock.id == old_id
        lock.migrate_lock(old_id, new_id)  # fix the lock
        assert lock.id == new_id
        lock.release()


@pytest.fixture()
def rosterpath(tmpdir):
    return str(tmpdir.join('roster'))


class TestLockRoster:
    def test_empty(self, rosterpath):
        roster = LockRoster(rosterpath)
        empty = roster.load()
        roster.save(empty)
        assert empty == {}

    def test_modify_get(self, rosterpath):
        roster1 = LockRoster(rosterpath, id=ID1)
        assert roster1.get(SHARED) == set()
        roster1.modify(SHARED, ADD)
        assert roster1.get(SHARED) == {ID1, }
        roster2 = LockRoster(rosterpath, id=ID2)
        roster2.modify(SHARED, ADD)
        assert roster2.get(SHARED) == {ID1, ID2, }
        roster1 = LockRoster(rosterpath, id=ID1)
        roster1.modify(SHARED, REMOVE)
        assert roster1.get(SHARED) == {ID2, }
        roster2 = LockRoster(rosterpath, id=ID2)
        roster2.modify(SHARED, REMOVE)
        assert roster2.get(SHARED) == set()

    def test_migrate_lock(self, rosterpath):
        old_id, new_id = ID1, ID2
        assert old_id[1] != new_id[1]  # different PIDs (like when doing daemonize())
        roster = LockRoster(rosterpath, id=old_id)
        assert roster.id == old_id
        roster.modify(SHARED, ADD)
        assert roster.get(SHARED) == {old_id}
        roster.migrate_lock(SHARED, old_id, new_id)  # fix the lock
        assert roster.id == new_id
        assert roster.get(SHARED) == {new_id}

import time

import pytest

from ..locking import get_id, TimeoutTimer, ExclusiveLock, UpgradableLock, LockRoster, \
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


class TestUpgradableLock:
    def test_shared(self, lockpath):
        lock1 = UpgradableLock(lockpath, exclusive=False, id=ID1).acquire()
        lock2 = UpgradableLock(lockpath, exclusive=False, id=ID2).acquire()
        assert len(lock1._roster.get(SHARED)) == 2
        assert len(lock1._roster.get(EXCLUSIVE)) == 0
        lock1.release()
        lock2.release()

    def test_exclusive(self, lockpath):
        with UpgradableLock(lockpath, exclusive=True, id=ID1) as lock:
            assert len(lock._roster.get(SHARED)) == 0
            assert len(lock._roster.get(EXCLUSIVE)) == 1

    def test_upgrade(self, lockpath):
        with UpgradableLock(lockpath, exclusive=False) as lock:
            lock.upgrade()
            lock.upgrade()  # NOP
            assert len(lock._roster.get(SHARED)) == 0
            assert len(lock._roster.get(EXCLUSIVE)) == 1

    def test_downgrade(self, lockpath):
        with UpgradableLock(lockpath, exclusive=True) as lock:
            lock.downgrade()
            lock.downgrade()  # NOP
            assert len(lock._roster.get(SHARED)) == 1
            assert len(lock._roster.get(EXCLUSIVE)) == 0

    def test_break(self, lockpath):
        lock = UpgradableLock(lockpath, exclusive=True, id=ID1).acquire()
        lock.break_lock()
        assert len(lock._roster.get(SHARED)) == 0
        assert len(lock._roster.get(EXCLUSIVE)) == 0
        with UpgradableLock(lockpath, exclusive=True, id=ID2):
            pass

    def test_timeout(self, lockpath):
        with UpgradableLock(lockpath, exclusive=False, id=ID1):
            with pytest.raises(LockTimeout):
                UpgradableLock(lockpath, exclusive=True, id=ID2, timeout=0.1).acquire()
        with UpgradableLock(lockpath, exclusive=True, id=ID1):
            with pytest.raises(LockTimeout):
                UpgradableLock(lockpath, exclusive=False, id=ID2, timeout=0.1).acquire()
        with UpgradableLock(lockpath, exclusive=True, id=ID1):
            with pytest.raises(LockTimeout):
                UpgradableLock(lockpath, exclusive=True, id=ID2, timeout=0.1).acquire()


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

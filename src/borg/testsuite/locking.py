import random
import time
from threading import Thread, Lock as ThreadingLock
from traceback import format_exc

import pytest

from ..platform import get_process_id, process_alive
from ..locking import (
    TimeoutTimer,
    ExclusiveLock,
    Lock,
    LockRoster,
    ADD,
    REMOVE,
    SHARED,
    EXCLUSIVE,
    LockTimeout,
    NotLocked,
    NotMyLock,
)

ID1 = "foo", 1, 1
ID2 = "bar", 2, 2
RACE_TEST_NUM_THREADS = 40
RACE_TEST_DURATION = 0.4  # seconds


@pytest.fixture()
def free_pid():
    """Return a free PID not used by any process (naturally this is racy)"""
    host, pid, tid = get_process_id()
    while True:
        # PIDs are often restricted to a small range. On Linux the range >32k is by default not used.
        pid = random.randint(33000, 65000)
        if not process_alive(host, pid, tid):
            return pid


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
    return str(tmpdir.join("lock"))


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

    def test_kill_stale(self, lockpath, free_pid):
        host, pid, tid = our_id = get_process_id()
        dead_id = host, free_pid, tid
        cant_know_if_dead_id = "foo.bar.example.net", 1, 2

        dead_lock = ExclusiveLock(lockpath, id=dead_id).acquire()
        with ExclusiveLock(lockpath, id=our_id):
            with pytest.raises(NotMyLock):
                dead_lock.release()
        with pytest.raises(NotLocked):
            dead_lock.release()

        with ExclusiveLock(lockpath, id=cant_know_if_dead_id):
            with pytest.raises(LockTimeout):
                ExclusiveLock(lockpath, id=our_id, timeout=0.1).acquire()

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

    def test_race_condition(self, lockpath):
        class SynchronizedCounter:
            def __init__(self, count=0):
                self.lock = ThreadingLock()
                self.count = count
                self.maxcount = count

            def value(self):
                with self.lock:
                    return self.count

            def maxvalue(self):
                with self.lock:
                    return self.maxcount

            def incr(self):
                with self.lock:
                    self.count += 1
                    if self.count > self.maxcount:
                        self.maxcount = self.count
                    return self.count

            def decr(self):
                with self.lock:
                    self.count -= 1
                    return self.count

        def print_locked(msg):
            with print_lock:
                print(msg)

        def acquire_release_loop(
            id, timeout, thread_id, lock_owner_counter, exception_counter, print_lock, last_thread=None
        ):
            print_locked(
                "Thread %2d: Starting acquire_release_loop(id=%s, timeout=%d); lockpath=%s"
                % (thread_id, id, timeout, lockpath)
            )
            timer = TimeoutTimer(timeout, -1).start()
            cycle = 0

            while not timer.timed_out():
                cycle += 1
                try:
                    with ExclusiveLock(
                        lockpath, id=id, timeout=timeout / 20, sleep=-1
                    ):  # This timeout is only for not exceeding the given timeout by more than 5%. With sleep<0 it's constantly polling anyway.
                        lock_owner_count = lock_owner_counter.incr()
                        print_locked(
                            "Thread %2d: Acquired the lock. It's my %d. loop cycle. I am the %d. who has the lock concurrently."
                            % (thread_id, cycle, lock_owner_count)
                        )
                        time.sleep(0.005)
                        lock_owner_count = lock_owner_counter.decr()
                        print_locked(
                            "Thread %2d: Releasing the lock, finishing my %d. loop cycle. Currently, %d colleagues still have the lock."
                            % (thread_id, cycle, lock_owner_count)
                        )
                except LockTimeout:
                    print_locked("Thread %2d: Got LockTimeout, finishing my %d. loop cycle." % (thread_id, cycle))
                except:
                    exception_count = exception_counter.incr()
                    e = format_exc()
                    print_locked(
                        "Thread %2d: Exception thrown, finishing my %d. loop cycle. It's the %d. exception seen until now: %s"
                        % (thread_id, cycle, exception_count, e)
                    )

            print_locked("Thread %2d: Loop timed out--terminating after %d loop cycles." % (thread_id, cycle))
            if last_thread is not None:  # joining its predecessor, if any
                last_thread.join()

        print("")
        lock_owner_counter = SynchronizedCounter()
        exception_counter = SynchronizedCounter()
        print_lock = ThreadingLock()
        thread = None
        for thread_id in range(RACE_TEST_NUM_THREADS):
            thread = Thread(
                target=acquire_release_loop,
                args=(
                    ("foo", thread_id, 0),
                    RACE_TEST_DURATION,
                    thread_id,
                    lock_owner_counter,
                    exception_counter,
                    print_lock,
                    thread,
                ),
            )
            thread.start()
        thread.join()  # joining the last thread

        assert lock_owner_counter.maxvalue() > 0, "Never gained the lock? Something went wrong here..."
        assert (
            lock_owner_counter.maxvalue() <= 1
        ), "Maximal number of concurrent lock holders was %d. So exclusivity is broken." % (
            lock_owner_counter.maxvalue()
        )
        assert (
            exception_counter.value() == 0
        ), "ExclusiveLock threw %d exceptions due to unclean concurrency handling." % (exception_counter.value())


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

    def test_kill_stale(self, lockpath, free_pid):
        host, pid, tid = our_id = get_process_id()
        dead_id = host, free_pid, tid
        cant_know_if_dead_id = "foo.bar.example.net", 1, 2

        dead_lock = Lock(lockpath, id=dead_id, exclusive=True).acquire()
        roster = dead_lock._roster
        with Lock(lockpath, id=our_id):
            assert roster.get(EXCLUSIVE) == set()
            assert roster.get(SHARED) == {our_id}
        assert roster.get(EXCLUSIVE) == set()
        assert roster.get(SHARED) == set()
        with pytest.raises(KeyError):
            dead_lock.release()

        with Lock(lockpath, id=cant_know_if_dead_id, exclusive=True):
            with pytest.raises(LockTimeout):
                Lock(lockpath, id=our_id, timeout=0.1).acquire()

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
    return str(tmpdir.join("roster"))


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
        assert roster1.get(SHARED) == {ID1}
        roster2 = LockRoster(rosterpath, id=ID2)
        roster2.modify(SHARED, ADD)
        assert roster2.get(SHARED) == {ID1, ID2}
        roster1 = LockRoster(rosterpath, id=ID1)
        roster1.modify(SHARED, REMOVE)
        assert roster1.get(SHARED) == {ID2}
        roster2 = LockRoster(rosterpath, id=ID2)
        roster2.modify(SHARED, REMOVE)
        assert roster2.get(SHARED) == set()

    def test_kill_stale(self, rosterpath, free_pid):
        host, pid, tid = our_id = get_process_id()
        dead_id = host, free_pid, tid

        # put a dead local process lock into roster
        roster1 = LockRoster(rosterpath, id=dead_id)
        roster1.kill_stale_locks = False
        assert roster1.get(SHARED) == set()
        roster1.modify(SHARED, ADD)
        assert roster1.get(SHARED) == {dead_id}

        # put a unknown-state remote process lock into roster
        cant_know_if_dead_id = "foo.bar.example.net", 1, 2
        roster1 = LockRoster(rosterpath, id=cant_know_if_dead_id)
        roster1.kill_stale_locks = False
        assert roster1.get(SHARED) == {dead_id}
        roster1.modify(SHARED, ADD)
        assert roster1.get(SHARED) == {dead_id, cant_know_if_dead_id}

        killer_roster = LockRoster(rosterpath)
        # Active kill_stale_locks here - does it kill the dead_id lock?
        assert killer_roster.get(SHARED) == {cant_know_if_dead_id}
        killer_roster.modify(SHARED, ADD)
        assert killer_roster.get(SHARED) == {our_id, cant_know_if_dead_id}

        other_killer_roster = LockRoster(rosterpath)
        # Active kill_stale_locks here - must not kill our_id lock since we're alive.
        assert other_killer_roster.get(SHARED) == {our_id, cant_know_if_dead_id}

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

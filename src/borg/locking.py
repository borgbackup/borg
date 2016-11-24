import json
import os
import time

from . import platform
from .helpers import Error, ErrorWithTraceback
from .logger import create_logger

ADD, REMOVE = 'add', 'remove'
SHARED, EXCLUSIVE = 'shared', 'exclusive'

logger = create_logger(__name__)


class TimeoutTimer:
    """
    A timer for timeout checks (can also deal with no timeout, give timeout=None [default]).
    It can also compute and optionally execute a reasonable sleep time (e.g. to avoid
    polling too often or to support thread/process rescheduling).
    """
    def __init__(self, timeout=None, sleep=None):
        """
        Initialize a timer.

        :param timeout: time out interval [s] or None (no timeout)
        :param sleep: sleep interval [s] (>= 0: do sleep call, <0: don't call sleep)
                      or None (autocompute: use 10% of timeout [but not more than 60s],
                      or 1s for no timeout)
        """
        if timeout is not None and timeout < 0:
            raise ValueError("timeout must be >= 0")
        self.timeout_interval = timeout
        if sleep is None:
            if timeout is None:
                sleep = 1.0
            else:
                sleep = min(60.0, timeout / 10.0)
        self.sleep_interval = sleep
        self.start_time = None
        self.end_time = None

    def __repr__(self):
        return "<%s: start=%r end=%r timeout=%r sleep=%r>" % (
            self.__class__.__name__, self.start_time, self.end_time,
            self.timeout_interval, self.sleep_interval)

    def start(self):
        self.start_time = time.time()
        if self.timeout_interval is not None:
            self.end_time = self.start_time + self.timeout_interval
        return self

    def sleep(self):
        if self.sleep_interval >= 0:
            time.sleep(self.sleep_interval)

    def timed_out(self):
        return self.end_time is not None and time.time() >= self.end_time

    def timed_out_or_sleep(self):
        if self.timed_out():
            return True
        else:
            self.sleep()
            return False


class LockError(Error):
    """Failed to acquire the lock {}."""


class LockErrorT(ErrorWithTraceback):
    """Failed to acquire the lock {}."""


class LockTimeout(LockError):
    """Failed to create/acquire the lock {} (timeout)."""


class LockFailed(LockErrorT):
    """Failed to create/acquire the lock {} ({})."""


class NotLocked(LockErrorT):
    """Failed to release the lock {} (was not locked)."""


class NotMyLock(LockErrorT):
    """Failed to release the lock {} (was/is locked, but not by me)."""


class ExclusiveLock:
    """An exclusive Lock based on mkdir fs operation being atomic.

    If possible, try to use the contextmanager here like::

        with ExclusiveLock(...) as lock:
            ...

    This makes sure the lock is released again if the block is left, no
    matter how (e.g. if an exception occurred).
    """
    def __init__(self, path, timeout=None, sleep=None, id=None, kill_stale_locks=False):
        self.timeout = timeout
        self.sleep = sleep
        self.path = os.path.abspath(path)
        self.id = id or platform.get_process_id()
        self.unique_name = os.path.join(self.path, "%s.%d-%x" % self.id)
        self.kill_stale_locks = kill_stale_locks
        self.stale_warning_printed = False

    def __enter__(self):
        return self.acquire()

    def __exit__(self, *exc):
        self.release()

    def __repr__(self):
        return "<%s: %r>" % (self.__class__.__name__, self.unique_name)

    def acquire(self, timeout=None, sleep=None):
        if timeout is None:
            timeout = self.timeout
        if sleep is None:
            sleep = self.sleep
        timer = TimeoutTimer(timeout, sleep).start()
        while True:
            try:
                os.mkdir(self.path)
            except FileExistsError:  # already locked
                if self.by_me():
                    return self
                self.kill_stale_lock()
                if timer.timed_out_or_sleep():
                    raise LockTimeout(self.path)
            except OSError as err:
                raise LockFailed(self.path, str(err)) from None
            else:
                with open(self.unique_name, "wb"):
                    pass
                return self

    def release(self):
        if not self.is_locked():
            raise NotLocked(self.path)
        if not self.by_me():
            raise NotMyLock(self.path)
        os.unlink(self.unique_name)
        os.rmdir(self.path)

    def is_locked(self):
        return os.path.exists(self.path)

    def by_me(self):
        return os.path.exists(self.unique_name)

    def kill_stale_lock(self):
        for name in os.listdir(self.path):
            try:
                host_pid, thread_str = name.rsplit('-', 1)
                host, pid_str = host_pid.rsplit('.', 1)
                pid = int(pid_str)
                thread = int(thread_str)
            except ValueError:
                # Malformed lock name? Or just some new format we don't understand?
                # It's safer to just exit.
                return False

            if platform.process_alive(host, pid, thread):
                return False

            if not self.kill_stale_locks:
                if not self.stale_warning_printed:
                    # Log this at warning level to hint the user at the ability
                    logger.warning("Found stale lock %s, but not deleting because BORG_HOSTNAME_IS_UNIQUE is not set.", name)
                    self.stale_warning_printed = True
                return False

            try:
                os.unlink(os.path.join(self.path, name))
                logger.warning('Killed stale lock %s.', name)
            except OSError as err:
                if not self.stale_warning_printed:
                    # This error will bubble up and likely result in locking failure
                    logger.error('Found stale lock %s, but cannot delete due to %s', name, str(err))
                    self.stale_warning_printed = True
                return False

        try:
            os.rmdir(self.path)
        except OSError:
            # Directory is not empty = we lost the race to somebody else
            # Permission denied = we cannot operate anyway
            # other error like EIO = we cannot operate and it's unsafe too.
            return False

        return True

    def break_lock(self):
        if self.is_locked():
            for name in os.listdir(self.path):
                os.unlink(os.path.join(self.path, name))
            os.rmdir(self.path)


class LockRoster:
    """
    A Lock Roster to track shared/exclusive lockers.

    Note: you usually should call the methods with an exclusive lock held,
    to avoid conflicting access by multiple threads/processes/machines.
    """
    def __init__(self, path, id=None, kill_stale_locks=False):
        self.path = path
        self.id = id or platform.get_process_id()
        self.kill_stale_locks = kill_stale_locks

    def load(self):
        try:
            with open(self.path) as f:
                data = json.load(f)

            # Just nuke the stale locks early on load
            if self.kill_stale_locks:
                for key in (SHARED, EXCLUSIVE):
                    try:
                        entries = data[key]
                    except KeyError:
                        continue
                    elements = set()
                    for host, pid, thread in entries:
                        if platform.process_alive(host, pid, thread):
                            elements.add((host, pid, thread))
                        else:
                            logger.warning('Removed stale %s roster lock for pid %d.', key, pid)
                    data[key] = list(elements)
        except (FileNotFoundError, ValueError):
            # no or corrupt/empty roster file?
            data = {}
        return data

    def save(self, data):
        with open(self.path, "w") as f:
            json.dump(data, f)

    def remove(self):
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass

    def get(self, key):
        roster = self.load()
        return set(tuple(e) for e in roster.get(key, []))

    def empty(self, *keys):
        return all(not self.get(key) for key in keys)

    def modify(self, key, op):
        roster = self.load()
        try:
            elements = set(tuple(e) for e in roster[key])
        except KeyError:
            elements = set()
        if op == ADD:
            elements.add(self.id)
        elif op == REMOVE:
            elements.remove(self.id)
        else:
            raise ValueError('Unknown LockRoster op %r' % op)
        roster[key] = list(list(e) for e in elements)
        self.save(roster)


class Lock:
    """
    A Lock for a resource that can be accessed in a shared or exclusive way.
    Typically, write access to a resource needs an exclusive lock (1 writer,
    noone is allowed reading) and read access to a resource needs a shared
    lock (multiple readers are allowed).

    If possible, try to use the contextmanager here like::

        with Lock(...) as lock:
            ...

    This makes sure the lock is released again if the block is left, no
    matter how (e.g. if an exception occurred).
    """
    def __init__(self, path, exclusive=False, sleep=None, timeout=None, id=None, kill_stale_locks=False):
        self.path = path
        self.is_exclusive = exclusive
        self.sleep = sleep
        self.timeout = timeout
        self.id = id or platform.get_process_id()
        # globally keeping track of shared and exclusive lockers:
        self._roster = LockRoster(path + '.roster', id=id, kill_stale_locks=kill_stale_locks)
        # an exclusive lock, used for:
        # - holding while doing roster queries / updates
        # - holding while the Lock itself is exclusive
        self._lock = ExclusiveLock(path + '.exclusive', id=id, timeout=timeout, kill_stale_locks=kill_stale_locks)

    def __enter__(self):
        return self.acquire()

    def __exit__(self, *exc):
        self.release()

    def __repr__(self):
        return "<%s: %r>" % (self.__class__.__name__, self.id)

    def acquire(self, exclusive=None, remove=None, sleep=None):
        if exclusive is None:
            exclusive = self.is_exclusive
        sleep = sleep or self.sleep or 0.2
        if exclusive:
            self._wait_for_readers_finishing(remove, sleep)
            self._roster.modify(EXCLUSIVE, ADD)
        else:
            with self._lock:
                if remove is not None:
                    self._roster.modify(remove, REMOVE)
                self._roster.modify(SHARED, ADD)
        self.is_exclusive = exclusive
        return self

    def _wait_for_readers_finishing(self, remove, sleep):
        timer = TimeoutTimer(self.timeout, sleep).start()
        while True:
            self._lock.acquire()
            try:
                if remove is not None:
                    self._roster.modify(remove, REMOVE)
                if len(self._roster.get(SHARED)) == 0:
                    return  # we are the only one and we keep the lock!
                # restore the roster state as before (undo the roster change):
                if remove is not None:
                    self._roster.modify(remove, ADD)
            except:
                # avoid orphan lock when an exception happens here, e.g. Ctrl-C!
                self._lock.release()
                raise
            else:
                self._lock.release()
            if timer.timed_out_or_sleep():
                raise LockTimeout(self.path)

    def release(self):
        if self.is_exclusive:
            self._roster.modify(EXCLUSIVE, REMOVE)
            if self._roster.empty(EXCLUSIVE, SHARED):
                self._roster.remove()
            self._lock.release()
        else:
            with self._lock:
                self._roster.modify(SHARED, REMOVE)
                if self._roster.empty(EXCLUSIVE, SHARED):
                    self._roster.remove()

    def upgrade(self):
        # WARNING: if multiple read-lockers want to upgrade, it will deadlock because they
        # all will wait until the other read locks go away - and that won't happen.
        if not self.is_exclusive:
            self.acquire(exclusive=True, remove=SHARED)

    def downgrade(self):
        if self.is_exclusive:
            self.acquire(exclusive=False, remove=EXCLUSIVE)

    def got_exclusive_lock(self):
        return self.is_exclusive and self._lock.is_locked() and self._lock.by_me()

    def break_lock(self):
        self._roster.remove()
        self._lock.break_lock()

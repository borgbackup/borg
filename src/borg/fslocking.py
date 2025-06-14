import errno
import json
import os
import tempfile
import time
from pathlib import Path

from . import platform
from .helpers import Error, ErrorWithTraceback
from .logger import create_logger

ADD, REMOVE, REMOVE2 = "add", "remove", "remove2"
SHARED, EXCLUSIVE = "shared", "exclusive"

logger = create_logger(__name__)


class TimeoutTimer:
    """
    A timer for timeout checks (can also deal with "never timeout").
    It can also compute and optionally execute a reasonable sleep time (e.g. to avoid
    polling too often or to support thread/process rescheduling).
    """

    def __init__(self, timeout=None, sleep=None):
        """
        Initialize a timer.

        :param timeout: time out interval [s] or None (never timeout, wait forever) [default]
        :param sleep: sleep interval [s] (>= 0: do sleep call, <0: don't call sleep)
                      or None (autocompute: use 10% of timeout [but not more than 60s],
                      or 1s for "never timeout" mode)
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
        return "<{}: start={!r} end={!r} timeout={!r} sleep={!r}>".format(
            self.__class__.__name__, self.start_time, self.end_time, self.timeout_interval, self.sleep_interval
        )

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

    exit_mcode = 70


class LockErrorT(ErrorWithTraceback):
    """Failed to acquire the lock {}."""

    exit_mcode = 71


class LockFailed(LockErrorT):
    """Failed to create/acquire the lock {} ({})."""

    exit_mcode = 72


class LockTimeout(LockError):
    """Failed to create/acquire the lock {} (timeout)."""

    exit_mcode = 73


class NotLocked(LockErrorT):
    """Failed to release the lock {} (was not locked)."""

    exit_mcode = 74


class NotMyLock(LockErrorT):
    """Failed to release the lock {} (was/is locked, but not by me)."""

    exit_mcode = 75


class ExclusiveLock:
    """An exclusive Lock based on mkdir fs operation being atomic.

    If possible, try to use the contextmanager here like::

        with ExclusiveLock(...) as lock:
            ...

    This makes sure the lock is released again if the block is left, no
    matter how (e.g. if an exception occurred).
    """

    def __init__(self, path, timeout=None, sleep=None, id=None):
        self.timeout = timeout
        self.sleep = sleep
        self.path = Path(path).absolute()
        self.id = id or platform.get_process_id()
        self.unique_name = self.path / ("%s.%d-%x" % self.id)
        self.kill_stale_locks = True
        self.stale_warning_printed = False

    def __enter__(self):
        return self.acquire()

    def __exit__(self, *exc):
        self.release()

    def __repr__(self):
        return f"<{self.__class__.__name__}: {str(self.unique_name)!r}>"

    def acquire(self, timeout=None, sleep=None):
        if timeout is None:
            timeout = self.timeout
        if sleep is None:
            sleep = self.sleep
        parent_path, base_name = str(self.path.parent), self.path.name
        unique_base_name = self.unique_name.name
        temp_path = None
        try:
            temp_path = tempfile.mkdtemp(".tmp", base_name + ".", parent_path)
            temp_unique_name = Path(temp_path) / unique_base_name
            with temp_unique_name.open("wb"):
                pass
        except OSError as err:
            raise LockFailed(str(self.path), str(err)) from None
        else:
            timer = TimeoutTimer(timeout, sleep).start()
            while True:
                try:
                    Path(temp_path).replace(str(self.path))
                except OSError:  # already locked
                    if self.by_me():
                        return self
                    self.kill_stale_lock()
                    if timer.timed_out_or_sleep():
                        raise LockTimeout(str(self.path)) from None
                else:
                    temp_path = None  # see finally:-block below
                    return self
        finally:
            if temp_path is not None:
                # Renaming failed for some reason, so temp_dir still exists and
                # should be cleaned up anyway. Try to clean up, but don't crash.
                try:
                    os.unlink(temp_unique_name)
                except:  # nosec B110 # noqa
                    pass
                try:
                    os.rmdir(temp_path)
                except:  # nosec B110 # noqa
                    pass

    def release(self):
        if not self.is_locked():
            raise NotLocked(str(self.path))
        if not self.by_me():
            raise NotMyLock(str(self.path))
        self.unique_name.unlink()
        for retry in range(42):
            try:
                self.path.rmdir()
            except OSError as err:
                if err.errno in (errno.EACCES,):
                    # windows behaving strangely? -> just try again.
                    continue
                if err.errno not in (errno.ENOTEMPTY, errno.EEXIST, errno.ENOENT):
                    # EACCES or EIO or ... = we cannot operate anyway, so re-throw
                    raise err
                # else:
                # Directory is not empty or doesn't exist any more.
                # this means we lost the race to somebody else -- which is ok.
            return

    def is_locked(self):
        return self.path.exists()

    def by_me(self):
        return self.unique_name.exists()

    def kill_stale_lock(self):
        try:
            names = [p.name for p in self.path.iterdir()]
        except FileNotFoundError:  # another process did our job in the meantime.
            return False
        except PermissionError:  # win32 might throw this.
            return False
        else:
            for name in names:
                try:
                    host_pid, thread_str = name.rsplit("-", 1)
                    host, pid_str = host_pid.rsplit(".", 1)
                    pid = int(pid_str)
                    thread = int(thread_str, 16)
                except ValueError:
                    # Malformed lock name? Or just some new format we don't understand?
                    logger.error("Found malformed lock %s in %s. Please check/fix manually.", name, str(self.path))
                    return False

                if platform.process_alive(host, pid, thread):
                    return False

                if not self.kill_stale_locks:
                    if not self.stale_warning_printed:
                        # Log this at warning level to hint the user at the ability
                        logger.warning(
                            "Found stale lock %s, but not deleting because self.kill_stale_locks = False.", name
                        )
                        self.stale_warning_printed = True
                    return False

                try:
                    (self.path / name).unlink()
                    logger.warning("Killed stale lock %s.", name)
                except OSError as err:
                    if not self.stale_warning_printed:
                        # This error will bubble up and likely result in locking failure
                        logger.error("Found stale lock %s, but cannot delete due to %s", name, str(err))
                        self.stale_warning_printed = True
                    return False

        try:
            self.path.rmdir()
        except OSError as err:
            if err.errno in (errno.ENOTEMPTY, errno.EEXIST, errno.ENOENT):
                # Directory is not empty or doesn't exist any more = we lost the race to somebody else--which is ok.
                return False
            # EACCES or EIO or ... = we cannot operate anyway
            logger.error("Failed to remove lock dir: %s", str(err))
            return False

        return True

    def break_lock(self):
        if self.is_locked():
            for path_obj in self.path.iterdir():
                path_obj.unlink()
            self.path.rmdir()

    def migrate_lock(self, old_id, new_id):
        """migrate the lock ownership from old_id to new_id"""
        assert self.id == old_id
        new_unique_name = self.path / ("%s.%d-%x" % new_id)
        if self.is_locked() and self.by_me():
            with new_unique_name.open("wb"):
                pass
            self.unique_name.unlink()
        self.id, self.unique_name = new_id, new_unique_name


class LockRoster:
    """
    A Lock Roster to track shared/exclusive lockers.

    Note: you usually should call the methods with an exclusive lock held,
    to avoid conflicting access by multiple threads/processes/machines.
    """

    def __init__(self, path, id=None):
        assert isinstance(path, Path)
        self.path = path
        self.id = id or platform.get_process_id()
        self.kill_stale_locks = True

    def load(self):
        try:
            with self.path.open() as f:
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
                            logger.warning(
                                "Removed stale %s roster lock for host %s pid %d thread %d.", key, host, pid, thread
                            )
                    data[key] = list(elements)
        except (FileNotFoundError, ValueError):
            # no or corrupt/empty roster file?
            data = {}
        return data

    def save(self, data):
        with self.path.open("w") as f:
            json.dump(data, f)

    def remove(self):
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass

    def get(self, key):
        roster = self.load()
        return {tuple(e) for e in roster.get(key, [])}

    def empty(self, *keys):
        return all(not self.get(key) for key in keys)

    def modify(self, key, op):
        roster = self.load()
        try:
            elements = {tuple(e) for e in roster[key]}
        except KeyError:
            elements = set()
        if op == ADD:
            elements.add(self.id)
        elif op == REMOVE:
            # note: we ignore it if the element is already not present anymore.
            # this has been frequently seen in teardowns involving Repository.__del__ and Repository.__exit__.
            elements.discard(self.id)
        elif op == REMOVE2:
            # needed for callers that do not want to ignore.
            elements.remove(self.id)
        else:
            raise ValueError("Unknown LockRoster op %r" % op)
        roster[key] = list(list(e) for e in elements)
        self.save(roster)

    def migrate_lock(self, key, old_id, new_id):
        """migrate the lock ownership from old_id to new_id"""
        assert self.id == old_id
        # need to switch off stale lock killing temporarily as we want to
        # migrate rather than kill them (at least the one made by old_id).
        killing, self.kill_stale_locks = self.kill_stale_locks, False
        try:
            try:
                self.modify(key, REMOVE2)
            except KeyError:
                # entry was not there, so no need to add a new one, but still update our id
                self.id = new_id
            else:
                # old entry removed, update our id and add a updated entry
                self.id = new_id
                self.modify(key, ADD)
        finally:
            self.kill_stale_locks = killing


class Lock:
    """
    A Lock for a resource that can be accessed in a shared or exclusive way.
    Typically, write access to a resource needs an exclusive lock (1 writer,
    no one is allowed reading) and read access to a resource needs a shared
    lock (multiple readers are allowed).

    If possible, try to use the contextmanager here like::

        with Lock(...) as lock:
            ...

    This makes sure the lock is released again if the block is left, no
    matter how (e.g. if an exception occurred).
    """

    def __init__(self, path, exclusive=False, sleep=None, timeout=None, id=None):
        self.path = path
        self.is_exclusive = exclusive
        self.sleep = sleep
        self.timeout = timeout
        self.id = id or platform.get_process_id()
        # globally keeping track of shared and exclusive lockers:
        self._roster = LockRoster(Path(path + ".roster"), id=id)
        # an exclusive lock, used for:
        # - holding while doing roster queries / updates
        # - holding while the Lock itself is exclusive
        self._lock = ExclusiveLock(str(Path(path + ".exclusive")), id=id, timeout=timeout)

    def __enter__(self):
        return self.acquire()

    def __exit__(self, *exc):
        self.release()

    def __repr__(self):
        return f"<{self.__class__.__name__}: {self.id!r}>"

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
            except:  # noqa
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

    def migrate_lock(self, old_id, new_id):
        assert self.id == old_id
        self.id = new_id
        if self.is_exclusive:
            self._lock.migrate_lock(old_id, new_id)
            self._roster.migrate_lock(EXCLUSIVE, old_id, new_id)
        else:
            with self._lock:
                self._lock.migrate_lock(old_id, new_id)
                self._roster.migrate_lock(SHARED, old_id, new_id)

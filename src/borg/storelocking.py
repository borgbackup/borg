import datetime
import hashlib
import json
import random
import threading
import time
from collections import namedtuple

from borgstore.store import ObjectNotFound

from . import platform
from .constants import MAX_MUTUAL_CLOCK_SKEW
from .helpers import Error, ErrorWithTraceback
from .logger import create_logger

logger = create_logger(__name__)

# all we know about the lock object we most recently created: its store key, its content timestamp
# (stamped by our clock) and its store-side mtime [s] (stamped by the store's clock, harvested from
# lock listings, None until harvested), plus time.monotonic() at its creation. always replaced as a
# whole, so concurrent readers (e.g. a LockRefresher thread) never see a torn mix of its fields.
LockAnchor = namedtuple("LockAnchor", "key dt mtime monotonic")


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


class Lock:
    """
    A lock for a resource that can be accessed in a shared or exclusive way.

    Typically, write access to a resource needs an exclusive lock (one writer,
    no readers allowed), and read access to a resource needs a shared lock
    (multiple readers are allowed).

    If possible, use the context manager form::

        with Lock(...) as lock:
            ...

    This ensures the lock is released when the block is exited, no matter how
    (e.g., if an exception occurs).
    """

    def __init__(self, store, exclusive=False, sleep=None, timeout=1.0, stale=30 * 60, id=None):
        self.store = store
        self.is_exclusive = exclusive
        self.sleep = sleep
        self.timeout = timeout
        self.race_recheck_delay = 0.01  # local: 0.01, network/slow remote: >= 1.0
        self.other_locks_go_away_delay = 0.1  # local: 0.1, network/slow remote: >= 1.0
        self.retry_delay_min = 1.0
        self.retry_delay_max = 5.0
        self.stale_td = datetime.timedelta(seconds=stale)  # ignore/delete it if older
        self.refresh_td = datetime.timedelta(seconds=stale // 2)  # don't refresh it if younger
        self.last_refresh_dt = None
        self.my_lock_key = None  # store key of the lock we currently hold, None if we hold none
        # LockAnchor of our current lock object - its mtime and monotonic fields together let us
        # compute the current time in the store's clock domain, see _store_now().
        self.my_lock_anchor = None
        self.skew_warned = False  # emit the clock-skew warning only once per Lock instance
        self.id = id or platform.get_process_id()
        assert len(self.id) == 3
        logger.debug(f"LOCK-INIT: initializing. store: {store}, stale: {stale}s, refresh: {stale // 2}s.")

    def __enter__(self):
        return self.acquire()

    def __exit__(self, exc_type, exc_val, exc_tb):
        ignore_not_found = exc_type is not None
        # if there was an exception, try to release the lock,
        # but don't raise another exception while trying if it was not there.
        self.release(ignore_not_found=ignore_not_found)

    def __repr__(self):
        return f"<{self.__class__.__name__}: {self.id!r}>"

    def _create_lock(self, *, exclusive=None, update_last_refresh=False):
        assert exclusive is not None
        now = datetime.datetime.now(datetime.UTC)
        timestamp = now.isoformat(timespec="milliseconds")
        lock = dict(exclusive=exclusive, hostid=self.id[0], processid=self.id[1], threadid=self.id[2], time=timestamp)
        value = json.dumps(lock).encode("utf-8")
        key = hashlib.sha256(value).hexdigest()
        logger.debug(f"LOCK-CREATE: creating lock in store. key: {key}, lock: {lock}.")
        self.store.store(f"locks/{key}", value)
        if update_last_refresh:
            # we parse the timestamp string to get *precisely* the datetime in the lock:
            self.last_refresh_dt = datetime.datetime.fromisoformat(timestamp)
            self.my_lock_key = key
            # the store-side mtime of the new lock object is not known yet - it is harvested
            # from the next locks listing. anchor the monotonic clock at creation time so the
            # harvested mtime can be extrapolated to "now" later, see _store_now().
            self.my_lock_anchor = LockAnchor(key, self.last_refresh_dt, None, time.monotonic())
        return key

    def _delete_lock(self, key, *, ignore_not_found=False, update_last_refresh=False):
        logger.debug(f"LOCK-DELETE: deleting lock from store. key: {key}.")
        try:
            self.store.delete(f"locks/{key}")
        except ObjectNotFound:
            if not ignore_not_found:
                raise
        finally:
            if update_last_refresh:
                self.last_refresh_dt = None
                self.my_lock_key = None
                self.my_lock_anchor = None

    def _is_our_lock(self, lock):
        return self.id == (lock["hostid"], lock["processid"], lock["threadid"])

    def _store_now(self):
        """Return the current time in the store's clock domain [UNIX timestamp], or None if unknown."""
        anchor = self.my_lock_anchor  # single read - it gets replaced atomically as a whole
        if anchor is None or anchor.mtime is None:
            return None
        # note: on most platforms time.monotonic() does not advance while the machine is suspended,
        # so after a suspend this underestimates store "now". that errs towards NOT considering
        # other locks stale (the safe direction) and self-heals at our next lock creation/refresh.
        return anchor.mtime + (time.monotonic() - anchor.monotonic)

    def _mutual_skew(self, lock):
        """
        Return the clock skew [s] between us and the writer of <lock> (positive: their clock runs
        ahead of ours), or None if it can not be determined.

        Each lock object carries two timestamps of the same write instant: its content timestamp
        (stamped by the writer's clock) and its store-side mtime (stamped by the store's clock).
        Their difference is that writer's clock offset relative to the store; comparing two
        writers' offsets yields their mutual skew, with the store's absolute clock error cancelled
        out (the store's clock is only used as a common reference and may itself be wrong).
        """
        anchor = self.my_lock_anchor  # single read - it gets replaced atomically as a whole
        if not lock.get("mtime") or anchor is None or anchor.mtime is None:
            return None
        offset_self = anchor.dt.timestamp() - anchor.mtime
        offset_other = lock["dt"].timestamp() - lock["mtime"]
        return offset_other - offset_self

    def _warn_clock_skew(self, lock, skew):
        if self.skew_warned:
            return
        self.skew_warned = True
        logger.warning(
            f"Clock skew of ~{abs(skew):.0f}s detected between this machine and the borg client on "
            f"{lock['hostid']!r} (also using this repository). "
            f"The clocks of machines sharing a repository should be synchronized (e.g. via NTP)."
        )

    def _check_clock_skew(self, locks):
        """Warn (once) if another current lock writer's clock is skewed against ours."""
        if self.skew_warned:
            return
        for lock in locks.values():
            if lock["key"] == self.my_lock_key:
                continue
            skew = self._mutual_skew(lock)
            if skew is not None and abs(skew) > MAX_MUTUAL_CLOCK_SKEW:
                self._warn_clock_skew(lock, skew)

    def _is_stale_lock(self, lock):
        if lock["key"] == self.my_lock_key:
            # the lock we are currently holding: we are obviously alive and can refresh or
            # release it, so it must never be considered stale (and get deleted), no matter
            # how old it is. it can get old e.g. if the machine is suspended while doing a
            # backup or if there is a long stretch of work without repository access, see #9883.
            return False
        if not platform.process_alive(lock["hostid"], lock["processid"], lock["threadid"]):
            # the lock owner is a process on THIS machine and it is dead - local knowledge,
            # independent of any clock and of the store. checked first (and never vetoed by
            # store timestamps below), so a store serving bogus, always-fresh mtimes can not
            # keep an abandoned lock alive forever and block us.
            logger.debug(f"LOCK-STALE: we KNOW that the lock-owning process is dead. lock: {lock}.")
            return True
        now = datetime.datetime.now(datetime.UTC)
        if now > lock["dt"] + self.stale_td:
            # the lock looks stale, judging by its content timestamp (writer's clock) vs. our
            # local clock. but that comparison breaks down if the writer's clock is skewed
            # against ours, and we must never kill a healthy lock (data loss hazard, #9870).
            # thus, cross-check in the store's clock domain: the lock object's store-side mtime
            # vs. store "now". store timestamps are advisory only: they can veto a kill here,
            # but they can never cause a kill on their own (the store might be hostile).
            if lock["mtime"]:
                store_now = self._store_now()
                if store_now is None:
                    # we do not have a store-written object of our own yet, so we can not compute
                    # store "now". defer: the caller may create our lock first and list again -
                    # then we get here again with store_now available. never kill unconfirmed.
                    lock["maybe_stale"] = True
                    logger.debug(f"LOCK-STALE: lock looks stale, deferring until store time is known. lock: {lock}.")
                    return False
                if store_now <= lock["mtime"] + self.stale_td.total_seconds():
                    # the store saw this lock object being written recently: it is NOT stale.
                    # either its writer's clock is skewed against ours (the skew check in
                    # _get_locks warns about that) or our store "now" estimate lags behind
                    # (e.g. time.monotonic() stood still while we were suspended). never kill it!
                    logger.debug(f"LOCK-STALE: lock looks stale locally, but not to the store. lock: {lock}.")
                    return False
            # either both clock domains agree that the lock is stale, or the backend can not
            # provide store-side mtimes (mtime == 0) and the content timestamp has to suffice.
            logger.debug(f"LOCK-STALE: lock is too old, it was not refreshed. lock: {lock}.")
            return True
        return False

    def _get_locks(self):
        locks = {}
        try:
            infos = list(self.store.list("locks"))
        except ObjectNotFound:
            return {}
        for info in infos:
            key = info.name
            try:
                content = self.store.load(f"locks/{key}")
            except ObjectNotFound:
                # the lock vanished between our listing and loading it, e.g. it was released
                # by its owner or another client killed it as stale - so just ignore it.
                continue
            lock = json.loads(content.decode("utf-8"))
            lock["key"] = key
            lock["dt"] = datetime.datetime.fromisoformat(lock["time"])
            lock["mtime"] = info.mtime  # store-side mtime [s], 0 if the backend can not provide it
            locks[key] = lock
        my_key = self.my_lock_key  # single read - a LockRefresher thread may rebind it concurrently
        if my_key in locks:
            # harvest the store-side mtime of our own lock object from this listing into the
            # anchor set at its creation (see _create_lock / _store_now) - but only if the anchor
            # still describes the same lock object (a concurrent refresh may have replaced it).
            mtime = locks[my_key]["mtime"]
            anchor = self.my_lock_anchor
            if mtime and anchor is not None and anchor.key == my_key:
                self.my_lock_anchor = anchor._replace(mtime=mtime)
        for key in list(locks):
            if self._is_stale_lock(locks[key]):
                # ignore it and delete it (even if it is not from us).
                # note: this is never the lock we currently hold (see _is_stale_lock), so this
                # must not touch last_refresh_dt / my_lock_key - a stale lock matching our id
                # can only be a leftover of a dead process (pid reuse), not our own lock.
                self._delete_lock(key, ignore_not_found=True)
                del locks[key]
        # check for clock skew on every listing, not just on acquire success: the listing that
        # satisfies an exclusive acquire only contains our own lock, so a skewed peer is only
        # visible in earlier listings, e.g. while we wait for its healthy lock to go away.
        self._check_clock_skew(locks)
        return locks

    def _find_locks(self, *, only_exclusive=False, only_mine=False):
        locks = self._get_locks()
        found_locks = []
        for key in locks:
            lock = locks[key]
            if (not only_exclusive or lock["exclusive"]) and (
                not only_mine or (lock["hostid"], lock["processid"], lock["threadid"]) == self.id
            ):
                found_locks.append(lock)
        return found_locks

    def acquire(self):
        # goal
        # for exclusive lock: there must be only 1 exclusive lock and no other (exclusive or non-exclusive) locks.
        # for non-exclusive lock: there can be multiple n-e locks, but there must not exist an exclusive lock.
        logger.debug(f"LOCK-ACQUIRE: trying to acquire a lock. exclusive: {self.is_exclusive}.")
        started = time.monotonic()
        while time.monotonic() - started < self.timeout:
            exclusive_locks = self._find_locks(only_exclusive=True)
            if all(lock.get("maybe_stale") for lock in exclusive_locks):
                # there are no exclusive locks (or only ones that look stale, but whose staleness
                # could not be confirmed in the store's clock domain yet, see _is_stale_lock -
                # creating our lock below gives the next listing a store time reference, so they
                # get either confirmed (and deleted) or vetoed there). create our lock.
                key = self._create_lock(exclusive=self.is_exclusive, update_last_refresh=True)
                # obviously we have a race condition here: other client(s) might have created exclusive
                # lock(s) at the same time in parallel. thus we have to check again.
                time.sleep(
                    self.race_recheck_delay
                )  # give other clients time to notice our exclusive lock, stop creating theirs
                exclusive_locks = self._find_locks(only_exclusive=True)
                if self.is_exclusive:
                    if len(exclusive_locks) == 1 and exclusive_locks[0]["key"] == key:
                        logger.debug("LOCK-ACQUIRE: we are the only exclusive lock!")
                        while time.monotonic() - started < self.timeout:
                            locks = self._find_locks(only_exclusive=False)
                            if len(locks) == 1 and locks[0]["key"] == key:
                                logger.debug("LOCK-ACQUIRE: success! no non-exclusive locks are left!")
                                return self
                            time.sleep(self.other_locks_go_away_delay)
                        logger.debug("LOCK-ACQUIRE: timeout while waiting for non-exclusive locks to go away.")
                        # we won't get the exclusive lock, so do not leave our lock behind:
                        # it would needlessly block other clients until it expired as stale.
                        self._delete_lock(key, ignore_not_found=True, update_last_refresh=True)
                        break  # timeout
                    else:
                        logger.debug("LOCK-ACQUIRE: someone else also created an exclusive lock, deleting ours.")
                        self._delete_lock(key, ignore_not_found=True, update_last_refresh=True)
                else:  # not is_exclusive
                    if len(exclusive_locks) == 0:
                        logger.debug("LOCK-ACQUIRE: success! no exclusive locks detected.")
                        # We don't care for other non-exclusive locks.
                        return self
                    else:
                        logger.debug("LOCK-ACQUIRE: exclusive locks detected, deleting our shared lock.")
                        self._delete_lock(key, ignore_not_found=True, update_last_refresh=True)
            # wait a random bit before retrying
            time.sleep(
                self.retry_delay_min + (self.retry_delay_max - self.retry_delay_min) * random.random()  # nosec B311
            )
        logger.debug("LOCK-ACQUIRE: timeout while trying to acquire a lock.")
        raise LockTimeout(str(self.store))

    def release(self, *, ignore_not_found=False):
        self.last_refresh_dt = None
        locks = self._find_locks(only_mine=True)
        if not locks:
            if ignore_not_found:
                logger.debug("LOCK-RELEASE: trying to release the lock, but none was found.")
                return
            else:
                raise NotLocked(str(self.store))
        assert len(locks) == 1
        lock = locks[0]
        logger.debug(f"LOCK-RELEASE: releasing lock: {lock}.")
        self._delete_lock(lock["key"], ignore_not_found=True, update_last_refresh=True)

    def got_exclusive_lock(self):
        locks = self._find_locks(only_mine=True, only_exclusive=True)
        return len(locks) == 1

    def break_lock(self):
        """Breaks all locks (not just ours)."""
        logger.debug("LOCK-BREAK: break_lock() was called - deleting ALL locks!")
        locks = self._get_locks()
        for key in locks:
            self._delete_lock(key, ignore_not_found=True)
        self.last_refresh_dt = None
        self.my_lock_key = None

    def migrate_lock(self, old_id, new_id):
        """Migrates the lock ownership from old_id to new_id."""
        logger.debug(f"LOCK-MIGRATE: {old_id} -> {new_id}.")
        assert self.id == old_id
        assert len(new_id) == 3
        old_locks = self._find_locks(only_mine=True)
        assert len(old_locks) == 1
        self.id = new_id
        self._create_lock(exclusive=old_locks[0]["exclusive"], update_last_refresh=True)
        self._delete_lock(old_locks[0]["key"], update_last_refresh=False)

    def refresh(self):
        """Refreshes the lock; call this frequently, but not later than every <stale> seconds."""
        now = datetime.datetime.now(datetime.UTC)
        if self.last_refresh_dt is not None and now > self.last_refresh_dt + self.refresh_td:
            old_locks = self._find_locks(only_mine=True)
            if len(old_locks) == 0:
                # crap, my lock has been removed. :-(
                # this can happen e.g. if my machine has been suspended while doing a backup, so that the
                # lock became stale and a borg client on another machine killed it.
                # if my machine then wakes up again, the lock will have vanished and we get here.
                # note: if our lock became stale, but is still present (no other client killed it),
                # we do not get here - we never consider our own lock stale (see _is_stale_lock),
                # so it is found above and simply refreshed below.
                # in this case, we need to abort the operation, because the other borg might have removed
                # repo objects we have written, but the referential tree was not yet full present, e.g.
                # no archive has been added yet to the manifest, thus all objects looked unused/orphaned.
                # another scenario when this can happen is a careless user running break-lock on another
                # machine without making sure there is no borg activity in that repo.
                logger.debug("LOCK-REFRESH: our lock was killed, there is no safe way to continue.")
                raise LockTimeout(str(self.store))
            assert len(old_locks) == 1  # there shouldn't be more than 1
            old_lock = old_locks[0]
            if now > old_lock["dt"] + self.refresh_td:
                logger.debug(f"LOCK-REFRESH: lock needs a refresh. lock: {old_lock}.")
                new_key = self._create_lock(exclusive=old_lock["exclusive"], update_last_refresh=True)
                try:
                    self._delete_lock(old_lock["key"], update_last_refresh=False)
                except ObjectNotFound:
                    # our old lock vanished between listing and deleting it: another client considered
                    # it stale, killed it and (not having seen our new lock in its recheck) might have
                    # acquired its own lock already. there is no safe way to continue - clean up the
                    # new lock (so it does not needlessly block others until it expires) and abort.
                    logger.debug("LOCK-REFRESH: our lock was killed while refreshing it, no safe way to continue.")
                    self._delete_lock(new_key, ignore_not_found=True, update_last_refresh=True)
                    raise LockTimeout(str(self.store))


class LockRefresher:
    def __init__(self, refresh_callable, sleep_interval=60, lock=None):
        """
        Periodically refreshes the repository lock in a background thread.

        :param refresh_callable: Callable (e.g. repository.info) to refresh the lock.
        :param sleep_interval: Frequency of refresh attempts (in seconds).
        :param lock: Optional reentrant lock (RLock) to serialize repository access.
        """
        self.refresh_callable = refresh_callable
        self.sleep_interval = sleep_interval
        self.lock = lock
        self._thread = None
        self._keep_running = threading.Event()
        self._keep_running.set()

    def _run(self):
        while self._keep_running.is_set():
            try:
                if self.lock is not None:
                    with self.lock:
                        self.refresh_callable()
                else:
                    self.refresh_callable()
            except LockTimeout:
                logger.error("Lock refresh thread: lock has been killed/timed out. Terminating refresh.")
                break
            except Exception as e:
                logger.warning(f"Lock refresh thread: temporary error during lock refresh: {e}. Will retry.")

            # sleep up to self.sleep_interval in small steps to allow quick shutdown
            count = 1000
            micro_sleep = float(self.sleep_interval) / count
            while self._keep_running.is_set() and count > 0:
                time.sleep(micro_sleep)
                count -= 1

    def start(self):
        # daemon=True so a refresh that is stuck in a blocking refresh_callable() (e.g. network
        # I/O to a remote repo that never returns) can never keep the process alive on exit.
        self._thread = threading.Thread(target=self._run, name="LockRefresher", daemon=True)
        self._thread.start()

    def terminate(self):
        if self._thread is not None:
            self._keep_running.clear()
            # bounded join: if refresh_callable() is wedged (e.g. a hung remote-repo request),
            # don't let it stall shutdown - e.g. a FUSE unmount waiting for this. the thread is a
            # daemon, so it is torn down at interpreter exit even if it is still alive here.
            self._thread.join(timeout=5.0)
            if self._thread.is_alive():
                logger.warning("Lock refresh thread did not stop within 5s; continuing shutdown.")

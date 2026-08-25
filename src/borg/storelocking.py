"""
Repository locking on top of borgstore.

Lock objects
------------
Each client holding a lock owns one small object below locks/ in the repository store. Its content
(JSON) records the lock type (exclusive or shared), the owner's host / process / thread id and a
timestamp (the "content timestamp"), stamped by the *owner's* clock when the object was written.
Lock objects are immutable: to refresh a lock, the owner writes a new object and deletes the old one.
Where the storage backend provides object timestamps (file, sftp, s3, current rest servers - not
rclone), a lock object additionally carries a store-side mtime, stamped by the *storage's* clock at
the same write instant; borgstore reports it as ItemInfo.mtime (0 if unavailable).

Acquiring
---------
Shared locks may coexist, an exclusive lock must be alone. acquire() lists the lock objects, creates
its own lock object if nothing forbids it, and lists again to detect a race with other clients
creating theirs at the same time: an exclusive acquirer backs off if another exclusive lock showed
up (and otherwise waits for remaining shared locks to go away), a shared acquirer backs off if an
exclusive lock showed up. This is retried until the timeout.

Staleness
---------
A lock whose owner died (crash, power loss, suspended laptop, ...) must not block others forever, so
every listing judges each lock object and deletes it if it is stale:

- Our own lock object (and, during a refresh, the one we are just replacing) is never stale: we are
  obviously alive and will refresh or release it.
- If the owner is a process on this machine and it is dead, the lock is stale. This is local
  knowledge, independent of any clock, so it is checked first and can not be vetoed by anything the
  storage says (a storage serving bogus, always-fresh mtimes must not be able to keep an abandoned
  local lock alive forever).
- Otherwise, a lock is stale by age if it was not refreshed for longer than the stale timeout
  (default 30 minutes; owners refresh after half of it). But owners write the content timestamp
  with *their* clock and we compare it with *ours*: if the owner's clock runs more than the stale
  timeout behind ours, its just refreshed lock already looks stale to us, and killing it would e.g.
  enable a compact to delete chunks a running backup still references (see #9870). Thus a lock is
  only expired by age if it looks stale in BOTH clock domains:

  * writer / local clock domain: our "now" vs. the lock's content timestamp, and
  * store clock domain: store "now" vs. the lock object's store-side mtime.

  Store "now" is extrapolated from our own lock object: its store-side mtime (harvested from a
  listing after we created it) plus the time.monotonic() elapsed since its creation (LockAnchor
  keeps these together, see there). So the store domain comparison involves no client's clock at
  all, and the storage's absolute clock error cancels out - the storage only serves as a common
  reference. Its clock should run steadily, though: borg warns if it detects that it jumped between
  two of its own lock writes (see _check_store_clock_step), and refresh() creates the new lock
  object before listing, so the stale sweep always judges with a fresh anchor.

  Store-side mtimes are advisory only: they can veto an expiry, but never cause one on their own,
  so a hostile or broken storage gains no new capabilities (it can not make us kill a healthy lock;
  blocking us was possible for it before, anyway). A client without an own lock object can not
  compute store "now" and defers the decision until acquire() has created one - the listing right
  afterwards then confirms or vetoes. If the backend provides no store-side mtimes (mtime == 0),
  staleness is judged by the content timestamp alone.

Clock skew warning
------------------
As every lock object carries two timestamps of the same write instant (content timestamp: writer's
clock, store-side mtime: storage's clock), the writers' clock offsets relative to the storage are
comparable, with the storage's absolute clock error cancelled out. Every listing compares the other
writers' offsets with ours and warns (once per Lock instance) if the clocks of concurrently active
clients differ by more than MAX_MUTUAL_CLOCK_SKEW. This is diagnosis only, never an abort.

Refreshing
----------
Lock holders must call refresh() regularly (LockRefresher does that from a background thread). It is
a no-op until the lock is older than half the stale timeout, then it writes a new lock object and
deletes the old one. If the old one turns out to be gone, another client killed it as stale (and
might have acquired its own lock meanwhile), so there is no safe way to continue: LockTimeout.
"""

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
from .helpers import Error, ErrorWithTraceback, format_timedelta
from .logger import create_logger

logger = create_logger(__name__)

# all we know about the lock object we most recently created: its store key, its content timestamp
# (stamped by our clock) and its store-side mtime [s] (stamped by the store's clock, harvested from
# lock listings, None until harvested), plus time.monotonic() at its creation. always replaced as a
# whole, so concurrent readers (e.g. a LockRefresher thread) never see a torn mix of its fields.
LockAnchor = namedtuple("LockAnchor", "key dt mtime monotonic")

# why a refresh gives up: our own lock object is gone, see refresh().
LOCK_KILLED_MSG = (
    "Our lock was killed by another borg (it considered our lock stale, e.g. because this machine "
    "was suspended or too slow to refresh the lock in time, or because someone ran break-lock) - "
    "there is no safe way to continue."
)


def format_lock(lock):
    """Return a human readable description of a lock object: what it is, who holds it, since when."""
    kind = "exclusive" if lock["exclusive"] else "shared"
    age = format_timedelta(datetime.datetime.now(datetime.UTC) - lock["dt"])
    return f"{kind} lock on host {lock['hostid']}, pid {lock['processid']}, age {age}"


def format_locks(locks, max_shown=3):
    """Return a human readable description of the given lock objects (at most max_shown of them)."""
    if not locks:
        # e.g. all the locks that blocked us went away while we were retrying, but we ran out of time.
        return "unknown (no blocking lock seen)"
    descriptions = [format_lock(lock) for lock in locks[:max_shown]]
    if len(locks) > max_shown:
        descriptions.append(f"and {len(locks) - max_shown} more")
    return "; ".join(descriptions)


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
    """Failed to create/acquire the lock {} (timeout). {}"""

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

    def __init__(self, store, exclusive=False, sleep=None, timeout=1.0, stale=30 * 60, id=None, repository=None):
        self.store = store
        # how to call the locked repository in messages to the user. the store's repr does not tell
        # which repository it is, so the caller should give a (credentials-free) repository name.
        self.repository = repository if repository is not None else str(store)
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
        self.my_old_lock_key = None  # store key of the lock we are replacing while a refresh is in progress
        # LockAnchor of the lock object we most recently created - its mtime and monotonic fields
        # together let us compute the current time in the store's clock domain, see _store_now().
        # it deliberately outlives its lock object: the calibration stays valid after deletion.
        self.my_lock_anchor = None
        self.prev_lock_anchor = None  # the anchor before the current one, see _check_store_clock_step()
        self.blocking_locks_logged = False  # tell the user only once per Lock instance who blocks us
        self.skew_warned = False  # emit the clock-skew warning only once per Lock instance
        self.store_clock_step_warned = False  # emit the storage-clock-step warning only once per Lock instance
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

    def _create_lock(self, *, exclusive=None, dt=None, update_last_refresh=False):
        assert exclusive is not None
        # dt: explicit content timestamp (default: now) - tests use it to simulate skewed clocks.
        now = dt if dt is not None else datetime.datetime.now(datetime.UTC)
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
            self.prev_lock_anchor = self.my_lock_anchor
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
                # my_lock_anchor is deliberately kept: it is a store-clock calibration, not a
                # property of the deleted object. keeping it lets an acquire that is blocked by
                # a healthy-but-skewed lock veto the kill on the first listing of every retry,
                # instead of re-deferring and re-creating a transient lock each time.

    def _is_our_lock(self, lock):
        return self.id == (lock["hostid"], lock["processid"], lock["threadid"])

    def _store_now(self):
        """Return the current time in the store's clock domain [UNIX timestamp], or None if unknown."""
        anchor = self.my_lock_anchor  # single read - it gets replaced atomically as a whole
        if anchor is None or anchor.mtime is None:
            return None
        # note: on most platforms time.monotonic() does not advance while the machine is suspended,
        # so after a suspend the extrapolation below lags behind store "now" by up to the suspend
        # duration. that errs towards NOT considering other locks stale (the safe direction), but
        # do not extrapolate from a too old anchor at all: its age is measured with our wall clock
        # at both ends, so suspends count here. self-heals at our next lock creation/refresh.
        if datetime.datetime.now(datetime.UTC) > anchor.dt + self.stale_td:
            return None
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

    def _check_store_clock_step(self, anchor, mtime):
        """
        Warn (once) if the storage's clock jumped between the writes of our previous and our current
        lock object: compare the new object's store-side mtime with what the previous anchor
        extrapolates for the new object's creation instant. Diagnostic only: a backward step larger
        than the stale timeout can defeat the store-domain cross-check in _is_stale_lock (see there),
        this at least names the cause.
        """
        prev = self.prev_lock_anchor  # single read - it gets replaced atomically as a whole
        if prev is None or prev.mtime is None or self.store_clock_step_warned:
            return
        elapsed_monotonic = anchor.monotonic - prev.monotonic
        elapsed_wall = (anchor.dt - prev.dt).total_seconds()
        if abs(elapsed_wall - elapsed_monotonic) > MAX_MUTUAL_CLOCK_SKEW:
            # our own two clocks disagree about the elapsed time (suspend: time.monotonic() stood
            # still, or our wall clock was stepped): then we can not judge the storage's clock.
            return
        step = (mtime - prev.mtime) - elapsed_monotonic
        if abs(step) > MAX_MUTUAL_CLOCK_SKEW:
            self.store_clock_step_warned = True
            logger.warning(
                f"The clock of the repository storage jumped by ~{step:+.0f}s between two lock writes of ours. "
                f"Storage clock steps interfere with stale lock detection, the storage's clock should run steadily."
            )

    def _check_clock_skew(self, locks):
        """Warn (once) if another current lock writer's clock is skewed against ours."""
        if self.skew_warned:
            return
        for lock in locks.values():
            if self._is_our_lock(lock):
                # our own lock object(s): e.g. during a refresh, our old and our new lock object -
                # a storage clock step between their writes would make them look skewed against
                # each other, but that is no peer with a skewed clock (see _check_store_clock_step).
                continue
            skew = self._mutual_skew(lock)
            if skew is not None and abs(skew) > MAX_MUTUAL_CLOCK_SKEW:
                self._warn_clock_skew(lock, skew)

    def _is_stale_lock(self, lock):
        if lock["key"] in (self.my_lock_key, self.my_old_lock_key):
            # the lock we are currently holding (or the one we are just replacing by it, see
            # refresh): we are obviously alive and can refresh or release it, so it must never
            # be considered stale (and get deleted), no matter how old it is. it can get old e.g.
            # if the machine is suspended while doing a backup or if there is a long stretch of
            # work without repository access, see #9883.
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
            # residual risk: a store clock that steps BACK by more than the stale timeout during
            # the lifetime of our anchor defeats the veto; accepted - pre-#9870 there was no
            # cross-check at all, and re-anchoring at each lock creation bounds the window.
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
                if anchor.mtime is None:
                    # first harvest for this anchor: cross-check the storage clock's continuity.
                    self._check_store_clock_step(anchor, mtime)
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
        blocking_locks = []  # the foreign lock(s) that most recently kept us from acquiring
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
                            blocking_locks = [lock for lock in locks if lock["key"] != key]
                            self._log_blocking_locks(blocking_locks)
                            time.sleep(self.other_locks_go_away_delay)
                        logger.debug("LOCK-ACQUIRE: timeout while waiting for non-exclusive locks to go away.")
                        # we won't get the exclusive lock, so do not leave our lock behind:
                        # it would needlessly block other clients until it expired as stale.
                        self._delete_lock(key, ignore_not_found=True, update_last_refresh=True)
                        break  # timeout
                    else:
                        logger.debug("LOCK-ACQUIRE: someone else also created an exclusive lock, deleting ours.")
                        blocking_locks = [lock for lock in exclusive_locks if lock["key"] != key]
                        self._delete_lock(key, ignore_not_found=True, update_last_refresh=True)
                else:  # not is_exclusive
                    if len(exclusive_locks) == 0:
                        logger.debug("LOCK-ACQUIRE: success! no exclusive locks detected.")
                        # We don't care for other non-exclusive locks.
                        return self
                    else:
                        logger.debug("LOCK-ACQUIRE: exclusive locks detected, deleting our shared lock.")
                        blocking_locks = [lock for lock in exclusive_locks if lock["key"] != key]
                        self._delete_lock(key, ignore_not_found=True, update_last_refresh=True)
            else:
                # there is at least one exclusive lock we can not consider stale - it blocks us.
                blocking_locks = exclusive_locks
            self._log_blocking_locks(blocking_locks)
            # wait a random bit before retrying
            time.sleep(
                self.retry_delay_min + (self.retry_delay_max - self.retry_delay_min) * random.random()  # nosec B311
            )
        logger.debug("LOCK-ACQUIRE: timeout while trying to acquire a lock.")
        raise LockTimeout(self.repository, f"Repository is locked by: {format_locks(blocking_locks)}.")

    def _log_blocking_locks(self, locks):
        """Tell the user (once) which foreign lock(s) we are waiting for."""
        if locks and not self.blocking_locks_logged:
            self.blocking_locks_logged = True
            logger.info(f"Waiting for the lock. Repository is locked by: {format_locks(locks)}.")

    def release(self, *, ignore_not_found=False):
        self.last_refresh_dt = None
        locks = self._find_locks(only_mine=True)
        if not locks:
            if ignore_not_found:
                logger.debug("LOCK-RELEASE: trying to release the lock, but none was found.")
                return
            else:
                raise NotLocked(self.repository)
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
            logger.info(f"Breaking {format_lock(locks[key])}.")
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
            old_key = self.my_lock_key
            logger.debug(f"LOCK-REFRESH: lock needs a refresh. key: {old_key}.")
            # create the new lock object BEFORE listing: the listing then harvests a fresh (seconds
            # old) store-clock anchor before its stale sweep judges other locks with it. listing
            # first would judge with the anchor of the previous refresh (up to refresh_td old) -
            # a window in which a storage clock that stepped back meanwhile could make the store-
            # domain cross-check wrongly confirm a skewed peer's healthy lock as stale, see #9870.
            new_key = self._create_lock(exclusive=self.is_exclusive, update_last_refresh=True)
            self.my_old_lock_key = old_key  # exempt our old lock from the stale sweep meanwhile
            try:
                locks = self._find_locks(only_mine=True)
                if old_key not in {lock["key"] for lock in locks}:
                    # crap, my lock has been removed. :-(
                    # this can happen e.g. if my machine has been suspended while doing a backup, so that the
                    # lock became stale and a borg client on another machine killed it.
                    # if my machine then wakes up again, the lock will have vanished and we get here.
                    # note: if our lock became stale, but is still present (no other client killed it),
                    # we do not get here - we never consider our own lock stale (see _is_stale_lock),
                    # so it is found above and simply replaced below.
                    # in this case, we need to abort the operation, because the other borg might have removed
                    # repo objects we have written, but the referential tree was not yet full present, e.g.
                    # no archive has been added yet to the manifest, thus all objects looked unused/orphaned.
                    # another scenario when this can happen is a careless user running break-lock on another
                    # machine without making sure there is no borg activity in that repo.
                    # clean up the new lock (so it does not needlessly block others until it expires).
                    logger.debug("LOCK-REFRESH: our lock was killed, there is no safe way to continue.")
                    self._delete_lock(new_key, ignore_not_found=True, update_last_refresh=True)
                    raise LockTimeout(self.repository, LOCK_KILLED_MSG)
                try:
                    self._delete_lock(old_key, update_last_refresh=False)
                except ObjectNotFound:
                    # our old lock vanished between listing and deleting it: another client considered
                    # it stale, killed it and (not having seen our new lock in its recheck) might have
                    # acquired its own lock already. there is no safe way to continue - clean up the
                    # new lock (so it does not needlessly block others until it expires) and abort.
                    logger.debug("LOCK-REFRESH: our lock was killed while refreshing it, no safe way to continue.")
                    self._delete_lock(new_key, ignore_not_found=True, update_last_refresh=True)
                    raise LockTimeout(self.repository, LOCK_KILLED_MSG)
            finally:
                self.my_old_lock_key = None


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

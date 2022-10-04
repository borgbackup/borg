import errno
import mmap
import os
import shutil
import stat
import struct
import time
from binascii import unhexlify
from collections import defaultdict
from configparser import ConfigParser
from datetime import datetime, timezone
from functools import partial
from itertools import islice

from .constants import *  # NOQA
from .hashindex import NSIndexEntry, NSIndex, NSIndex1, hashindex_variant
from .helpers import Error, ErrorWithTraceback, IntegrityError, format_file_size, parse_file_size
from .helpers import Location
from .helpers import ProgressIndicatorPercent
from .helpers import bin_to_hex
from .helpers import secure_erase, safe_unlink
from .helpers import msgpack
from .helpers.lrucache import LRUCache
from .locking import Lock, LockError, LockErrorT
from .logger import create_logger
from .manifest import Manifest
from .platform import SaveFile, SyncFile, sync_dir, safe_fadvise
from .repoobj import RepoObj
from .checksums import crc32, StreamingXXH64
from .crypto.file_integrity import IntegrityCheckedFile, FileIntegrityError

logger = create_logger(__name__)

MAGIC = b"BORG_SEG"
MAGIC_LEN = len(MAGIC)

TAG_PUT = 0
TAG_DELETE = 1
TAG_COMMIT = 2
TAG_PUT2 = 3

# Highest ID usable as TAG_* value
#
# Code may expect not to find any tags exceeding this value. In particular,
# in order to speed up `borg check --repair`, any tag greater than MAX_TAG_ID
# is assumed to be corrupted. When increasing this value, in order to add more
# tags, keep in mind that old versions of Borg accessing a new repository
# may not be able to handle the new tags.
MAX_TAG_ID = 15

FreeSpace = partial(defaultdict, int)


def header_size(tag):
    if tag == TAG_PUT2:
        size = LoggedIO.HEADER_ID_SIZE + LoggedIO.ENTRY_HASH_SIZE
    elif tag == TAG_PUT or tag == TAG_DELETE:
        size = LoggedIO.HEADER_ID_SIZE
    elif tag == TAG_COMMIT:
        size = LoggedIO.header_fmt.size
    else:
        raise ValueError(f"unsupported tag: {tag!r}")
    return size


class Repository:
    """
    Filesystem based transactional key value store

    Transactionality is achieved by using a log (aka journal) to record changes. The log is a series of numbered files
    called segments. Each segment is a series of log entries. The segment number together with the offset of each
    entry relative to its segment start establishes an ordering of the log entries. This is the "definition" of
    time for the purposes of the log.

    Log entries are either PUT, DELETE or COMMIT.

    A COMMIT is always the final log entry in a segment and marks all data from the beginning of the log until the
    segment ending with the COMMIT as committed and consistent. The segment number of a segment ending with a COMMIT
    is called the transaction ID of that commit, and a segment ending with a COMMIT is called committed.

    When reading from a repository it is first checked whether the last segment is committed. If it is not, then
    all segments after the last committed segment are deleted; they contain log entries whose consistency is not
    established by a COMMIT.

    Note that the COMMIT can't establish consistency by itself, but only manages to do so with proper support from
    the platform (including the hardware). See platform.base.SyncFile for details.

    A PUT inserts a key-value pair. The value is stored in the log entry, hence the repository implements
    full data logging, meaning that all data is consistent, not just metadata (which is common in file systems).

    A DELETE marks a key as deleted.

    For a given key only the last entry regarding the key, which is called current (all other entries are called
    superseded), is relevant: If there is no entry or the last entry is a DELETE then the key does not exist.
    Otherwise the last PUT defines the value of the key.

    By superseding a PUT (with either another PUT or a DELETE) the log entry becomes obsolete. A segment containing
    such obsolete entries is called sparse, while a segment containing no such entries is called compact.

    Sparse segments can be compacted and thereby disk space freed. This destroys the transaction for which the
    superseded entries where current.

    On disk layout:

    dir/README
    dir/config
    dir/data/<X // SEGMENTS_PER_DIR>/<X>
    dir/index.X
    dir/hints.X

    File system interaction
    -----------------------

    LoggedIO generally tries to rely on common behaviours across transactional file systems.

    Segments that are deleted are truncated first, which avoids problems if the FS needs to
    allocate space to delete the dirent of the segment. This mostly affects CoW file systems,
    traditional journaling file systems have a fairly good grip on this problem.

    Note that deletion, i.e. unlink(2), is atomic on every file system that uses inode reference
    counts, which includes pretty much all of them. To remove a dirent the inodes refcount has
    to be decreased, but you can't decrease the refcount before removing the dirent nor can you
    decrease the refcount after removing the dirent. File systems solve this with a lock,
    and by ensuring it all stays within the same FS transaction.

    Truncation is generally not atomic in itself, and combining truncate(2) and unlink(2) is of
    course never guaranteed to be atomic. Truncation in a classic extent-based FS is done in
    roughly two phases, first the extents are removed then the inode is updated. (In practice
    this is of course way more complex).

    LoggedIO gracefully handles truncate/unlink splits as long as the truncate resulted in
    a zero length file. Zero length segments are considered to not exist, while LoggedIO.cleanup()
    will still get rid of them.
    """

    class DoesNotExist(Error):
        """Repository {} does not exist."""

    class AlreadyExists(Error):
        """A repository already exists at {}."""

    class PathAlreadyExists(Error):
        """There is already something at {}."""

    class ParentPathDoesNotExist(Error):
        """The parent path of the repo directory [{}] does not exist."""

    class InvalidRepository(Error):
        """{} is not a valid repository. Check repo config."""

    class InvalidRepositoryConfig(Error):
        """{} does not have a valid configuration. Check repo config [{}]."""

    class CheckNeeded(ErrorWithTraceback):
        """Inconsistency detected. Please run "borg check {}"."""

    class ObjectNotFound(ErrorWithTraceback):
        """Object with key {} not found in repository {}."""

        def __init__(self, id, repo):
            if isinstance(id, bytes):
                id = bin_to_hex(id)
            super().__init__(id, repo)

    class InsufficientFreeSpaceError(Error):
        """Insufficient free space to complete transaction (required: {}, available: {})."""

    class StorageQuotaExceeded(Error):
        """The storage quota ({}) has been exceeded ({}). Try deleting some archives."""

    def __init__(
        self,
        path,
        create=False,
        exclusive=False,
        lock_wait=None,
        lock=True,
        append_only=False,
        storage_quota=None,
        make_parent_dirs=False,
    ):
        self.path = os.path.abspath(path)
        self._location = Location("file://%s" % self.path)
        self.version = None
        self.io = None  # type: LoggedIO
        self.lock = None
        self.index = None
        # This is an index of shadowed log entries during this transaction. Consider the following sequence:
        # segment_n PUT A, segment_x DELETE A
        # After the "DELETE A" in segment_x the shadow index will contain "A -> [n]".
        # .delete() is updating this index, it is persisted into "hints" file and is later used by .compact_segments().
        self.shadow_index = {}
        self._active_txn = False
        self.lock_wait = lock_wait
        self.do_lock = lock
        self.do_create = create
        self.created = False
        self.exclusive = exclusive
        self.append_only = append_only
        self.storage_quota = storage_quota
        self.storage_quota_use = 0
        self.transaction_doomed = None
        self.make_parent_dirs = make_parent_dirs
        # v2 is the default repo version for borg 2.0
        # v1 repos must only be used in a read-only way, e.g. for
        # --other-repo=V1_REPO with borg init and borg transfer!
        self.acceptable_repo_versions = (1, 2)

    def __del__(self):
        if self.lock:
            self.close()
            assert False, "cleanup happened in Repository.__del__"

    def __repr__(self):
        return f"<{self.__class__.__name__} {self.path}>"

    def __enter__(self):
        if self.do_create:
            self.do_create = False
            self.create(self.path)
            self.created = True
        self.open(self.path, bool(self.exclusive), lock_wait=self.lock_wait, lock=self.do_lock)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            no_space_left_on_device = exc_type is OSError and exc_val.errno == errno.ENOSPC
            # The ENOSPC could have originated somewhere else besides the Repository. The cleanup is always safe, unless
            # EIO or FS corruption ensues, which is why we specifically check for ENOSPC.
            if self._active_txn and no_space_left_on_device:
                logger.warning("No space left on device, cleaning up partial transaction to free space.")
                cleanup = True
            else:
                cleanup = False
            self._rollback(cleanup=cleanup)
        self.close()

    @property
    def id_str(self):
        return bin_to_hex(self.id)

    @staticmethod
    def is_repository(path):
        """Check whether there is already a Borg repository at *path*."""
        try:
            # Use binary mode to avoid troubles if a README contains some stuff not in our locale
            with open(os.path.join(path, "README"), "rb") as fd:
                # Read only the first ~100 bytes (if any), in case some README file we stumble upon is large.
                readme_head = fd.read(100)
                # The first comparison captures our current variant (REPOSITORY_README), the second comparison
                # is an older variant of the README file (used by 1.0.x).
                return b"Borg Backup repository" in readme_head or b"Borg repository" in readme_head
        except OSError:
            # Ignore FileNotFound, PermissionError, ...
            return False

    def check_can_create_repository(self, path):
        """
        Raise an exception if a repository already exists at *path* or any parent directory.

        Checking parent directories is done for two reasons:
        (1) It's just a weird thing to do, and usually not intended. A Borg using the "parent" repository
            may be confused, or we may accidentally put stuff into the "data/" or "data/<n>/" directories.
        (2) When implementing repository quotas (which we currently don't), it's important to prohibit
            folks from creating quota-free repositories. Since no one can create a repository within another
            repository, user's can only use the quota'd repository, when their --restrict-to-path points
            at the user's repository.
        """
        try:
            st = os.stat(path)
        except FileNotFoundError:
            pass  # nothing there!
        else:
            # there is something already there!
            if self.is_repository(path):
                raise self.AlreadyExists(path)
            if not stat.S_ISDIR(st.st_mode) or os.listdir(path):
                raise self.PathAlreadyExists(path)
            # an empty directory is acceptable for us.

        while True:
            # Check all parent directories for Borg's repository README
            previous_path = path
            # Thus, path = previous_path/..
            path = os.path.abspath(os.path.join(previous_path, os.pardir))
            if path == previous_path:
                # We reached the root of the directory hierarchy (/.. = / and C:\.. = C:\).
                break
            if self.is_repository(path):
                raise self.AlreadyExists(path)

    def create(self, path):
        """Create a new empty repository at `path`"""
        self.check_can_create_repository(path)
        if self.make_parent_dirs:
            parent_path = os.path.join(path, os.pardir)
            os.makedirs(parent_path, exist_ok=True)
        if not os.path.exists(path):
            try:
                os.mkdir(path)
            except FileNotFoundError as err:
                raise self.ParentPathDoesNotExist(path) from err
        with open(os.path.join(path, "README"), "w") as fd:
            fd.write(REPOSITORY_README)
        os.mkdir(os.path.join(path, "data"))
        config = ConfigParser(interpolation=None)
        config.add_section("repository")
        self.version = 2
        config.set("repository", "version", str(self.version))
        config.set("repository", "segments_per_dir", str(DEFAULT_SEGMENTS_PER_DIR))
        config.set("repository", "max_segment_size", str(DEFAULT_MAX_SEGMENT_SIZE))
        config.set("repository", "append_only", str(int(self.append_only)))
        if self.storage_quota:
            config.set("repository", "storage_quota", str(self.storage_quota))
        else:
            config.set("repository", "storage_quota", "0")
        config.set("repository", "additional_free_space", "0")
        config.set("repository", "id", bin_to_hex(os.urandom(32)))
        self.save_config(path, config)

    def save_config(self, path, config):
        config_path = os.path.join(path, "config")
        old_config_path = os.path.join(path, "config.old")

        if os.path.isfile(old_config_path):
            logger.warning("Old config file not securely erased on previous config update")
            secure_erase(old_config_path, avoid_collateral_damage=True)

        if os.path.isfile(config_path):
            link_error_msg = (
                "Failed to securely erase old repository config file (hardlinks not supported). "
                "Old repokey data, if any, might persist on physical storage."
            )
            try:
                os.link(config_path, old_config_path)
            except OSError as e:
                if e.errno in (errno.EMLINK, errno.ENOSYS, errno.EPERM, errno.EACCES, errno.ENOTSUP, errno.EIO):
                    logger.warning(link_error_msg)
                else:
                    raise
            except AttributeError:
                # some python ports have no os.link, see #4901
                logger.warning(link_error_msg)

        try:
            with SaveFile(config_path) as fd:
                config.write(fd)
        except PermissionError as e:
            # error is only a problem if we even had a lock
            if self.do_lock:
                raise
            logger.warning(
                "%s: Failed writing to '%s'. This is expected when working on "
                "read-only repositories." % (e.strerror, e.filename)
            )

        if os.path.isfile(old_config_path):
            secure_erase(old_config_path, avoid_collateral_damage=True)

    def save_key(self, keydata):
        assert self.config
        keydata = keydata.decode("utf-8")  # remote repo: msgpack issue #99, getting bytes
        # note: saving an empty key means that there is no repokey any more
        self.config.set("repository", "key", keydata)
        self.save_config(self.path, self.config)

    def load_key(self):
        keydata = self.config.get("repository", "key", fallback="").strip()
        # note: if we return an empty string, it means there is no repo key
        return keydata.encode("utf-8")  # remote repo: msgpack issue #99, returning bytes

    def get_free_nonce(self):
        if self.do_lock and not self.lock.got_exclusive_lock():
            raise AssertionError("bug in code, exclusive lock should exist here")

        nonce_path = os.path.join(self.path, "nonce")
        try:
            with open(nonce_path) as fd:
                return int.from_bytes(unhexlify(fd.read()), byteorder="big")
        except FileNotFoundError:
            return None

    def commit_nonce_reservation(self, next_unreserved, start_nonce):
        if self.do_lock and not self.lock.got_exclusive_lock():
            raise AssertionError("bug in code, exclusive lock should exist here")

        if self.get_free_nonce() != start_nonce:
            raise Exception("nonce space reservation with mismatched previous state")
        nonce_path = os.path.join(self.path, "nonce")
        try:
            with SaveFile(nonce_path, binary=False) as fd:
                fd.write(bin_to_hex(next_unreserved.to_bytes(8, byteorder="big")))
        except PermissionError as e:
            # error is only a problem if we even had a lock
            if self.do_lock:
                raise
            logger.warning(
                "%s: Failed writing to '%s'. This is expected when working on "
                "read-only repositories." % (e.strerror, e.filename)
            )

    def destroy(self):
        """Destroy the repository at `self.path`"""
        if self.append_only:
            raise ValueError(self.path + " is in append-only mode")
        self.close()
        os.remove(os.path.join(self.path, "config"))  # kill config first
        shutil.rmtree(self.path)

    def get_index_transaction_id(self):
        indices = sorted(
            int(fn[6:])
            for fn in os.listdir(self.path)
            if fn.startswith("index.") and fn[6:].isdigit() and os.stat(os.path.join(self.path, fn)).st_size != 0
        )
        if indices:
            return indices[-1]
        else:
            return None

    def check_transaction(self):
        index_transaction_id = self.get_index_transaction_id()
        segments_transaction_id = self.io.get_segments_transaction_id()
        if index_transaction_id is not None and segments_transaction_id is None:
            # we have a transaction id from the index, but we did not find *any*
            # commit in the segment files (thus no segments transaction id).
            # this can happen if a lot of segment files are lost, e.g. due to a
            # filesystem or hardware malfunction. it means we have no identifiable
            # valid (committed) state of the repo which we could use.
            msg = '%s" - although likely this is "beyond repair' % self.path  # dirty hack
            raise self.CheckNeeded(msg)
        # Attempt to automatically rebuild index if we crashed between commit
        # tag write and index save.
        if index_transaction_id != segments_transaction_id:
            if index_transaction_id is not None and index_transaction_id > segments_transaction_id:
                replay_from = None
            else:
                replay_from = index_transaction_id
            self.replay_segments(replay_from, segments_transaction_id)

    def get_transaction_id(self):
        self.check_transaction()
        return self.get_index_transaction_id()

    def break_lock(self):
        Lock(os.path.join(self.path, "lock")).break_lock()

    def migrate_lock(self, old_id, new_id):
        # note: only needed for local repos
        if self.lock is not None:
            self.lock.migrate_lock(old_id, new_id)

    def open(self, path, exclusive, lock_wait=None, lock=True):
        self.path = path
        try:
            st = os.stat(path)
        except FileNotFoundError:
            raise self.DoesNotExist(path)
        if not stat.S_ISDIR(st.st_mode):
            raise self.InvalidRepository(path)
        if lock:
            self.lock = Lock(os.path.join(path, "lock"), exclusive, timeout=lock_wait).acquire()
        else:
            self.lock = None
        self.config = ConfigParser(interpolation=None)
        try:
            with open(os.path.join(self.path, "config")) as fd:
                self.config.read_file(fd)
        except FileNotFoundError:
            self.close()
            raise self.InvalidRepository(self.path)
        if "repository" not in self.config.sections():
            self.close()
            raise self.InvalidRepositoryConfig(path, "no repository section found")
        self.version = self.config.getint("repository", "version")
        if self.version not in self.acceptable_repo_versions:
            self.close()
            raise self.InvalidRepositoryConfig(
                path, "repository version %d is not supported by this borg version" % self.version
            )
        self.max_segment_size = parse_file_size(self.config.get("repository", "max_segment_size"))
        if self.max_segment_size >= MAX_SEGMENT_SIZE_LIMIT:
            self.close()
            raise self.InvalidRepositoryConfig(path, "max_segment_size >= %d" % MAX_SEGMENT_SIZE_LIMIT)  # issue 3592
        self.segments_per_dir = self.config.getint("repository", "segments_per_dir")
        self.additional_free_space = parse_file_size(self.config.get("repository", "additional_free_space", fallback=0))
        # append_only can be set in the constructor
        # it shouldn't be overridden (True -> False) here
        self.append_only = self.append_only or self.config.getboolean("repository", "append_only", fallback=False)
        if self.storage_quota is None:
            # self.storage_quota is None => no explicit storage_quota was specified, use repository setting.
            self.storage_quota = parse_file_size(self.config.get("repository", "storage_quota", fallback=0))
        self.id = unhexlify(self.config.get("repository", "id").strip())
        self.io = LoggedIO(self.path, self.max_segment_size, self.segments_per_dir)

    def info(self):
        """return some infos about the repo (must be opened first)"""
        return dict(id=self.id, version=self.version, append_only=self.append_only)

    def close(self):
        if self.lock:
            if self.io:
                self.io.close()
            self.io = None
            self.lock.release()
            self.lock = None

    def commit(self, save_space=False, compact=True, threshold=0.1):
        """Commit transaction"""
        # save_space is not used anymore, but stays for RPC/API compatibility.
        if self.transaction_doomed:
            exception = self.transaction_doomed
            self.rollback()
            raise exception
        self.check_free_space()
        self.log_storage_quota()
        segment = self.io.write_commit()
        self.segments.setdefault(segment, 0)
        self.compact[segment] += LoggedIO.header_fmt.size
        if compact and not self.append_only:
            self.compact_segments(threshold)
        self.write_index()
        self.rollback()

    def _read_integrity(self, transaction_id, key):
        integrity_file = "integrity.%d" % transaction_id
        integrity_path = os.path.join(self.path, integrity_file)
        try:
            with open(integrity_path, "rb") as fd:
                integrity = msgpack.unpack(fd)
        except FileNotFoundError:
            return
        if integrity.get("version") != 2:
            logger.warning("Unknown integrity data version %r in %s", integrity.get("version"), integrity_file)
            return
        return integrity[key]

    def open_index(self, transaction_id, auto_recover=True):
        if transaction_id is None:
            return NSIndex()
        index_path = os.path.join(self.path, "index.%d" % transaction_id)
        variant = hashindex_variant(index_path)
        integrity_data = self._read_integrity(transaction_id, "index")
        try:
            with IntegrityCheckedFile(index_path, write=False, integrity_data=integrity_data) as fd:
                if variant == 2:
                    return NSIndex.read(fd)
                if variant == 1:  # legacy
                    return NSIndex1.read(fd)
        except (ValueError, OSError, FileIntegrityError) as exc:
            logger.warning("Repository index missing or corrupted, trying to recover from: %s", exc)
            os.unlink(index_path)
            if not auto_recover:
                raise
            self.prepare_txn(self.get_transaction_id())
            # don't leave an open transaction around
            self.commit(compact=False)
            return self.open_index(self.get_transaction_id())

    def prepare_txn(self, transaction_id, do_cleanup=True):
        self._active_txn = True
        if self.do_lock and not self.lock.got_exclusive_lock():
            if self.exclusive is not None:
                # self.exclusive is either True or False, thus a new client is active here.
                # if it is False and we get here, the caller did not use exclusive=True although
                # it is needed for a write operation. if it is True and we get here, something else
                # went very wrong, because we should have an exclusive lock, but we don't.
                raise AssertionError("bug in code, exclusive lock should exist here")
            # if we are here, this is an old client talking to a new server (expecting lock upgrade).
            # or we are replaying segments and might need a lock upgrade for that.
            try:
                self.lock.upgrade()
            except (LockError, LockErrorT):
                # if upgrading the lock to exclusive fails, we do not have an
                # active transaction. this is important for "serve" mode, where
                # the repository instance lives on - even if exceptions happened.
                self._active_txn = False
                raise
        if not self.index or transaction_id is None:
            try:
                self.index = self.open_index(transaction_id, auto_recover=False)
            except (ValueError, OSError, FileIntegrityError) as exc:
                logger.warning("Checking repository transaction due to previous error: %s", exc)
                self.check_transaction()
                self.index = self.open_index(transaction_id, auto_recover=False)
        if transaction_id is None:
            self.segments = {}  # XXX bad name: usage_count_of_segment_x = self.segments[x]
            self.compact = FreeSpace()  # XXX bad name: freeable_space_of_segment_x = self.compact[x]
            self.storage_quota_use = 0
            self.shadow_index.clear()
        else:
            if do_cleanup:
                self.io.cleanup(transaction_id)
            hints_path = os.path.join(self.path, "hints.%d" % transaction_id)
            index_path = os.path.join(self.path, "index.%d" % transaction_id)
            integrity_data = self._read_integrity(transaction_id, "hints")
            try:
                with IntegrityCheckedFile(hints_path, write=False, integrity_data=integrity_data) as fd:
                    hints = msgpack.unpack(fd)
            except (msgpack.UnpackException, FileNotFoundError, FileIntegrityError) as e:
                logger.warning("Repository hints file missing or corrupted, trying to recover: %s", e)
                if not isinstance(e, FileNotFoundError):
                    os.unlink(hints_path)
                # index must exist at this point
                os.unlink(index_path)
                self.check_transaction()
                self.prepare_txn(transaction_id)
                return
            if hints["version"] == 1:
                logger.debug("Upgrading from v1 hints.%d", transaction_id)
                self.segments = hints["segments"]
                self.compact = FreeSpace()
                self.storage_quota_use = 0
                self.shadow_index = {}
                for segment in sorted(hints["compact"]):
                    logger.debug("Rebuilding sparse info for segment %d", segment)
                    self._rebuild_sparse(segment)
                logger.debug("Upgrade to v2 hints complete")
            elif hints["version"] != 2:
                raise ValueError("Unknown hints file version: %d" % hints["version"])
            else:
                self.segments = hints["segments"]
                self.compact = FreeSpace(hints["compact"])
                self.storage_quota_use = hints.get("storage_quota_use", 0)
                self.shadow_index = hints.get("shadow_index", {})
            self.log_storage_quota()
            # Drop uncommitted segments in the shadow index
            for key, shadowed_segments in self.shadow_index.items():
                for segment in list(shadowed_segments):
                    if segment > transaction_id:
                        shadowed_segments.remove(segment)

    def write_index(self):
        def flush_and_sync(fd):
            fd.flush()
            os.fsync(fd.fileno())

        def rename_tmp(file):
            os.rename(file + ".tmp", file)

        hints = {
            "version": 2,
            "segments": self.segments,
            "compact": self.compact,
            "storage_quota_use": self.storage_quota_use,
            "shadow_index": self.shadow_index,
        }
        integrity = {
            # Integrity version started at 2, the current hints version.
            # Thus, integrity version == hints version, for now.
            "version": 2
        }
        transaction_id = self.io.get_segments_transaction_id()
        assert transaction_id is not None

        # Log transaction in append-only mode
        if self.append_only:
            with open(os.path.join(self.path, "transactions"), "a") as log:
                print(
                    "transaction %d, UTC time %s"
                    % (transaction_id, datetime.now(tz=timezone.utc).isoformat(timespec="microseconds")),
                    file=log,
                )

        # Write hints file
        hints_name = "hints.%d" % transaction_id
        hints_file = os.path.join(self.path, hints_name)
        with IntegrityCheckedFile(hints_file + ".tmp", filename=hints_name, write=True) as fd:
            msgpack.pack(hints, fd)
            flush_and_sync(fd)
        integrity["hints"] = fd.integrity_data

        # Write repository index
        index_name = "index.%d" % transaction_id
        index_file = os.path.join(self.path, index_name)
        with IntegrityCheckedFile(index_file + ".tmp", filename=index_name, write=True) as fd:
            # XXX: Consider using SyncFile for index write-outs.
            self.index.write(fd)
            flush_and_sync(fd)
        integrity["index"] = fd.integrity_data

        # Write integrity file, containing checksums of the hints and index files
        integrity_name = "integrity.%d" % transaction_id
        integrity_file = os.path.join(self.path, integrity_name)
        with open(integrity_file + ".tmp", "wb") as fd:
            msgpack.pack(integrity, fd)
            flush_and_sync(fd)

        # Rename the integrity file first
        rename_tmp(integrity_file)
        sync_dir(self.path)
        # Rename the others after the integrity file is hypothetically on disk
        rename_tmp(hints_file)
        rename_tmp(index_file)
        sync_dir(self.path)

        # Remove old auxiliary files
        current = ".%d" % transaction_id
        for name in os.listdir(self.path):
            if not name.startswith(("index.", "hints.", "integrity.")):
                continue
            if name.endswith(current):
                continue
            os.unlink(os.path.join(self.path, name))
        self.index = None

    def check_free_space(self):
        """Pre-commit check for sufficient free space to actually perform the commit."""
        # As a baseline we take four times the current (on-disk) index size.
        # At this point the index may only be updated by compaction, which won't resize it.
        # We still apply a factor of four so that a later, separate invocation can free space
        # (journaling all deletes for all chunks is one index size) or still make minor additions
        # (which may grow the index up to twice its current size).
        # Note that in a subsequent operation the committed index is still on-disk, therefore we
        # arrive at index_size * (1 + 2 + 1).
        # In that order: journaled deletes (1), hashtable growth (2), persisted index (1).
        required_free_space = self.index.size() * 4

        # Conservatively estimate hints file size:
        # 10 bytes for each segment-refcount pair, 10 bytes for each segment-space pair
        # Assume maximum of 5 bytes per integer. Segment numbers will usually be packed more densely (1-3 bytes),
        # as will refcounts and free space integers. For 5 MiB segments this estimate is good to ~20 PB repo size.
        # Add 4K to generously account for constant format overhead.
        hints_size = len(self.segments) * 10 + len(self.compact) * 10 + 4096
        required_free_space += hints_size

        required_free_space += self.additional_free_space
        if not self.append_only:
            full_segment_size = self.max_segment_size + MAX_OBJECT_SIZE
            if len(self.compact) < 10:
                # This is mostly for the test suite to avoid overestimated free space needs. This can be annoying
                # if TMP is a small-ish tmpfs.
                compact_working_space = 0
                for segment, free in self.compact.items():
                    try:
                        compact_working_space += self.io.segment_size(segment) - free
                    except FileNotFoundError:
                        # looks like self.compact is referring to a non-existent segment file, ignore it.
                        pass
                logger.debug("check_free_space: Few segments, not requiring a full free segment")
                compact_working_space = min(compact_working_space, full_segment_size)
                logger.debug(
                    "check_free_space: Calculated working space for compact as %d bytes", compact_working_space
                )
                required_free_space += compact_working_space
            else:
                # Keep one full worst-case segment free in non-append-only mode
                required_free_space += full_segment_size

        try:
            free_space = shutil.disk_usage(self.path).free
        except OSError as os_error:
            logger.warning("Failed to check free space before committing: " + str(os_error))
            return
        logger.debug(f"check_free_space: Required bytes {required_free_space}, free bytes {free_space}")
        if free_space < required_free_space:
            if self.created:
                logger.error("Not enough free space to initialize repository at this location.")
                self.destroy()
            else:
                self._rollback(cleanup=True)
            formatted_required = format_file_size(required_free_space)
            formatted_free = format_file_size(free_space)
            raise self.InsufficientFreeSpaceError(formatted_required, formatted_free)

    def log_storage_quota(self):
        if self.storage_quota:
            logger.info(
                "Storage quota: %s out of %s used.",
                format_file_size(self.storage_quota_use),
                format_file_size(self.storage_quota),
            )

    def compact_segments(self, threshold):
        """Compact sparse segments by copying data into new segments"""
        if not self.compact:
            logger.debug("Nothing to do: compact empty")
            return
        quota_use_before = self.storage_quota_use
        index_transaction_id = self.get_index_transaction_id()
        segments = self.segments
        unused = []  # list of segments, that are not used anymore

        def complete_xfer(intermediate=True):
            # complete the current transfer (when some target segment is full)
            nonlocal unused
            # commit the new, compact, used segments
            segment = self.io.write_commit(intermediate=intermediate)
            self.segments.setdefault(segment, 0)
            self.compact[segment] += LoggedIO.header_fmt.size
            logger.debug(
                "complete_xfer: Wrote %scommit at segment %d", "intermediate " if intermediate else "", segment
            )
            # get rid of the old, sparse, unused segments. free space.
            for segment in unused:
                logger.debug("complete_xfer: Deleting unused segment %d", segment)
                count = self.segments.pop(segment)
                assert count == 0, "Corrupted segment reference count - corrupted index or hints"
                self.io.delete_segment(segment)
                del self.compact[segment]
            unused = []

        logger.debug("Compaction started (threshold is %i%%).", threshold * 100)
        pi = ProgressIndicatorPercent(
            total=len(self.compact), msg="Compacting segments %3.0f%%", step=1, msgid="repository.compact_segments"
        )
        for segment, freeable_space in sorted(self.compact.items()):
            if not self.io.segment_exists(segment):
                logger.warning("Segment %d not found, but listed in compaction data", segment)
                del self.compact[segment]
                pi.show()
                continue
            segment_size = self.io.segment_size(segment)
            freeable_ratio = 1.0 * freeable_space / segment_size
            # we want to compact if:
            # - we can free a considerable relative amount of space (freeable_ratio over some threshold)
            if not (freeable_ratio > threshold):
                logger.debug(
                    "Not compacting segment %d (maybe freeable: %2.2f%% [%d bytes])",
                    segment,
                    freeable_ratio * 100.0,
                    freeable_space,
                )
                pi.show()
                continue
            segments.setdefault(segment, 0)
            logger.debug(
                "Compacting segment %d with usage count %d (maybe freeable: %2.2f%% [%d bytes])",
                segment,
                segments[segment],
                freeable_ratio * 100.0,
                freeable_space,
            )
            for tag, key, offset, _, data in self.io.iter_objects(segment):
                if tag == TAG_COMMIT:
                    continue
                in_index = self.index.get(key)
                is_index_object = in_index and (in_index.segment, in_index.offset) == (segment, offset)
                if tag in (TAG_PUT2, TAG_PUT) and is_index_object:
                    try:
                        new_segment, offset = self.io.write_put(key, data, raise_full=True)
                    except LoggedIO.SegmentFull:
                        complete_xfer()
                        new_segment, offset = self.io.write_put(key, data)
                    self.index[key] = NSIndexEntry(new_segment, offset, len(data))
                    segments.setdefault(new_segment, 0)
                    segments[new_segment] += 1
                    segments[segment] -= 1
                    if tag == TAG_PUT:
                        # old tag is PUT, but new will be PUT2 and use a bit more storage
                        self.storage_quota_use += self.io.ENTRY_HASH_SIZE
                elif tag in (TAG_PUT2, TAG_PUT) and not is_index_object:
                    # If this is a PUT shadowed by a later tag, then it will be gone when this segment is deleted after
                    # this loop. Therefore it is removed from the shadow index.
                    try:
                        self.shadow_index[key].remove(segment)
                    except (KeyError, ValueError):
                        # do not remove entry with empty shadowed_segments list here,
                        # it is needed for shadowed_put_exists code (see below)!
                        pass
                    self.storage_quota_use -= header_size(tag) + len(data)
                elif tag == TAG_DELETE and not in_index:
                    # If the shadow index doesn't contain this key, then we can't say if there's a shadowed older tag,
                    # therefore we do not drop the delete, but write it to a current segment.
                    key_not_in_shadow_index = key not in self.shadow_index
                    # If the key is in the shadow index and there is any segment with an older PUT of this
                    # key, we have a shadowed put.
                    shadowed_put_exists = key_not_in_shadow_index or any(
                        shadowed < segment for shadowed in self.shadow_index[key]
                    )
                    delete_is_not_stable = index_transaction_id is None or segment > index_transaction_id

                    if shadowed_put_exists or delete_is_not_stable:
                        # (introduced in 6425d16aa84be1eaaf88)
                        # This is needed to avoid object un-deletion if we crash between the commit and the deletion
                        # of old segments in complete_xfer().
                        #
                        # However, this only happens if the crash also affects the FS to the effect that file deletions
                        # did not materialize consistently after journal recovery. If they always materialize in-order
                        # then this is not a problem, because the old segment containing a deleted object would be
                        # deleted before the segment containing the delete.
                        #
                        # Consider the following series of operations if we would not do this, i.e. this entire if:
                        # would be removed.
                        # Columns are segments, lines are different keys (line 1 = some key, line 2 = some other key)
                        # Legend: P=TAG_PUT/TAG_PUT2, D=TAG_DELETE, c=commit, i=index is written for latest commit
                        #
                        # Segment | 1     | 2   | 3
                        # --------+-------+-----+------
                        # Key 1   | P     | D   |
                        # Key 2   | P     |     | P
                        # commits |   c i |   c |   c i
                        # --------+-------+-----+------
                        #                       ^- compact_segments starts
                        #                           ^- complete_xfer commits, after that complete_xfer deletes
                        #                              segments 1 and 2 (and then the index would be written).
                        #
                        # Now we crash. But only segment 2 gets deleted, while segment 1 is still around. Now key 1
                        # is suddenly undeleted (because the delete in segment 2 is now missing).
                        # Again, note the requirement here. We delete these in the correct order that this doesn't happen,
                        # and only if the FS materialization of these deletes is reordered or parts dropped this can happen.
                        # In this case it doesn't cause outright corruption, 'just' an index count mismatch, which will be
                        # fixed by borg-check --repair.
                        #
                        # Note that in this check the index state is the proxy for a "most definitely settled" repository state,
                        # i.e. the assumption is that *all* operations on segments <= index state are completed and stable.
                        try:
                            new_segment, size = self.io.write_delete(key, raise_full=True)
                        except LoggedIO.SegmentFull:
                            complete_xfer()
                            new_segment, size = self.io.write_delete(key)
                        self.compact[new_segment] += size
                        segments.setdefault(new_segment, 0)
                    else:
                        logger.debug(
                            "Dropping DEL for id %s - seg %d, iti %r, knisi %r, spe %r, dins %r, si %r",
                            bin_to_hex(key),
                            segment,
                            index_transaction_id,
                            key_not_in_shadow_index,
                            shadowed_put_exists,
                            delete_is_not_stable,
                            self.shadow_index.get(key),
                        )
                        # we did not keep the delete tag for key (see if-branch)
                        if not self.shadow_index[key]:
                            # shadowed segments list is empty -> remove it
                            del self.shadow_index[key]
            assert segments[segment] == 0, "Corrupted segment reference count - corrupted index or hints"
            unused.append(segment)
            pi.show()
        pi.finish()
        complete_xfer(intermediate=False)
        quota_use_after = self.storage_quota_use
        logger.info("Compaction freed about %s repository space.", format_file_size(quota_use_before - quota_use_after))
        logger.debug("Compaction completed.")

    def replay_segments(self, index_transaction_id, segments_transaction_id):
        # fake an old client, so that in case we do not have an exclusive lock yet, prepare_txn will upgrade the lock:
        remember_exclusive = self.exclusive
        self.exclusive = None
        self.prepare_txn(index_transaction_id, do_cleanup=False)
        try:
            segment_count = sum(1 for _ in self.io.segment_iterator())
            pi = ProgressIndicatorPercent(
                total=segment_count, msg="Replaying segments %3.0f%%", msgid="repository.replay_segments"
            )
            for i, (segment, filename) in enumerate(self.io.segment_iterator()):
                pi.show(i)
                if index_transaction_id is not None and segment <= index_transaction_id:
                    continue
                if segment > segments_transaction_id:
                    break
                objects = self.io.iter_objects(segment)
                self._update_index(segment, objects)
            pi.finish()
            self.write_index()
        finally:
            self.exclusive = remember_exclusive
            self.rollback()

    def _update_index(self, segment, objects, report=None):
        """some code shared between replay_segments and check"""
        self.segments[segment] = 0
        for tag, key, offset, size, _ in objects:
            if tag in (TAG_PUT2, TAG_PUT):
                try:
                    # If this PUT supersedes an older PUT, mark the old segment for compaction and count the free space
                    in_index = self.index[key]
                    self.compact[in_index.segment] += header_size(tag) + size
                    self.segments[in_index.segment] -= 1
                except KeyError:
                    pass
                self.index[key] = NSIndexEntry(segment, offset, size)
                self.segments[segment] += 1
                self.storage_quota_use += header_size(tag) + size
            elif tag == TAG_DELETE:
                try:
                    # if the deleted PUT is not in the index, there is nothing to clean up
                    in_index = self.index.pop(key)
                except KeyError:
                    pass
                else:
                    if self.io.segment_exists(in_index.segment):
                        # the old index is not necessarily valid for this transaction (e.g. compaction); if the segment
                        # is already gone, then it was already compacted.
                        self.segments[in_index.segment] -= 1
                        self.compact[in_index.segment] += header_size(tag) + in_index.size
            elif tag == TAG_COMMIT:
                continue
            else:
                msg = f"Unexpected tag {tag} in segment {segment}"
                if report is None:
                    raise self.CheckNeeded(msg)
                else:
                    report(msg)
        if self.segments[segment] == 0:
            self.compact[segment] = self.io.segment_size(segment)

    def _rebuild_sparse(self, segment):
        """Rebuild sparse bytes count for a single segment relative to the current index."""
        try:
            segment_size = self.io.segment_size(segment)
        except FileNotFoundError:
            # segment does not exist any more, remove it from the mappings.
            # note: no need to self.compact.pop(segment), as we start from empty mapping.
            self.segments.pop(segment)
            return

        if self.segments[segment] == 0:
            self.compact[segment] = segment_size
            return

        self.compact[segment] = 0
        for tag, key, offset, size, _ in self.io.iter_objects(segment, read_data=False):
            if tag in (TAG_PUT2, TAG_PUT):
                in_index = self.index.get(key)
                if not in_index or (in_index.segment, in_index.offset) != (segment, offset):
                    # This PUT is superseded later.
                    self.compact[segment] += header_size(tag) + size
            elif tag == TAG_DELETE:
                # The outcome of the DELETE has been recorded in the PUT branch already.
                self.compact[segment] += header_size(tag) + size

    def check(self, repair=False, save_space=False, max_duration=0):
        """Check repository consistency

        This method verifies all segment checksums and makes sure
        the index is consistent with the data stored in the segments.
        """
        if self.append_only and repair:
            raise ValueError(self.path + " is in append-only mode")
        error_found = False

        def report_error(msg):
            nonlocal error_found
            error_found = True
            logger.error(msg)

        logger.info("Starting repository check")
        assert not self._active_txn
        try:
            transaction_id = self.get_transaction_id()
            current_index = self.open_index(transaction_id)
            logger.debug("Read committed index of transaction %d", transaction_id)
        except Exception as exc:
            transaction_id = self.io.get_segments_transaction_id()
            current_index = None
            logger.debug("Failed to read committed index (%s)", exc)
        if transaction_id is None:
            logger.debug("No segments transaction found")
            transaction_id = self.get_index_transaction_id()
        if transaction_id is None:
            logger.debug("No index transaction found, trying latest segment")
            transaction_id = self.io.get_latest_segment()
        if transaction_id is None:
            report_error("This repository contains no valid data.")
            return False
        if repair:
            self.io.cleanup(transaction_id)
        segments_transaction_id = self.io.get_segments_transaction_id()
        logger.debug("Segment transaction is    %s", segments_transaction_id)
        logger.debug("Determined transaction is %s", transaction_id)
        self.prepare_txn(None)  # self.index, self.compact, self.segments, self.shadow_index all empty now!
        segment_count = sum(1 for _ in self.io.segment_iterator())
        logger.debug("Found %d segments", segment_count)

        partial = bool(max_duration)
        assert not (repair and partial)
        mode = "partial" if partial else "full"
        if partial:
            # continue a past partial check (if any) or start one from beginning
            last_segment_checked = self.config.getint("repository", "last_segment_checked", fallback=-1)
            logger.info("Skipping to segments >= %d", last_segment_checked + 1)
        else:
            # start from the beginning and also forget about any potential past partial checks
            last_segment_checked = -1
            self.config.remove_option("repository", "last_segment_checked")
            self.save_config(self.path, self.config)
        t_start = time.monotonic()
        pi = ProgressIndicatorPercent(
            total=segment_count, msg="Checking segments %3.1f%%", step=0.1, msgid="repository.check"
        )
        segment = -1  # avoid uninitialized variable if there are no segment files at all
        for i, (segment, filename) in enumerate(self.io.segment_iterator()):
            pi.show(i)
            if segment <= last_segment_checked:
                continue
            if segment > transaction_id:
                continue
            logger.debug("Checking segment file %s...", filename)
            try:
                objects = list(self.io.iter_objects(segment))
            except IntegrityError as err:
                report_error(str(err))
                objects = []
                if repair:
                    self.io.recover_segment(segment, filename)
                    objects = list(self.io.iter_objects(segment))
            if not partial:
                self._update_index(segment, objects, report_error)
            if partial and time.monotonic() > t_start + max_duration:
                logger.info("Finished partial segment check, last segment checked is %d", segment)
                self.config.set("repository", "last_segment_checked", str(segment))
                self.save_config(self.path, self.config)
                break
        else:
            logger.info("Finished segment check at segment %d", segment)
            self.config.remove_option("repository", "last_segment_checked")
            self.save_config(self.path, self.config)

        pi.finish()
        # self.index, self.segments, self.compact now reflect the state of the segment files up to <transaction_id>.
        # We might need to add a commit tag if no committed segment is found.
        if repair and segments_transaction_id is None:
            report_error(f"Adding commit tag to segment {transaction_id}")
            self.io.segment = transaction_id + 1
            self.io.write_commit()
        if not partial:
            logger.info("Starting repository index check")
            if current_index and not repair:
                # current_index = "as found on disk"
                # self.index = "as rebuilt in-memory from segments"
                if len(current_index) != len(self.index):
                    report_error("Index object count mismatch.")
                    logger.error("Committed index: %d objects", len(current_index))
                    logger.error("Rebuilt index:   %d objects", len(self.index))
                else:
                    logger.info("Index object count match.")
                line_format = "ID: %-64s rebuilt index: %-16s committed index: %-16s"
                not_found = "<not found>"
                for key, value in self.index.iteritems():
                    current_value = current_index.get(key, not_found)
                    if current_value != value:
                        logger.warning(line_format, bin_to_hex(key), value, current_value)
                for key, current_value in current_index.iteritems():
                    if key in self.index:
                        continue
                    value = self.index.get(key, not_found)
                    if current_value != value:
                        logger.warning(line_format, bin_to_hex(key), value, current_value)
            if repair:
                self.write_index()
        self.rollback()
        if error_found:
            if repair:
                logger.info("Finished %s repository check, errors found and repaired.", mode)
            else:
                logger.error("Finished %s repository check, errors found.", mode)
        else:
            logger.info("Finished %s repository check, no problems found.", mode)
        return not error_found or repair

    def scan_low_level(self, segment=None, offset=None):
        """Very low level scan over all segment file entries.

        It does NOT care about what's committed and what not.
        It does NOT care whether an object might be deleted or superseded later.
        It just yields anything it finds in the segment files.

        This is intended as a last-resort way to get access to all repo contents of damaged repos,
        when there is uncommitted, but valuable data in there...

        When segment or segment+offset is given, limit processing to this location only.
        """
        for current_segment, filename in self.io.segment_iterator(start_segment=segment, end_segment=segment):
            try:
                for tag, key, current_offset, _, data in self.io.iter_objects(
                    segment=current_segment, offset=offset or 0
                ):
                    if offset is not None and current_offset > offset:
                        break
                    yield key, data, tag, current_segment, current_offset
            except IntegrityError as err:
                logger.error(
                    "Segment %d (%s) has IntegrityError(s) [%s] - skipping." % (current_segment, filename, str(err))
                )

    def _rollback(self, *, cleanup):
        if cleanup:
            self.io.cleanup(self.io.get_segments_transaction_id())
        self.index = None
        self._active_txn = False
        self.transaction_doomed = None

    def rollback(self):
        # note: when used in remote mode, this is time limited, see RemoteRepository.shutdown_time.
        self._rollback(cleanup=False)

    def __len__(self):
        if not self.index:
            self.index = self.open_index(self.get_transaction_id())
        return len(self.index)

    def __contains__(self, id):
        if not self.index:
            self.index = self.open_index(self.get_transaction_id())
        return id in self.index

    def list(self, limit=None, marker=None, mask=0, value=0):
        """
        list <limit> IDs starting from after id <marker> - in index (pseudo-random) order.

        if mask and value are given, only return IDs where flags & mask == value (default: all IDs).
        """
        if not self.index:
            self.index = self.open_index(self.get_transaction_id())
        return [id_ for id_, _ in islice(self.index.iteritems(marker=marker, mask=mask, value=value), limit)]

    def scan(self, limit=None, state=None):
        """
        list (the next) <limit> chunk IDs from the repository - in on-disk order, so that a client
        fetching data in this order does linear reads and reuses stuff from disk cache.

        state can either be None (initially, when starting to scan) or the object
        returned from a previous scan call (meaning "continue scanning").

        returns: list of chunk ids, state

        We rely on repository.check() has run already (either now or some time before) and that:

        - if we are called from a borg check command, self.index is a valid, fresh, in-sync repo index.
        - if we are called from elsewhere, either self.index or the on-disk index is valid and in-sync.
        - the repository segments are valid (no CRC errors).
          if we encounter CRC errors in segment entry headers, rest of segment is skipped.
        """
        if limit is not None and limit < 1:
            raise ValueError("please use limit > 0 or limit = None")
        transaction_id = self.get_transaction_id()
        if not self.index:
            self.index = self.open_index(transaction_id)
        # smallest valid seg is <uint32> 0, smallest valid offs is <uint32> 8
        start_segment, start_offset, end_segment = state if state is not None else (0, 0, transaction_id)
        ids, segment, offset = [], 0, 0
        # we only scan up to end_segment == transaction_id to only scan **committed** chunks,
        # avoiding scanning into newly written chunks.
        for segment, filename in self.io.segment_iterator(start_segment, end_segment):
            # the start_offset we potentially got from state is only valid for the start_segment we also got
            # from there. in case the segment file vanished meanwhile, the segment_iterator might never
            # return a segment/filename corresponding to the start_segment and we must start from offset 0 then.
            start_offset = start_offset if segment == start_segment else 0
            obj_iterator = self.io.iter_objects(segment, start_offset, read_data=False)
            while True:
                try:
                    tag, id, offset, size, _ = next(obj_iterator)
                except (StopIteration, IntegrityError):
                    # either end-of-segment or an error - we can not seek to objects at
                    # higher offsets than one that has an error in the header fields.
                    break
                if start_offset > 0:
                    # we are using a state != None and it points to the last object we have already
                    # returned in the previous scan() call - thus, we need to skip this one object.
                    # also, for the next segment, we need to start at offset 0.
                    start_offset = 0
                    continue
                if tag in (TAG_PUT2, TAG_PUT):
                    in_index = self.index.get(id)
                    if in_index and (in_index.segment, in_index.offset) == (segment, offset):
                        # we have found an existing and current object
                        ids.append(id)
                        if len(ids) == limit:
                            return ids, (segment, offset, end_segment)
        return ids, (segment, offset, end_segment)

    def flags(self, id, mask=0xFFFFFFFF, value=None):
        """
        query and optionally set flags

        :param id: id (key) of object
        :param mask: bitmask for flags (default: operate on all 32 bits)
        :param value: value to set masked bits to (default: do not change any flags)
        :return: (previous) flags value (only masked bits)
        """
        if not self.index:
            self.index = self.open_index(self.get_transaction_id())
        return self.index.flags(id, mask, value)

    def flags_many(self, ids, mask=0xFFFFFFFF, value=None):
        return [self.flags(id_, mask, value) for id_ in ids]

    def get(self, id, read_data=True):
        if not self.index:
            self.index = self.open_index(self.get_transaction_id())
        try:
            in_index = NSIndexEntry(*((self.index[id] + (None,))[:3]))  # legacy: index entries have no size element
            return self.io.read(in_index.segment, in_index.offset, id, expected_size=in_index.size, read_data=read_data)
        except KeyError:
            raise self.ObjectNotFound(id, self.path) from None

    def get_many(self, ids, read_data=True, is_preloaded=False):
        for id_ in ids:
            yield self.get(id_, read_data=read_data)

    def put(self, id, data, wait=True):
        """put a repo object

        Note: when doing calls with wait=False this gets async and caller must
              deal with async results / exceptions later.
        """
        if not self._active_txn:
            self.prepare_txn(self.get_transaction_id())
        try:
            in_index = self.index[id]
        except KeyError:
            pass
        else:
            # note: doing a delete first will do some bookkeeping.
            # we do not want to update the shadow_index here, because
            # we know already that we will PUT to this id, so it will
            # be in the repo index (and we won't need it in the shadow_index).
            self._delete(id, in_index.segment, in_index.offset, in_index.size, update_shadow_index=False)
        segment, offset = self.io.write_put(id, data)
        self.storage_quota_use += header_size(TAG_PUT2) + len(data)
        self.segments.setdefault(segment, 0)
        self.segments[segment] += 1
        self.index[id] = NSIndexEntry(segment, offset, len(data))
        if self.storage_quota and self.storage_quota_use > self.storage_quota:
            self.transaction_doomed = self.StorageQuotaExceeded(
                format_file_size(self.storage_quota), format_file_size(self.storage_quota_use)
            )
            raise self.transaction_doomed

    def delete(self, id, wait=True):
        """delete a repo object

        Note: when doing calls with wait=False this gets async and caller must
              deal with async results / exceptions later.
        """
        if not self._active_txn:
            self.prepare_txn(self.get_transaction_id())
        try:
            in_index = self.index.pop(id)
        except KeyError:
            raise self.ObjectNotFound(id, self.path) from None
        # if we get here, there is an object with this id in the repo,
        # we write a DEL here that shadows the respective PUT.
        # after the delete, the object is not in the repo index any more,
        # for the compaction code, we need to update the shadow_index in this case.
        self._delete(id, in_index.segment, in_index.offset, in_index.size, update_shadow_index=True)

    def _delete(self, id, segment, offset, size, *, update_shadow_index):
        # common code used by put and delete
        if update_shadow_index:
            self.shadow_index.setdefault(id, []).append(segment)
        self.segments[segment] -= 1
        self.compact[segment] += header_size(TAG_PUT2) + size
        segment, size = self.io.write_delete(id)
        self.compact[segment] += size
        self.segments.setdefault(segment, 0)

    def async_response(self, wait=True):
        """Get one async result (only applies to remote repositories).

        async commands (== calls with wait=False, e.g. delete and put) have no results,
        but may raise exceptions. These async exceptions must get collected later via
        async_response() calls. Repeat the call until it returns None.
        The previous calls might either return one (non-None) result or raise an exception.
        If wait=True is given and there are outstanding responses, it will wait for them
        to arrive. With wait=False, it will only return already received responses.
        """

    def preload(self, ids):
        """Preload objects (only applies to remote repositories)"""


class LoggedIO:
    class SegmentFull(Exception):
        """raised when a segment is full, before opening next"""

    header_fmt = struct.Struct("<IIB")
    assert header_fmt.size == 9
    header_no_crc_fmt = struct.Struct("<IB")
    assert header_no_crc_fmt.size == 5
    crc_fmt = struct.Struct("<I")
    assert crc_fmt.size == 4

    _commit = header_no_crc_fmt.pack(9, TAG_COMMIT)
    COMMIT = crc_fmt.pack(crc32(_commit)) + _commit

    HEADER_ID_SIZE = header_fmt.size + 32
    ENTRY_HASH_SIZE = 8

    def __init__(self, path, limit, segments_per_dir, capacity=90):
        self.path = path
        self.fds = LRUCache(capacity, dispose=self._close_fd)
        self.segment = 0
        self.limit = limit
        self.segments_per_dir = segments_per_dir
        self.offset = 0
        self._write_fd = None
        self._fds_cleaned = 0

    def close(self):
        self.close_segment()
        self.fds.clear()
        self.fds = None  # Just to make sure we're disabled

    def _close_fd(self, ts_fd):
        ts, fd = ts_fd
        safe_fadvise(fd.fileno(), 0, 0, "DONTNEED")
        fd.close()

    def segment_iterator(self, start_segment=None, end_segment=None, reverse=False):
        if start_segment is None:
            start_segment = 0 if not reverse else 2**32 - 1
        if end_segment is None:
            end_segment = 2**32 - 1 if not reverse else 0
        data_path = os.path.join(self.path, "data")
        start_segment_dir = start_segment // self.segments_per_dir
        end_segment_dir = end_segment // self.segments_per_dir
        dirs = os.listdir(data_path)
        if not reverse:
            dirs = [dir for dir in dirs if dir.isdigit() and start_segment_dir <= int(dir) <= end_segment_dir]
        else:
            dirs = [dir for dir in dirs if dir.isdigit() and start_segment_dir >= int(dir) >= end_segment_dir]
        dirs = sorted(dirs, key=int, reverse=reverse)
        for dir in dirs:
            filenames = os.listdir(os.path.join(data_path, dir))
            if not reverse:
                filenames = [
                    filename
                    for filename in filenames
                    if filename.isdigit() and start_segment <= int(filename) <= end_segment
                ]
            else:
                filenames = [
                    filename
                    for filename in filenames
                    if filename.isdigit() and start_segment >= int(filename) >= end_segment
                ]
            filenames = sorted(filenames, key=int, reverse=reverse)
            for filename in filenames:
                # Note: Do not filter out logically deleted segments  (see "File system interaction" above),
                # since this is used by cleanup and txn state detection as well.
                yield int(filename), os.path.join(data_path, dir, filename)

    def get_latest_segment(self):
        for segment, filename in self.segment_iterator(reverse=True):
            return segment
        return None

    def get_segments_transaction_id(self):
        """Return the last committed segment."""
        for segment, filename in self.segment_iterator(reverse=True):
            if self.is_committed_segment(segment):
                return segment
        return None

    def cleanup(self, transaction_id):
        """Delete segment files left by aborted transactions"""
        self.segment = transaction_id + 1
        count = 0
        for segment, filename in self.segment_iterator(reverse=True):
            if segment > transaction_id:
                if segment in self.fds:
                    del self.fds[segment]
                safe_unlink(filename)
                count += 1
            else:
                break
        logger.debug("Cleaned up %d uncommitted segment files (== everything after segment %d).", count, transaction_id)

    def is_committed_segment(self, segment):
        """Check if segment ends with a COMMIT_TAG tag"""
        try:
            iterator = self.iter_objects(segment)
        except IntegrityError:
            return False
        with open(self.segment_filename(segment), "rb") as fd:
            try:
                fd.seek(-self.header_fmt.size, os.SEEK_END)
            except OSError as e:
                # return False if segment file is empty or too small
                if e.errno == errno.EINVAL:
                    return False
                raise e
            if fd.read(self.header_fmt.size) != self.COMMIT:
                return False
        seen_commit = False
        while True:
            try:
                tag, key, offset, _, _ = next(iterator)
            except IntegrityError:
                return False
            except StopIteration:
                break
            if tag == TAG_COMMIT:
                seen_commit = True
                continue
            if seen_commit:
                return False
        return seen_commit

    def segment_filename(self, segment):
        return os.path.join(self.path, "data", str(segment // self.segments_per_dir), str(segment))

    def get_write_fd(self, no_new=False, want_new=False, raise_full=False):
        if not no_new and (want_new or self.offset and self.offset > self.limit):
            if raise_full:
                raise self.SegmentFull
            self.close_segment()
        if not self._write_fd:
            if self.segment % self.segments_per_dir == 0:
                dirname = os.path.join(self.path, "data", str(self.segment // self.segments_per_dir))
                if not os.path.exists(dirname):
                    os.mkdir(dirname)
                    sync_dir(os.path.join(self.path, "data"))
            self._write_fd = SyncFile(self.segment_filename(self.segment), binary=True)
            self._write_fd.write(MAGIC)
            self.offset = MAGIC_LEN
            if self.segment in self.fds:
                # we may have a cached fd for a segment file we already deleted and
                # we are writing now a new segment file to same file name. get rid of
                # the cached fd that still refers to the old file, so it will later
                # get repopulated (on demand) with a fd that refers to the new file.
                del self.fds[self.segment]
        return self._write_fd

    def get_fd(self, segment):
        # note: get_fd() returns a fd with undefined file pointer position,
        # so callers must always seek() to desired position afterwards.
        now = time.monotonic()

        def open_fd():
            fd = open(self.segment_filename(segment), "rb")
            self.fds[segment] = (now, fd)
            return fd

        def clean_old():
            # we regularly get rid of all old FDs here:
            if now - self._fds_cleaned > FD_MAX_AGE // 8:
                self._fds_cleaned = now
                for k, ts_fd in list(self.fds.items()):
                    ts, fd = ts_fd
                    if now - ts > FD_MAX_AGE:
                        # we do not want to touch long-unused file handles to
                        # avoid ESTALE issues (e.g. on network filesystems).
                        del self.fds[k]

        clean_old()
        if self._write_fd is not None:
            # without this, we have a test failure now
            self._write_fd.sync()
        try:
            ts, fd = self.fds[segment]
        except KeyError:
            fd = open_fd()
        else:
            # we only have fresh enough stuff here.
            # update the timestamp of the lru cache entry.
            self.fds.upd(segment, (now, fd))
        return fd

    def close_segment(self):
        # set self._write_fd to None early to guard against reentry from error handling code paths:
        fd, self._write_fd = self._write_fd, None
        if fd is not None:
            self.segment += 1
            self.offset = 0
            fd.close()

    def delete_segment(self, segment):
        if segment in self.fds:
            del self.fds[segment]
        try:
            safe_unlink(self.segment_filename(segment))
        except FileNotFoundError:
            pass

    def segment_exists(self, segment):
        filename = self.segment_filename(segment)
        # When deleting segments, they are first truncated. If truncate(2) and unlink(2) are split
        # across FS transactions, then logically deleted segments will show up as truncated.
        return os.path.exists(filename) and os.path.getsize(filename)

    def segment_size(self, segment):
        return os.path.getsize(self.segment_filename(segment))

    def get_segment_magic(self, segment):
        fd = self.get_fd(segment)
        fd.seek(0)
        return fd.read(MAGIC_LEN)

    def iter_objects(self, segment, offset=0, read_data=True):
        """
        Return object iterator for *segment*.

        See the _read() docstring about confidence in the returned data.

        The iterator returns five-tuples of (tag, key, offset, size, data).
        """
        fd = self.get_fd(segment)
        fd.seek(offset)
        if offset == 0:
            # we are touching this segment for the first time, check the MAGIC.
            # Repository.scan() calls us with segment > 0 when it continues an ongoing iteration
            # from a marker position - but then we have checked the magic before already.
            if fd.read(MAGIC_LEN) != MAGIC:
                raise IntegrityError(f"Invalid segment magic [segment {segment}, offset {0}]")
            offset = MAGIC_LEN
        header = fd.read(self.header_fmt.size)
        while header:
            size, tag, key, data = self._read(
                fd, header, segment, offset, (TAG_PUT2, TAG_DELETE, TAG_COMMIT, TAG_PUT), read_data=read_data
            )
            # tuple[3]: corresponds to len(data) == length of the full chunk payload (meta_len+enc_meta+enc_data)
            # tuple[4]: data will be None if read_data is False.
            yield tag, key, offset, size - header_size(tag), data
            assert size >= 0
            offset += size
            # we must get the fd via get_fd() here again as we yielded to our caller and it might
            # have triggered closing of the fd we had before (e.g. by calling io.read() for
            # different segment(s)).
            # by calling get_fd() here again we also make our fd "recently used" so it likely
            # does not get kicked out of self.fds LRUcache.
            fd = self.get_fd(segment)
            fd.seek(offset)
            header = fd.read(self.header_fmt.size)

    def recover_segment(self, segment, filename):
        logger.info("Attempting to recover " + filename)
        if segment in self.fds:
            del self.fds[segment]
        if os.path.getsize(filename) < MAGIC_LEN + self.header_fmt.size:
            # this is either a zero-byte file (which would crash mmap() below) or otherwise
            # just too small to be a valid non-empty segment file, so do a shortcut here:
            with SaveFile(filename, binary=True) as fd:
                fd.write(MAGIC)
            return
        with SaveFile(filename, binary=True) as dst_fd:
            with open(filename, "rb") as src_fd:
                # note: file must not be 0 size or mmap() will crash.
                with mmap.mmap(src_fd.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    # memoryview context manager is problematic, see https://bugs.python.org/issue35686
                    data = memoryview(mm)
                    d = data
                    try:
                        dst_fd.write(MAGIC)
                        while len(d) >= self.header_fmt.size:
                            crc, size, tag = self.header_fmt.unpack(d[: self.header_fmt.size])
                            size_invalid = size > MAX_OBJECT_SIZE or size < self.header_fmt.size or size > len(d)
                            if size_invalid or tag > MAX_TAG_ID:
                                d = d[1:]
                                continue
                            if tag == TAG_PUT2:
                                c_offset = self.HEADER_ID_SIZE + self.ENTRY_HASH_SIZE
                                # skip if header is invalid
                                if crc32(d[4:c_offset]) & 0xFFFFFFFF != crc:
                                    d = d[1:]
                                    continue
                                # skip if content is invalid
                                if (
                                    self.entry_hash(d[4 : self.HEADER_ID_SIZE], d[c_offset:size])
                                    != d[self.HEADER_ID_SIZE : c_offset]
                                ):
                                    d = d[1:]
                                    continue
                            elif tag in (TAG_DELETE, TAG_COMMIT, TAG_PUT):
                                if crc32(d[4:size]) & 0xFFFFFFFF != crc:
                                    d = d[1:]
                                    continue
                            else:  # tag unknown
                                d = d[1:]
                                continue
                            dst_fd.write(d[:size])
                            d = d[size:]
                    finally:
                        del d
                        data.release()

    def entry_hash(self, *data):
        h = StreamingXXH64()
        for d in data:
            h.update(d)
        return h.digest()

    def read(self, segment, offset, id, *, read_data=True, expected_size=None):
        """
        Read entry from *segment* at *offset* with *id*.

        See the _read() docstring about confidence in the returned data.
        """
        if segment == self.segment and self._write_fd:
            self._write_fd.sync()
        fd = self.get_fd(segment)
        fd.seek(offset)
        header = fd.read(self.header_fmt.size)
        size, tag, key, data = self._read(fd, header, segment, offset, (TAG_PUT2, TAG_PUT), read_data=read_data)
        if id != key:
            raise IntegrityError(
                "Invalid segment entry header, is not for wanted id [segment {}, offset {}]".format(segment, offset)
            )
        data_size_from_header = size - header_size(tag)
        if expected_size is not None and expected_size != data_size_from_header:
            raise IntegrityError(
                f"size from repository index: {expected_size} != " f"size from entry header: {data_size_from_header}"
            )
        return data

    def _read(self, fd, header, segment, offset, acceptable_tags, read_data=True):
        """
        Code shared by read() and iter_objects().

        Confidence in returned data:
        PUT2 tags, read_data == True: crc32 check (header) plus digest check (header+data)
        PUT2 tags, read_data == False: crc32 check (header)
        PUT tags, read_data == True: crc32 check (header+data)
        PUT tags, read_data == False: crc32 check can not be done, all data obtained must be considered informational

        read_data == False behaviour:
        PUT2 tags: return enough of the chunk so that the client is able to decrypt the metadata,
                   do not read, but just seek over the data.
        PUT tags:  return None and just seek over the data.
        """

        def check_crc32(wanted, header, *data):
            result = crc32(memoryview(header)[4:])  # skip first 32 bits of the header, they contain the crc.
            for d in data:
                result = crc32(d, result)
            if result & 0xFFFFFFFF != wanted:
                raise IntegrityError(f"Segment entry header checksum mismatch [segment {segment}, offset {offset}]")

        # See comment on MAX_TAG_ID for details
        assert max(acceptable_tags) <= MAX_TAG_ID, "Exceeding MAX_TAG_ID will break backwards compatibility"
        key = data = None
        fmt = self.header_fmt
        try:
            hdr_tuple = fmt.unpack(header)
        except struct.error as err:
            raise IntegrityError(f"Invalid segment entry header [segment {segment}, offset {offset}]: {err}") from None
        crc, size, tag = hdr_tuple
        length = size - fmt.size  # we already read the header
        if size > MAX_OBJECT_SIZE:
            # if you get this on an archive made with borg < 1.0.7 and millions of files and
            # you need to restore it, you can disable this check by using "if False:" above.
            raise IntegrityError(f"Invalid segment entry size {size} - too big [segment {segment}, offset {offset}]")
        if size < fmt.size:
            raise IntegrityError(f"Invalid segment entry size {size} - too small [segment {segment}, offset {offset}]")
        if tag not in (TAG_PUT2, TAG_DELETE, TAG_COMMIT, TAG_PUT):
            raise IntegrityError(
                f"Invalid segment entry header, did not get a known tag " f"[segment {segment}, offset {offset}]"
            )
        if tag not in acceptable_tags:
            raise IntegrityError(
                f"Invalid segment entry header, did not get acceptable tag " f"[segment {segment}, offset {offset}]"
            )
        if tag == TAG_COMMIT:
            check_crc32(crc, header)
            # that's all for COMMITs.
        else:
            # all other tags (TAG_PUT2, TAG_DELETE, TAG_PUT) have a key
            key = fd.read(32)
            length -= 32
            if len(key) != 32:
                raise IntegrityError(
                    f"Segment entry key short read [segment {segment}, offset {offset}]: "
                    f"expected {32}, got {len(key)} bytes"
                )
            if tag == TAG_DELETE:
                check_crc32(crc, header, key)
                # that's all for DELETEs.
            else:
                # TAG_PUT: we can not do a crc32 header check here, because the crc32 is computed over header+data!
                #          for the check, see code below when read_data is True.
                if tag == TAG_PUT2:
                    entry_hash = fd.read(self.ENTRY_HASH_SIZE)
                    length -= self.ENTRY_HASH_SIZE
                    if len(entry_hash) != self.ENTRY_HASH_SIZE:
                        raise IntegrityError(
                            f"Segment entry hash short read [segment {segment}, offset {offset}]: "
                            f"expected {self.ENTRY_HASH_SIZE}, got {len(entry_hash)} bytes"
                        )
                    check_crc32(crc, header, key, entry_hash)
                if not read_data:
                    if tag == TAG_PUT2:
                        # PUT2 is only used in new repos and they also have different RepoObj layout,
                        # supporting separately encrypted metadata and data.
                        # In this case, we return enough bytes so the client can decrypt the metadata
                        # and seek over the rest (over the encrypted data).
                        meta_len_size = RepoObj.meta_len_hdr.size
                        meta_len = fd.read(meta_len_size)
                        length -= meta_len_size
                        if len(meta_len) != meta_len_size:
                            raise IntegrityError(
                                f"Segment entry meta length short read [segment {segment}, offset {offset}]: "
                                f"expected {meta_len_size}, got {len(meta_len)} bytes"
                            )
                        ml = RepoObj.meta_len_hdr.unpack(meta_len)[0]
                        meta = fd.read(ml)
                        length -= ml
                        if len(meta) != ml:
                            raise IntegrityError(
                                f"Segment entry meta short read [segment {segment}, offset {offset}]: "
                                f"expected {ml}, got {len(meta)} bytes"
                            )
                        data = meta_len + meta  # shortened chunk - enough so the client can decrypt the metadata
                        # we do not have a checksum for this data, but the client's AEAD crypto will check it.
                    # in any case, we see over the remainder of the chunk
                    oldpos = fd.tell()
                    seeked = fd.seek(length, os.SEEK_CUR) - oldpos
                    if seeked != length:
                        raise IntegrityError(
                            f"Segment entry data short seek [segment {segment}, offset {offset}]: "
                            f"expected {length}, got {seeked} bytes"
                        )
                else:  # read data!
                    data = fd.read(length)
                    if len(data) != length:
                        raise IntegrityError(
                            f"Segment entry data short read [segment {segment}, offset {offset}]: "
                            f"expected {length}, got {len(data)} bytes"
                        )
                    if tag == TAG_PUT2:
                        if self.entry_hash(memoryview(header)[4:], key, data) != entry_hash:
                            raise IntegrityError(f"Segment entry hash mismatch [segment {segment}, offset {offset}]")
                    elif tag == TAG_PUT:
                        check_crc32(crc, header, key, data)
        return size, tag, key, data

    def write_put(self, id, data, raise_full=False):
        data_size = len(data)
        if data_size > MAX_DATA_SIZE:
            # this would push the segment entry size beyond MAX_OBJECT_SIZE.
            raise IntegrityError(f"More than allowed put data [{data_size} > {MAX_DATA_SIZE}]")
        fd = self.get_write_fd(want_new=(id == Manifest.MANIFEST_ID), raise_full=raise_full)
        size = data_size + self.HEADER_ID_SIZE + self.ENTRY_HASH_SIZE
        offset = self.offset
        header = self.header_no_crc_fmt.pack(size, TAG_PUT2)
        entry_hash = self.entry_hash(header, id, data)
        crc = self.crc_fmt.pack(crc32(entry_hash, crc32(id, crc32(header))) & 0xFFFFFFFF)
        fd.write(b"".join((crc, header, id, entry_hash)))
        fd.write(data)
        self.offset += size
        return self.segment, offset

    def write_delete(self, id, raise_full=False):
        fd = self.get_write_fd(want_new=(id == Manifest.MANIFEST_ID), raise_full=raise_full)
        header = self.header_no_crc_fmt.pack(self.HEADER_ID_SIZE, TAG_DELETE)
        crc = self.crc_fmt.pack(crc32(id, crc32(header)) & 0xFFFFFFFF)
        fd.write(b"".join((crc, header, id)))
        self.offset += self.HEADER_ID_SIZE
        return self.segment, self.HEADER_ID_SIZE

    def write_commit(self, intermediate=False):
        # Intermediate commits go directly into the current segment - this makes checking their validity more
        # expensive, but is faster and reduces clobber. Final commits go into a new segment.
        fd = self.get_write_fd(want_new=not intermediate, no_new=intermediate)
        if intermediate:
            fd.sync()
        header = self.header_no_crc_fmt.pack(self.header_fmt.size, TAG_COMMIT)
        crc = self.crc_fmt.pack(crc32(header) & 0xFFFFFFFF)
        fd.write(b"".join((crc, header)))
        self.close_segment()
        return self.segment - 1  # close_segment() increments it


assert LoggedIO.HEADER_ID_SIZE + LoggedIO.ENTRY_HASH_SIZE == 41 + 8  # see constants.MAX_OBJECT_SIZE

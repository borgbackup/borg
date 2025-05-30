import os
import time

from borgstore.store import Store
from borgstore.store import ObjectNotFound as StoreObjectNotFound
from borgstore.backends.errors import BackendError as StoreBackendError
from borgstore.backends.errors import BackendDoesNotExist as StoreBackendDoesNotExist
from borgstore.backends.errors import BackendAlreadyExists as StoreBackendAlreadyExists

from .checksums import xxh64
from .constants import *  # NOQA
from .hashindex import ChunkIndex, ChunkIndexEntry
from .helpers import Error, ErrorWithTraceback, IntegrityError
from .helpers import Location
from .helpers import bin_to_hex, hex_to_bin
from .storelocking import Lock
from .logger import create_logger
from .manifest import NoManifestError
from .repoobj import RepoObj

logger = create_logger(__name__)


def repo_lister(repository, *, limit=None):
    marker = None
    finished = False
    while not finished:
        result = repository.list(limit=limit, marker=marker)
        finished = (len(result) < limit) if limit is not None else (len(result) == 0)
        if not finished:
            marker = result[-1][0]
        yield from result


class Repository:
    """borgstore based key value store"""

    class AlreadyExists(Error):
        """A repository already exists at {}."""

        exit_mcode = 10

    class CheckNeeded(ErrorWithTraceback):
        """Inconsistency detected. Please run "borg check {}"."""

        exit_mcode = 12

    class DoesNotExist(Error):
        """Repository {} does not exist."""

        exit_mcode = 13

    class InsufficientFreeSpaceError(Error):
        """Insufficient free space to complete transaction (required: {}, available: {})."""

        exit_mcode = 14

    class InvalidRepository(Error):
        """{} is not a valid repository. Check repo config."""

        exit_mcode = 15

    class InvalidRepositoryConfig(Error):
        """{} does not have a valid configuration. Check repo config [{}]."""

        exit_mcode = 16

    class ObjectNotFound(ErrorWithTraceback):
        """Object with key {} not found in repository {}."""

        exit_mcode = 17

        def __init__(self, id, repo):
            if isinstance(id, bytes):
                id = bin_to_hex(id)
            super().__init__(id, repo)

    class ParentPathDoesNotExist(Error):
        """The parent path of the repo directory [{}] does not exist."""

        exit_mcode = 18

    class PathAlreadyExists(Error):
        """There is already something at {}."""

        exit_mcode = 19

    # StorageQuotaExceeded was exit_mcode = 20

    class PathPermissionDenied(Error):
        """Permission denied to {}."""

        exit_mcode = 21

    def __init__(
        self,
        path_or_location,
        create=False,
        exclusive=False,
        lock_wait=1.0,
        lock=True,
        send_log_cb=None,
        permissions=None,
    ):
        if isinstance(path_or_location, Location):
            location = path_or_location
            if location.proto == "file":
                url = f"file://{location.path}"  # frequently users give without file:// prefix
            else:
                url = location.processed  # location as given by user, processed placeholders
        else:
            url = "file://%s" % os.path.abspath(path_or_location)
            location = Location(url)
        self._location = location
        self.url = url
        # lots of stuff in data: use 2 levels by default (data/00/00/ .. data/ff/ff/ dirs)!
        data_levels = int(os.environ.get("BORG_STORE_DATA_LEVELS", "2"))
        levels_config = {
            "archives/": [0],
            "cache/": [0],
            "config/": [0],
            "data/": [data_levels],
            "keys/": [0],
            "locks/": [0],
        }
        # Get permissions from parameter or environment variable
        permissions = permissions if permissions is not None else os.environ.get("BORG_REPO_PERMISSIONS", "all")

        if permissions == "all":
            permissions = None  # permissions system will not be used
        elif permissions == "no-delete":  # mostly no delete, no overwrite
            permissions = {
                "": "lr",
                "archives": "lrw",
                "cache": "lrwWD",  # WD for chunks.<HASH>, last-key-checked, ...
                "config": "lrW",  # W for manifest
                "data": "lrw",
                "keys": "lr",
                "locks": "lrwD",  # borg needs to create/delete a shared lock here
            }
        elif permissions == "write-only":  # mostly no reading
            permissions = {
                "": "l",
                "archives": "lw",
                "cache": "lrwWD",  # read allowed, e.g. for chunks.<HASH> cache
                "config": "lrW",  # W for manifest
                "data": "lw",  # no r!
                "keys": "lr",
                "locks": "lrwD",  # borg needs to create/delete a shared lock here
            }
        elif permissions == "read-only":  # mostly r/o
            permissions = {"": "lr", "locks": "lrwD"}
        else:
            raise Error(
                f"Invalid BORG_REPO_PERMISSIONS value: {permissions}, should be one of: "
                f"all, no-delete, write-only, read-only."
            )

        try:
            self.store = Store(url, levels=levels_config, permissions=permissions)
        except StoreBackendError as e:
            raise Error(str(e))
        self.store_opened = False
        self.version = None
        # long-running repository methods which emit log or progress output are responsible for calling
        # the ._send_log method periodically to get log and progress output transferred to the borg client
        # in a timely manner, in case we have a RemoteRepository.
        # for local repositories ._send_log can be called also (it will just do nothing in that case).
        self._send_log = send_log_cb or (lambda: None)
        self.do_create = create
        self.created = False
        self.acceptable_repo_versions = (3,)
        self.opened = False
        self.lock = None
        self.do_lock = lock
        self.lock_wait = lock_wait
        self.exclusive = exclusive

    def __repr__(self):
        return f"<{self.__class__.__name__} {self._location}>"

    def __enter__(self):
        if self.do_create:
            self.do_create = False
            self.create()
            self.created = True
        try:
            self.open(exclusive=bool(self.exclusive), lock_wait=self.lock_wait, lock=self.do_lock)
        except Exception:
            self.close()
            raise
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @property
    def id_str(self):
        return bin_to_hex(self.id)

    def create(self):
        """Create a new empty repository"""
        try:
            self.store.create()
        except StoreBackendAlreadyExists:
            raise self.AlreadyExists(self.url)
        self.store.open()
        try:
            self.store.store("config/readme", REPOSITORY_README.encode())
            self.version = 3
            self.store.store("config/version", str(self.version).encode())
            self.store.store("config/id", bin_to_hex(os.urandom(32)).encode())
            # we know repo/data/ still does not have any chunks stored in it,
            # but for some stores, there might be a lot of empty directories and
            # listing them all might be rather slow, so we better cache an empty
            # ChunkIndex from here so that the first repo operation does not have
            # to build the ChunkIndex the slow way by listing all the directories.
            from borg.cache import write_chunkindex_to_repo_cache

            write_chunkindex_to_repo_cache(self, ChunkIndex(), clear=True, force_write=True)
        finally:
            self.store.close()

    def _set_id(self, id):
        # for testing: change the id of an existing repository
        assert self.opened
        assert isinstance(id, bytes) and len(id) == 32
        self.id = id
        self.store.store("config/id", bin_to_hex(id).encode())

    def _lock_refresh(self):
        if self.lock is not None:
            self.lock.refresh()

    def save_key(self, keydata):
        # note: saving an empty key means that there is no repokey anymore
        self.store.store("keys/repokey", keydata)

    def load_key(self):
        keydata = self.store.load("keys/repokey")
        # note: if we return an empty string, it means there is no repo key
        return keydata

    def destroy(self):
        """Destroy the repository"""
        self.close()
        self.store.destroy()

    def open(self, *, exclusive, lock_wait=None, lock=True):
        assert lock_wait is not None
        try:
            self.store.open()
        except StoreBackendDoesNotExist:
            raise self.DoesNotExist(str(self._location)) from None
        else:
            self.store_opened = True
        try:
            readme = self.store.load("config/readme").decode()
        except StoreObjectNotFound:
            raise self.DoesNotExist(str(self._location)) from None
        if readme != REPOSITORY_README:
            raise self.InvalidRepository(str(self._location))
        self.version = int(self.store.load("config/version").decode())
        if self.version not in self.acceptable_repo_versions:
            self.close()
            raise self.InvalidRepositoryConfig(
                str(self._location), "repository version %d is not supported by this borg version" % self.version
            )
        self.id = hex_to_bin(self.store.load("config/id").decode(), length=32)
        # important: lock *after* making sure that there actually is an existing, supported repository.
        if lock:
            self.lock = Lock(self.store, exclusive, timeout=lock_wait).acquire()
        self.opened = True

    def close(self):
        if self.lock:
            self.lock.release()
            self.lock = None
        if self.store_opened:
            self.store.close()
            self.store_opened = False
        self.opened = False

    def info(self):
        """return some infos about the repo (must be opened first)"""
        # note: don't do anything expensive here or separate the lock refresh into a separate method.
        self._lock_refresh()  # do not remove, see do_with_lock()
        info = dict(id=self.id, version=self.version)
        return info

    def check(self, repair=False, max_duration=0):
        """Check repository consistency"""

        def log_error(msg):
            nonlocal obj_corrupted
            obj_corrupted = True
            logger.error(f"Repo object {info.name} is corrupted: {msg}")

        def check_object(obj):
            """Check if obj looks valid."""
            hdr_size = RepoObj.obj_header.size
            obj_size = len(obj)
            if obj_size >= hdr_size:
                hdr = RepoObj.ObjHeader(*RepoObj.obj_header.unpack(obj[:hdr_size]))
                meta = obj[hdr_size : hdr_size + hdr.meta_size]
                if hdr.meta_size != len(meta):
                    log_error("metadata size incorrect.")
                elif hdr.meta_hash != xxh64(meta):
                    log_error("metadata does not match checksum.")
                data = obj[hdr_size + hdr.meta_size : hdr_size + hdr.meta_size + hdr.data_size]
                if hdr.data_size != len(data):
                    log_error("data size incorrect.")
                elif hdr.data_hash != xxh64(data):
                    log_error("data does not match checksum.")
            else:
                log_error("too small.")

        # TODO: progress indicator, ...
        partial = bool(max_duration)
        assert not (repair and partial)
        mode = "partial" if partial else "full"
        LAST_KEY_CHECKED = "cache/last-key-checked"
        logger.info(f"Starting {mode} repository check")
        if partial:
            # continue a past partial check (if any) or from a checkpoint or start one from beginning
            try:
                last_key_checked = self.store.load(LAST_KEY_CHECKED).decode()
            except StoreObjectNotFound:
                last_key_checked = ""
        else:
            # start from the beginning and also forget about any potential past partial checks
            last_key_checked = ""
            try:
                self.store.delete(LAST_KEY_CHECKED)
            except StoreObjectNotFound:
                pass
        if last_key_checked:
            logger.info(f"Skipping to keys after {last_key_checked}.")
        else:
            logger.info("Starting from beginning.")
        t_start = time.monotonic()
        t_last_checkpoint = t_start
        objs_checked = objs_errors = 0
        chunks = ChunkIndex()
        # we don't do refcounting anymore, neither we can know here whether any archive
        # is using this object, but we assume that this is the case.
        # As we don't do garbage collection here, this is not a problem.
        # We also don't know the plaintext size, so we set it to 0.
        init_entry = ChunkIndexEntry(flags=ChunkIndex.F_USED, size=0)
        infos = self.store.list("data")
        try:
            for info in infos:
                self._lock_refresh()
                key = "data/%s" % info.name
                if key <= last_key_checked:  # needs sorted keys
                    continue
                try:
                    obj = self.store.load(key)
                except StoreObjectNotFound:
                    # looks like object vanished since store.list(), ignore that.
                    continue
                obj_corrupted = False
                check_object(obj)
                objs_checked += 1
                if obj_corrupted:
                    objs_errors += 1
                    if repair:
                        # if it is corrupted, we can't do much except getting rid of it.
                        # but let's just retry loading it, in case the error goes away.
                        try:
                            obj = self.store.load(key)
                        except StoreObjectNotFound:
                            log_error("existing object vanished.")
                        else:
                            obj_corrupted = False
                            check_object(obj)
                            if obj_corrupted:
                                log_error("reloading did not help, deleting it!")
                                self.store.delete(key)
                            else:
                                log_error("reloading did help, inconsistent behaviour detected!")
                if not (obj_corrupted and repair):
                    # add all existing objects to the index.
                    # borg check: the index may have corrupted objects (we did not delete them)
                    # borg check --repair: the index will only have non-corrupted objects.
                    id = hex_to_bin(info.name)
                    chunks[id] = init_entry
                now = time.monotonic()
                if now > t_last_checkpoint + 300:  # checkpoint every 5 mins
                    t_last_checkpoint = now
                    logger.info(f"Checkpointing at key {key}.")
                    self.store.store(LAST_KEY_CHECKED, key.encode())
                if partial and now > t_start + max_duration:
                    logger.info(f"Finished partial repository check, last key checked is {key}.")
                    self.store.store(LAST_KEY_CHECKED, key.encode())
                    break
            else:
                logger.info("Finished repository check.")
                try:
                    self.store.delete(LAST_KEY_CHECKED)
                except StoreObjectNotFound:
                    pass
                if not partial:
                    # if we did a full pass in one go, we built a complete, uptodate ChunkIndex, cache it!
                    from .cache import write_chunkindex_to_repo_cache

                    write_chunkindex_to_repo_cache(
                        self, chunks, incremental=False, clear=True, force_write=True, delete_other=True
                    )
        except StoreObjectNotFound:
            # it can be that there is no "data/" at all, then it crashes when iterating infos.
            pass
        logger.info(f"Checked {objs_checked} repository objects, {objs_errors} errors.")
        if objs_errors == 0:
            logger.info(f"Finished {mode} repository check, no problems found.")
        else:
            if repair:
                logger.info(f"Finished {mode} repository check, errors found and repaired.")
            else:
                logger.error(f"Finished {mode} repository check, errors found.")
        return objs_errors == 0 or repair

    def list(self, limit=None, marker=None):
        """
        list <limit> infos starting from after id <marker>.
        each info is a tuple (id, storage_size).
        """
        collect = True if marker is None else False
        result = []
        infos = self.store.list("data")  # generator yielding ItemInfos
        while True:
            self._lock_refresh()
            try:
                info = next(infos)
            except StoreObjectNotFound:
                break  # can happen e.g. if "data" does not exist, pointless to continue in that case
            except StopIteration:
                break
            else:
                id = hex_to_bin(info.name)
                if collect:
                    result.append((id, info.size))
                    if len(result) == limit:
                        break
                elif id == marker:
                    collect = True
                    # note: do not collect the marker id
        return result

    def get(self, id, read_data=True, raise_missing=True):
        self._lock_refresh()
        id_hex = bin_to_hex(id)
        key = "data/" + id_hex
        try:
            if read_data:
                # read everything
                return self.store.load(key)
            else:
                # RepoObj layout supports separately encrypted metadata and data.
                # We return enough bytes so the client can decrypt the metadata.
                hdr_size = RepoObj.obj_header.size
                extra_size = 1024 - hdr_size  # load a bit more, 1024b, reduces round trips
                obj = self.store.load(key, size=hdr_size + extra_size)
                hdr = obj[0:hdr_size]
                if len(hdr) != hdr_size:
                    raise IntegrityError(f"Object too small [id {id_hex}]: expected {hdr_size}, got {len(hdr)} bytes")
                meta_size = RepoObj.obj_header.unpack(hdr)[0]
                if meta_size > extra_size:
                    # we did not get enough, need to load more, but not all.
                    # this should be rare, as chunk metadata is rather small usually.
                    obj = self.store.load(key, size=hdr_size + meta_size)
                meta = obj[hdr_size : hdr_size + meta_size]
                if len(meta) != meta_size:
                    raise IntegrityError(f"Object too small [id {id_hex}]: expected {meta_size}, got {len(meta)} bytes")
                return hdr + meta
        except StoreObjectNotFound:
            if raise_missing:
                raise self.ObjectNotFound(id, str(self._location)) from None
            else:
                return None

    def get_many(self, ids, read_data=True, is_preloaded=False, raise_missing=True):
        for id_ in ids:
            yield self.get(id_, read_data=read_data, raise_missing=raise_missing)

    def put(self, id, data, wait=True):
        """put a repo object

        Note: when doing calls with wait=False this gets async and caller must
              deal with async results / exceptions later.
        """
        self._lock_refresh()
        data_size = len(data)
        if data_size > MAX_DATA_SIZE:
            raise IntegrityError(f"More than allowed put data [{data_size} > {MAX_DATA_SIZE}]")

        key = "data/" + bin_to_hex(id)
        self.store.store(key, data)

    def delete(self, id, wait=True):
        """delete a repo object

        Note: when doing calls with wait=False this gets async and caller must
              deal with async results / exceptions later.
        """
        self._lock_refresh()
        key = "data/" + bin_to_hex(id)
        try:
            self.store.delete(key)
        except StoreObjectNotFound:
            raise self.ObjectNotFound(id, str(self._location)) from None

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

    def break_lock(self):
        Lock(self.store).break_lock()

    def migrate_lock(self, old_id, new_id):
        # note: only needed for local repos
        if self.lock is not None:
            self.lock.migrate_lock(old_id, new_id)

    def get_manifest(self):
        self._lock_refresh()
        try:
            return self.store.load("config/manifest")
        except StoreObjectNotFound:
            raise NoManifestError

    def put_manifest(self, data):
        self._lock_refresh()
        return self.store.store("config/manifest", data)

    def store_list(self, name, *, deleted=False):
        self._lock_refresh()
        try:
            return list(self.store.list(name, deleted=deleted))
        except StoreObjectNotFound:
            return []

    def store_load(self, name):
        self._lock_refresh()
        return self.store.load(name)

    def store_store(self, name, value):
        self._lock_refresh()
        return self.store.store(name, value)

    def store_delete(self, name, *, deleted=False):
        self._lock_refresh()
        return self.store.delete(name, deleted=deleted)

    def store_move(self, name, new_name=None, *, delete=False, undelete=False, deleted=False):
        self._lock_refresh()
        return self.store.move(name, new_name, delete=delete, undelete=undelete, deleted=deleted)

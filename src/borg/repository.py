import os

from borgstore.store import Store
from borgstore.store import ObjectNotFound as StoreObjectNotFound

from .checksums import xxh64
from .constants import *  # NOQA
from .helpers import Error, ErrorWithTraceback, IntegrityError
from .helpers import Location
from .helpers import bin_to_hex, hex_to_bin
from .storelocking import Lock
from .logger import create_logger
from .manifest import NoManifestError
from .repoobj import RepoObj

logger = create_logger(__name__)


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

    class StorageQuotaExceeded(Error):
        """The storage quota ({}) has been exceeded ({}). Try deleting some archives."""

        exit_mcode = 20

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
        append_only=False,
        storage_quota=None,
        make_parent_dirs=False,
        send_log_cb=None,
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
        # use a Store with flat config storage and 2-levels-nested data storage
        self.store = Store(url, levels={"config/": [0], "data/": [2]})
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
        self.append_only = append_only  # XXX not implemented / not implementable
        self.storage_quota = storage_quota  # XXX not implemented
        self.storage_quota_use = 0  # XXX not implemented
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
        self.open(exclusive=bool(self.exclusive), lock_wait=self.lock_wait, lock=self.do_lock)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @property
    def id_str(self):
        return bin_to_hex(self.id)

    def create(self):
        """Create a new empty repository"""
        self.store.create()
        self.store.open()
        self.store.store("config/readme", REPOSITORY_README.encode())
        self.version = 3
        self.store.store("config/version", str(self.version).encode())
        self.store.store("config/id", bin_to_hex(os.urandom(32)).encode())
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
        self.store.open()
        if lock:
            self.lock = Lock(self.store, exclusive, timeout=lock_wait).acquire()
        else:
            self.lock = None
        readme = self.store.load("config/readme").decode()
        if readme != REPOSITORY_README:
            raise self.InvalidRepository(str(self._location))
        self.version = int(self.store.load("config/version").decode())
        if self.version not in self.acceptable_repo_versions:
            self.close()
            raise self.InvalidRepositoryConfig(
                str(self._location), "repository version %d is not supported by this borg version" % self.version
            )
        self.id = hex_to_bin(self.store.load("config/id").decode(), length=32)
        self.opened = True

    def close(self):
        if self.opened:
            if self.lock:
                self.lock.release()
                self.lock = None
            self.store.close()
            self.opened = False

    def info(self):
        """return some infos about the repo (must be opened first)"""
        info = dict(
            id=self.id,
            version=self.version,
            storage_quota_use=self.storage_quota_use,
            storage_quota=self.storage_quota,
            append_only=self.append_only,
        )
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

        # TODO: progress indicator, partial checks, ...
        mode = "full"
        logger.info("Starting repository check")
        objs_checked = objs_errors = 0
        infos = self.store.list("data")
        try:
            for info in infos:
                self._lock_refresh()
                key = "data/%s" % info.name
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
        self._lock_refresh()
        collect = True if marker is None else False
        result = []
        infos = self.store.list("data")  # generator yielding ItemInfos
        while True:
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

    def get(self, id, read_data=True):
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
            raise self.ObjectNotFound(id, str(self._location)) from None

    def get_many(self, ids, read_data=True, is_preloaded=False):
        for id_ in ids:
            yield self.get(id_, read_data=read_data)

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
        try:
            return self.store.load("config/manifest")
        except StoreObjectNotFound:
            raise NoManifestError

    def put_manifest(self, data):
        return self.store.store("config/manifest", data)

    def store_list(self, name):
        try:
            return list(self.store.list(name))
        except StoreObjectNotFound:
            return []

    def store_load(self, name):
        return self.store.load(name)

    def store_store(self, name, value):
        return self.store.store(name, value)

    def store_delete(self, name):
        return self.store.delete(name)

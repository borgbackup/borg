import os
import sys
import time
from pathlib import Path
from hashlib import sha256

from borgstore.store import Store
from borgstore.backends.rest import REST, ssh_cmd
from borgstore.store import ObjectNotFound as StoreObjectNotFound
from borgstore.backends.errors import BackendError as StoreBackendError
from borgstore.backends.errors import BackendDoesNotExist as StoreBackendDoesNotExist
from borgstore.backends.errors import BackendAlreadyExists as StoreBackendAlreadyExists

from .constants import *  # NOQA
from .hashindex import ChunkIndex, ChunkIndexEntry
from .helpers import Error, ErrorWithTraceback, IntegrityError
from .helpers import Location
from .helpers import bin_to_hex, hex_to_bin
from .storelocking import Lock
from .logger import create_logger
from .manifest import NoManifestError
from .repoobj import RepoObj, OBJ_MAGIC, OBJ_VERSION
from .crypto.key import is_keyfile

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


def borg_permissions(permissions):
    """Map a borg permissions string to a borgstore permissions dict (or None for "all").

    The namespaces match the borg repository layout (see Repository.__init__ ns_config).
    """
    if permissions == "all":
        return None  # permissions system will not be used
    elif permissions == "no-delete":  # mostly no delete, no overwrite
        return {
            "": "lr",
            "archives": "lrw",
            "cache": "lrwWD",  # WD for chunks.<HASH>, last-key-checked, ...
            "config": "lrW",  # W for manifest
            "keys": "lr",
            "locks": "lrwD",  # borg needs to create/delete a shared lock here
            "packs": "lrw",
        }
    elif permissions == "write-only":  # mostly no reading
        return {
            "": "l",
            "archives": "lw",
            "cache": "lrwWD",  # read allowed, e.g. for chunks.<HASH> cache
            "config": "lrW",  # W for manifest
            "keys": "lr",
            "locks": "lrwD",  # borg needs to create/delete a shared lock here
            "packs": "lw",  # no r!
        }
    elif permissions == "read-only":  # mostly r/o
        return {"": "lr", "locks": "lrwD"}
    else:
        raise Error(
            f"Invalid BORG_REPO_PERMISSIONS value: {permissions}, should be one of: "
            f"all, no-delete, write-only, read-only."
        )


def rest_serve_command(location):
    """Build the command line that serves a rest:// *location* via "borg serve --rest".

    For a local rest:// (no host) we run this borg directly (over stdio); if a host is
    given, we prefix an ssh command (reusing borgstore's ssh_cmd / BORGSTORE_RSH).
    """
    backend_arg = f"FILE:{location.path}"
    if not location.host:
        # run this borg locally, talking over stdio
        borg_cmd = [sys.executable] if getattr(sys, "frozen", False) else [sys.executable, "-m", "borg"]
        return borg_cmd + ["serve", "--rest", "--backend", backend_arg]
    # reach the remote borg via ssh
    remote_path = os.environ.get("BORG_REMOTE_PATH", "borg")
    return ssh_cmd(location.user, location.host, location.port) + [
        remote_path,
        "serve",
        "--rest",
        "--backend",
        backend_arg,
    ]


def build_rest_backend(location):
    """Return a borgstore REST backend for a rest:// *location*, served by "borg serve --rest"."""
    return REST(base_url="http://stdio-backend", command=rest_serve_command(location))


class PackWriter:
    """Buffers chunks into a pack file and writes to the store when full.

    Collects (chunk_id, cdata) pairs in a list and flushes once max_count is
    reached.  On flush it returns the location info for every chunk so the
    caller can update the ChunkIndex with real values.

    At max_count=1 (N=1 phase) each put() maps exactly one chunk to one pack,
    so pack_id == chunk_id and the naming scheme is unchanged from before.
    Raising max_count later (N>1 phase) enables real packing without touching
    this class's interface.
    """

    def __init__(self, store, *, max_count=1):
        self.store = store
        self.max_count = max_count
        self._pieces = []  # list of (chunk_id, cdata)

    def add(self, chunk_id, cdata):
        """Buffer a chunk.  Returns flush results if the pack is now full, else None."""
        self._pieces.append((chunk_id, cdata))
        if len(self._pieces) >= self.max_count:
            return self.flush()
        return None

    def flush(self):
        """Write the current pack to the store.

        Returns a list of (chunk_id, pack_id, obj_offset, obj_size) tuples —
        one entry per chunk that was written.  Returns None if there was nothing
        to flush.
        """
        if not self._pieces:
            return None

        # Build the pack bytes once by joining all pieces (avoids O(n^2) copies
        # that incremental string concatenation would cause in Python).
        pack_data = b"".join(cdata for _, cdata in self._pieces)

        # Determine pack_id.
        # N=1: the pack contains exactly one chunk, so we keep pack_id == chunk_id
        #      (backward-compatible file naming: packs/{chunk_id_hex}).
        # N>1: the pack contains multiple chunks; use SHA256(pack_bytes) so the
        #      file is content-addressed and borgstore can verify/cache it.
        if self.max_count == 1:
            pack_id = self._pieces[0][0]  # N=1: pack_id == chunk_id
        else:
            pack_id = sha256(pack_data).digest()  # N>1: content-addressed

        # Record (chunk_id, pack_id, obj_offset, obj_size) for every piece.
        results = []
        offset = 0
        for chunk_id, cdata in self._pieces:
            obj_size = len(cdata)
            results.append((chunk_id, pack_id, offset, obj_size))
            offset += obj_size

        key = "packs/" + bin_to_hex(pack_id)
        try:
            self.store.store(key, pack_data)
        finally:
            self._pieces = []  # reset even on failure to prevent re-bundling a failed chunk
        return results


class Repository:
    """borgstore-based key/value store."""

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
        """Insufficient free space to complete the transaction (required: {}, available: {})."""

        exit_mcode = 14

    class InvalidRepository(Error):
        """{} is not a valid repository. Check the repository config."""

        exit_mcode = 15

    class InvalidRepositoryConfig(Error):
        """{} does not have a valid config. Check the repository config [{}]."""

        exit_mcode = 16

    class ObjectNotFound(ErrorWithTraceback):
        """Object with key {} not found in repository {}."""

        exit_mcode = 17

        def __init__(self, id, repo):
            if isinstance(id, bytes):
                id = bin_to_hex(id)
            super().__init__(id, repo)

    class ParentPathDoesNotExist(Error):
        """The parent path of the repository directory [{}] does not exist."""

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
                url = Path(location.path).as_uri()
            else:
                url = location.processed  # location as given by user, processed placeholders
        else:
            url = Path(path_or_location).absolute().as_uri()
            location = Location(url)
        self._location = location
        self.url = url
        ns_config = {
            "archives/": {"levels": [0]},
            "cache/": {"levels": [0]},
            "config/": {"levels": [0]},
            "keys/": {"levels": [0]},
            "locks/": {"levels": [0]},
            "packs/": {"levels": [1]},
        }
        # Get permissions from parameter or environment variable
        permissions = permissions if permissions is not None else os.environ.get("BORG_REPO_PERMISSIONS", "all")
        permissions = borg_permissions(permissions)

        try:
            if location.proto == "rest":
                # rest:// is served by "borg serve --rest" (reachable via ssh if a host is given),
                # talking HTTP over stdio - rather than borgstore's own "borgstore-server-rest" command.
                # permissions are not given to the (remote) backend here; they are enforced on the
                # server side by "borg serve --rest --permissions ...".
                backend = build_rest_backend(location)
                self.store = Store(backend=backend, config=ns_config)
            else:
                self.store = Store(url, config=ns_config, permissions=permissions)
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
        self.acceptable_repo_versions = (4,)
        self.opened = False
        self.lock = None
        self.do_lock = lock
        self.lock_wait = lock_wait
        self.exclusive = exclusive
        self._pack_writer = None
        self._chunks = None  # borrowed ChunkIndex reference, set by set_chunk_index()

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
            self.version = 4
            self.store.store("config/version", str(self.version).encode())
            self.store.store("config/id", bin_to_hex(os.urandom(32)).encode())
            # we know repo/packs/ still does not have any chunks stored in it,
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
        # currently, there is only one repokey,
        # thus we delete all old/outdated keys stored in this repository.
        try:
            infos = list(self.store.list("keys"))
        except StoreObjectNotFound:
            pass
        else:
            for info in infos:
                try:
                    self.store.delete(f"keys/{info.name}")
                except StoreObjectNotFound:
                    pass
        # note: saving an empty key means that there is no repokey for this repo anymore.
        if keydata:
            digest = sha256(keydata).hexdigest()
            self.store.store(f"keys/{digest}", keydata)

    def load_key(self):
        repo_id_hex = bin_to_hex(self.id)
        # search for a key matching this repository's ID in the keys/ namespace
        try:
            infos = list(self.store.list("keys"))
        except StoreObjectNotFound:
            pass
        else:
            for info in infos:
                try:
                    keydata = self.store.load(f"keys/{info.name}")
                    if is_keyfile(keydata, repo_id_hex):
                        return keydata
                except StoreObjectNotFound:
                    pass
        return b""

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
        self._pack_writer = PackWriter(self.store, max_count=1)
        self._chunks = ChunkIndex()
        self.opened = True

    def set_chunk_index(self, chunks):
        """Set the ChunkIndex get() uses to resolve pack locations.

        The caller retains ownership; Repository holds a borrowed reference.
        Pass None to reset to an empty index.
        """
        self._chunks = chunks if chunks is not None else ChunkIndex()

    def flush(self):
        """Flush any buffered pack writer chunks."""
        if self._pack_writer is not None:
            pack_results = self._pack_writer.flush()
            if pack_results:
                self._chunks.update_pack_info(pack_results)

    def close(self):
        if self._pack_writer is not None:
            assert not self._pack_writer._pieces, "PackWriter has unflushed chunks; call flush() before close()"
        if self.lock:
            self.lock.release()
            self.lock = None
        if self.store_opened:
            self.store.close()
            self.store_opened = False
        self._chunks = None
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
            if len(obj) < hdr_size:
                log_error("too small.")
                return
            hdr = RepoObj.ObjHeader(*RepoObj.obj_header.unpack(obj[:hdr_size]))
            if hdr.magic != OBJ_MAGIC:
                log_error("invalid object magic.")
            elif hdr.version != OBJ_VERSION:
                log_error(f"unsupported object version: {hdr.version}.")
            else:
                meta = obj[hdr_size : hdr_size + hdr.meta_size]
                if hdr.meta_size != len(meta):
                    log_error("metadata size mismatch.")
                data = obj[hdr_size + hdr.meta_size : hdr_size + hdr.meta_size + hdr.data_size]
                if hdr.data_size != len(data):
                    log_error("data size mismatch.")

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
        infos = self.store.list("packs")
        try:
            for info in infos:
                self._lock_refresh()
                key = "packs/%s" % info.name
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
                    pack_id = hex_to_bin(info.name)
                    pack_size = info.size
                    chunk_id = pack_id  # N=1: chunk_id == pack_id
                    obj_size = pack_size  # correct for N=1
                    chunks[chunk_id] = ChunkIndexEntry(
                        flags=ChunkIndex.F_USED, size=0, pack_id=pack_id, obj_offset=0, obj_size=obj_size
                    )
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
                    # if we did a full pass in one go, we built a complete, up-to-date ChunkIndex, cache it!
                    from .cache import write_chunkindex_to_repo_cache

                    write_chunkindex_to_repo_cache(
                        self, chunks, incremental=False, clear=True, force_write=True, delete_other=True
                    )
        except StoreObjectNotFound:
            # it can be that there is no "packs/" at all, then it crashes when iterating infos.
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
        infos = self.store.list("packs")  # generator yielding ItemInfos
        while True:
            self._lock_refresh()
            try:
                info = next(infos)
            except StoreObjectNotFound:
                break  # can happen e.g. if "packs" does not exist, pointless to continue in that case
            except StopIteration:
                break
            else:
                pack_id = hex_to_bin(info.name)
                chunk_id = pack_id  # N=1: chunk_id == pack_id
                if collect:
                    chunk_size = info.size  # only correct for N=1
                    result.append((chunk_id, chunk_size))
                    if len(result) == limit:
                        break
                elif chunk_id == marker:
                    collect = True
                    # note: do not collect the marker id
        return result

    def get(self, id, read_data=True, raise_missing=True):
        self._lock_refresh()
        pack_id = id  # N=1 fallback: pack_id == chunk_id
        obj_offset, obj_size = 0, None
        entry = self._chunks.get(id)
        if entry is not None and entry.pack_id != UNKNOWN_BYTES32:  # UNKNOWN: buffered, not yet flushed
            pack_id, obj_offset, obj_size = entry.pack_id, entry.obj_offset, entry.obj_size
        id_hex = bin_to_hex(id)
        key = "packs/" + bin_to_hex(pack_id)
        try:
            if read_data:
                return self.store.load(key, offset=obj_offset, size=obj_size)
            else:
                # RepoObj layout supports separately encrypted metadata and data.
                # We return enough bytes so the client can decrypt the metadata.
                hdr_size = RepoObj.obj_header.size
                extra_size = 1024 - hdr_size  # load a bit more, 1024b, reduces round trips
                load_size = hdr_size + extra_size
                if obj_size is not None:
                    load_size = min(load_size, obj_size)
                obj = self.store.load(key, offset=obj_offset, size=load_size)
                hdr = obj[0:hdr_size]
                if len(hdr) != hdr_size:
                    raise IntegrityError(f"Object too small [id {id_hex}]: expected {hdr_size}, got {len(hdr)} bytes")
                meta_size = RepoObj.ObjHeader(*RepoObj.obj_header.unpack(hdr)).meta_size
                if meta_size > extra_size:
                    # we did not get enough, need to load more, but not all.
                    # this should be rare, as chunk metadata is rather small usually.
                    retry_size = hdr_size + meta_size
                    if obj_size is not None:
                        # normally a no-op (meta_size <= obj_size - hdr_size for a healthy object);
                        # guards against a corrupted meta_size producing an oversize read.
                        retry_size = min(retry_size, obj_size)
                    obj = self.store.load(key, offset=obj_offset, size=retry_size)
                meta = obj[hdr_size : hdr_size + meta_size]
                if len(meta) != meta_size:
                    raise IntegrityError(f"Object too small [id {id_hex}]: expected {meta_size}, got {len(meta)} bytes")
                return hdr + meta
        except StoreObjectNotFound:
            if raise_missing:
                raise self.ObjectNotFound(id, str(self._location)) from None
            else:
                return None

    def get_many(self, ids, read_data=True, raise_missing=True):
        for id_ in ids:
            yield self.get(id_, read_data=read_data, raise_missing=raise_missing)

    def put(self, id, data, wait=True):
        """put a repo object

        Note: when doing calls with wait=False this gets async and caller must
              deal with async results / exceptions later.

        Returns a list of (chunk_id, pack_id, obj_offset, obj_size) tuples for
        every chunk written to disk this call.  At max_count=1 this is always
        one entry.
        """
        self._lock_refresh()
        data_size = len(data)
        if data_size > MAX_DATA_SIZE:
            raise IntegrityError(f"More than allowed put data [{data_size} > {MAX_DATA_SIZE}]")
        return self._pack_writer.add(id, data)

    def delete(self, id, wait=True):
        """delete a repo object

        Note: when doing calls with wait=False this gets async and caller must
              deal with async results / exceptions later.
        """
        self._lock_refresh()
        pack_id = id  # N=1: pack_id == chunk_id
        key = "packs/" + bin_to_hex(pack_id)
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

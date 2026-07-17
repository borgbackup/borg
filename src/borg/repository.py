import io
import os
import sys
import time
from collections import defaultdict, namedtuple
from pathlib import Path
from hashlib import sha256

from borghash import HashTableNT

from borgstore.store import Store
from borgstore.backends.rest import REST, ssh_cmd
from borgstore.store import ObjectNotFound as StoreObjectNotFound, ReadRangeError
from borgstore.backends.errors import BackendError as StoreBackendError
from borgstore.backends.errors import BackendDoesNotExist as StoreBackendDoesNotExist
from borgstore.backends.errors import BackendAlreadyExists as StoreBackendAlreadyExists

from .constants import *  # NOQA
from .hashindex import ChunkIndex
from .helpers import Error, ErrorWithTraceback, IntegrityError
from .helpers import Location
from .helpers import bin_to_hex, hex_to_bin
from .helpers import get_cache_dir
from .helpers import sig_int
from .helpers import ProgressIndicatorPercent
from .helpers.lrucache import LRUCache
from .storelocking import Lock
from .logger import create_logger
from .manifest import NoManifestError
from .repoobj import RepoObj, OBJ_MAGIC
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
    match permissions:
        case "all":
            return None  # permissions system will not be used
        case "no-delete":  # mostly no delete, no overwrite
            return {
                "": "lr",
                "archives": "lrw",
                "cache": "lrwWD",  # WD for checked-packs, ...
                "config": "lrW",  # W for manifest
                "index": "lrwWD",  # WD for index/<HASH> (merge/compaction of incremental indexes)
                "keys": "lr",
                "locks": "lrwD",  # borg needs to create/delete a shared lock here
                "packs": "lrw",
            }
        case "write-only":  # mostly no reading
            return {
                "": "l",
                "archives": "lw",
                "cache": "lrwWD",  # TODO: check more restrictive permissions
                "config": "lrW",  # W for manifest
                "index": "lrwWD",  # read allowed so that borg create can check chunk presence for deduplication
                "keys": "lr",
                "locks": "lrwD",  # borg needs to create/delete a shared lock here
                "packs": "lw",  # no r!
            }
        case "read-only":  # mostly r/o
            return {"": "lr", "locks": "lrwD"}
        case _:
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
    """Buffers chunks into a pack file and writes it to the store when full.

    add() buffers a (chunk_id, cdata) pair and marks the chunk pending (F_PENDING);
    flush() writes the pack and sets each entry's pack_id, obj_offset and obj_size,
    clearing F_PENDING.

    The ChunkIndex comes from the repository, or from an explicit chunks index when
    there is no repository (see the chunks property).

    max_count bounds how many chunks a pack holds; max_size bounds its byte size.
    flush() fires when either limit is reached.  Set a limit to None to disable it;
    at least one must be set, otherwise the pack buffer is unbounded.
    """

    def __init__(self, store, *, max_count=None, max_size=None, chunks=None, repository=None):
        if repository is None and chunks is None:
            raise ValueError("PackWriter requires either a repository or an explicit chunks index")
        if max_count is None and max_size is None:
            raise ValueError("PackWriter needs max_count or max_size, otherwise the pack buffer is unbounded")
        self.store = store
        self.max_count = max_count  # None = no count limit
        self.max_size = max_size  # None = no size limit
        self.repository = repository
        self._chunks = chunks  # used when there is no repository
        self._pieces = []  # list of (chunk_id, cdata)
        self._size = 0  # byte size of buffered pieces

    @property
    def chunks(self):
        """The ChunkIndex this writer updates: the repository's index, or the
        explicit index passed at construction when there is no repository."""
        if self.repository is not None:
            return self.repository.chunks
        return self._chunks

    def add(self, chunk_id, cdata):
        """Buffer a chunk.  Returns flush results if the pack is now full, else None."""
        self.chunks.add(chunk_id, 0)  # size: plaintext chunk size, set by the cache layer
        self._pieces.append((chunk_id, cdata))
        self._size += len(cdata)
        if (self.max_count is not None and len(self._pieces) >= self.max_count) or (
            self.max_size is not None and self._size >= self.max_size
        ):
            return self.flush()
        return None

    def flush(self):
        """Write the current pack to the store.

        Returns a list of (chunk_id, pack_id, obj_offset, obj_size) tuples --
        one entry per chunk that was written.  Returns None if there was nothing
        to flush.  Always updates the ChunkIndex with the real pack_id and obj_offset.
        """
        if not self._pieces:
            return None

        # Build the pack bytes once by joining all pieces (avoids O(n^2) copies
        # that incremental string concatenation would cause in Python).
        pack_data = b"".join(cdata for _, cdata in self._pieces)

        # Name the pack by the SHA-256 of its bytes: the name commits to the stored content,
        # so borgstore can verify and cache the file.
        pack_id = sha256(pack_data).digest()

        # Record (chunk_id, pack_id, obj_offset, obj_size) for every piece.
        results = []
        offset = 0
        for chunk_id, cdata in self._pieces:
            obj_size = len(cdata)
            results.append((chunk_id, pack_id, offset, obj_size))
            offset += obj_size

        key = "packs/" + bin_to_hex(pack_id)
        pending_ids = [chunk_id for chunk_id, _ in self._pieces]
        try:
            self.store.store(key, pack_data)
        except Exception:
            # the pack was not stored: drop the index entries for its chunks.
            for chunk_id in pending_ids:
                if chunk_id in self.chunks:  # a chunk_id may appear more than once in this pack
                    del self.chunks[chunk_id]
            raise
        finally:
            self._pieces = []  # cleared on success and on failure
            self._size = 0
        self.chunks.update_pack_info(results)  # set the real location and clear F_PENDING
        return results


class PackReader:
    """Reads pack files, the read-side counterpart to PackWriter.

    Pass pack_id to read from the store, or pack_contents for a pack already in memory.
    """

    def __init__(self, store=None, pack_id=None, pack_contents=None):
        self.store = store
        self.pack_id = pack_id
        self.key = "packs/" + bin_to_hex(pack_id) if pack_id is not None else None
        self.pack_contents = pack_contents

    def read(self, offset, size):
        # read from the in-memory pack if we have it, else range-read from the store
        if self.pack_contents is not None:
            return self.pack_contents[offset : offset + size]
        return self.store.load(self.key, offset=offset, size=size)

    def iter_headers(self):
        """Yield (chunk_id, offset, size) for each object by walking the fixed object headers.

        Only the headers are read, not the payloads, so locating every object costs one short
        range read per object (or just a slice, when the pack is already in memory).
        """
        hdr_size = RepoObj.obj_header.size
        offset = 0
        while True:
            hdr_data = self.read(offset, hdr_size)
            if len(hdr_data) < hdr_size:
                break  # clean EOF, or trailing partial bytes
            hdr = RepoObj.ObjHeader(*RepoObj.obj_header.unpack(hdr_data))
            obj_size = hdr_size + hdr.meta_size + hdr.data_size
            yield hdr.chunk_id, offset, obj_size
            offset += obj_size


class PackTracker:
    """Packs check() verified in the current cycle, mapping pack_id (32 bytes) -> (timestamp, result).

    A cycle is one full pass over packs/, which --max-duration may spread over several partial checks.
    The set is stored at cache/checked-packs with a sha256 over the serialized table appended. load()
    accepts the table only if that hash matches and its entries have the layout this class writes.
    """

    NAME = "cache/checked-packs"
    Entry = namedtuple("Entry", "timestamp result")
    EntryFormatT = namedtuple("EntryFormatT", "timestamp result")
    _EntryFormat = EntryFormatT(timestamp="Q", result="B")  # unix ts, 1=ok 0=corrupt

    def __init__(self, store):
        self.store = store
        self.table = self._new_table()

    @classmethod
    def _new_table(cls):
        return HashTableNT(key_size=32, value_type=cls.Entry, value_format=cls._EntryFormat)

    def __len__(self):
        return len(self.table)

    def is_intact(self, pack_id):
        entry = self.table.get(pack_id)
        return entry is not None and bool(entry.result)

    def record(self, pack_id, ok):
        self.table[pack_id] = self.Entry(timestamp=int(time.time()), result=int(ok))

    def load(self):
        try:
            data = self.store.load(self.NAME)
        except StoreObjectNotFound:
            return
        if len(data) < 32 or sha256(data[:-32]).digest() != data[-32:]:
            logger.warning("Ignoring corrupted checked-packs set.")
            return
        try:
            with io.BytesIO(data[:-32]) as f:
                table = HashTableNT.read(f)
        except ValueError:
            logger.warning("Ignoring unreadable checked-packs set.")
            return
        # read() rebuilds key size and value type from the blob, so a table written with a different
        # Entry layout reads without error. All entries share one layout, so sampling one is enough.
        for key, value in table.items():
            if len(key) != 32 or value._fields != self.Entry._fields:
                logger.warning("Ignoring checked-packs set with an unexpected layout.")
                return
            break
        self.table = table

    def save(self):
        with io.BytesIO() as f:
            self.table.write(f)
            data = f.getvalue()
        self.store.store(self.NAME, data + sha256(data).digest())

    def clear(self):
        self.table.clear()
        try:
            self.store.delete(self.NAME)
        except StoreObjectNotFound:
            pass


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

    class PackLocationUnknown(ErrorWithTraceback):
        """Object with key {} is indexed but its pack location is unresolved in repository {}."""

        exit_mcode = 22

        # this is a code bug, not a genuine miss: the chunk is in the index but still buffered
        # (not flushed).  deliberately NOT a subclass of ObjectNotFound, so the usual
        # "except ObjectNotFound" handlers do not swallow it -- it surfaces loudly with a traceback.
        def __init__(self, id, repo):
            if isinstance(id, bytes):
                id = bin_to_hex(id)
            super().__init__(id, repo)

    class PackNotFound(ErrorWithTraceback):
        """Object with key {} is indexed to pack {}, but that whole pack is missing from repository {}."""

        exit_mcode = 23

        # a missing pack means the index is stale or more than one object was lost.
        def __init__(self, id, pack_id, repo):
            if isinstance(id, bytes):
                id = bin_to_hex(id)
            if isinstance(pack_id, bytes):
                pack_id = bin_to_hex(pack_id)
            super().__init__(id, pack_id, repo)

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

    class PermissionDenied(Error):
        """Repository permission denied: {}"""

        exit_mcode = 24

    # Whole packs kept in memory for reads; the least recently used is evicted first.
    # Memory use is this count times the pack size.
    PACK_READER_CACHE_SIZE = 3

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
            "index/": {"levels": [0]},
            "keys/": {"levels": [0]},
            "locks/": {"levels": [0]},
            "packs/": {"levels": [1]},
        }
        # Get permissions from parameter or environment variable
        permissions = permissions if permissions is not None else os.environ.get("BORG_REPO_PERMISSIONS", "all")
        permissions = borg_permissions(permissions)

        # writethrough cache for the packs/ namespace: on a cache miss borgstore loads the whole
        # pack, caches it, and serves later reads of that pack's objects from the cache.
        # packs are named by content hash, so one cache directory can hold packs from several
        # repositories; a colliding name has identical content, so sharing is safe.
        # BORG_STORE_CACHE sets the cache directory ("1" means <cache_dir>/storecache); the
        # directory holds the whole store's cache, currently just the packs/ namespace.
        # BORG_PACK_CACHE_SIZE limits the pack cache size in bytes.
        cache_url = None
        store_cache = os.environ.get("BORG_STORE_CACHE")
        if store_cache:
            if store_cache == "1":
                cache_dir = Path(get_cache_dir("storecache"))
            else:
                cache_dir = Path(store_cache)
                cache_dir.mkdir(parents=True, exist_ok=True)
            ns_config["packs/"]["cache"] = "writethrough"
            cache_size = os.environ.get("BORG_PACK_CACHE_SIZE")
            if cache_size:
                ns_config["packs/"]["size"] = int(cache_size)
            cache_url = cache_dir.as_uri()

        try:
            if location.proto == "rest":
                # rest:// is served by "borg serve --rest" (reachable via ssh if a host is given),
                # talking HTTP over stdio - rather than borgstore's own "borgstore-server-rest" command.
                # permissions are not given to the (remote) backend here; they are enforced on the
                # server side by "borg serve --rest --permissions ...".
                backend = build_rest_backend(location)
                self.store = Store(backend=backend, config=ns_config, cache_url=cache_url)
            else:
                self.store = Store(url, config=ns_config, permissions=permissions, cache_url=cache_url)
        except StoreBackendError as e:
            raise Error(str(e))
        # None means "all" (no restrictions); for rest:// the backend enforces permissions
        # server-side, so the client does not check them (see above).
        self.permissions = None if location.proto == "rest" else permissions
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
        self._chunks = None  # ChunkIndex; loaded lazily on first access to .chunks
        # pack_id -> PackReader holding the whole pack; get_many loads into it, get() reuses it
        self._pack_cache = LRUCache(capacity=self.PACK_READER_CACHE_SIZE)

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
            from borg.cache import write_chunkindex_to_repo

            write_chunkindex_to_repo(self, ChunkIndex(), clear=True, force_write=True)
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

    def store_key(self, keydata):
        # store a single repokey borg key (content-addressed). does NOT delete other borg keys,
        # so a repository can have multiple borg keys (one per passphrase). returns the
        # store object name (= borg key id) under which the borg key was stored.
        digest = sha256(keydata).hexdigest()
        self.store.store(f"keys/{digest}", keydata)
        return digest

    def save_key(self, keydata):
        # additive: store this borg key, keeping any other borg keys of this repository.
        # note: saving an empty key is a no-op here; use delete_key() to remove a borg key.
        if keydata:
            self.store_key(keydata)

    def load_keys(self):
        # return a list of (name, keydata) for all borg keys matching this repository's ID.
        repo_id_hex = bin_to_hex(self.id)
        result = []
        try:
            infos = list(self.store.list("keys"))
        except StoreObjectNotFound:
            return result
        for info in infos:
            try:
                keydata = self.store.load(f"keys/{info.name}")
            except StoreObjectNotFound:
                continue
            if is_keyfile(keydata, repo_id_hex):
                result.append((info.name, keydata))
        return result

    def load_key(self):
        # convenience: return the first borg key matching this repository's ID, or b"" if none.
        keys = self.load_keys()
        return keys[0][1] if keys else b""

    def delete_key(self, name):
        # delete a single borg key by its store object name (borg key id).
        try:
            self.store.delete(f"keys/{name}")
        except StoreObjectNotFound:
            pass

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
        self._chunks = None
        # pack-sizing overrides: BORG_PACK_MAX_COUNT sets the max object count per pack,
        # BORG_PACK_MAX_SIZE the max pack size in bytes. Default: size-bound only.
        max_count_env = os.environ.get("BORG_PACK_MAX_COUNT")
        max_size_env = os.environ.get("BORG_PACK_MAX_SIZE")
        max_count = int(max_count_env) if max_count_env is not None else None
        if max_size_env is not None:
            max_size = int(max_size_env)
        else:
            max_size = None if max_count is not None else DEFAULT_PACK_MAX_SIZE
        self._pack_writer = PackWriter(self.store, repository=self, max_count=max_count, max_size=max_size)
        self.opened = True

    @property
    def pack_max_size(self):
        """The configured byte cap for a pack (BORG_PACK_MAX_SIZE, or the default if count-bound)."""
        return self._pack_writer.max_size or DEFAULT_PACK_MAX_SIZE

    @property
    def chunks(self):
        """ChunkIndex mapping every known chunk id to its pack location.

        This property is the single owner of the in-memory index: get() resolves
        pack locations through it, PackWriter updates it, and the Cache reads it
        from here rather than building its own.  Built lazily on first access and
        persisted back to the repo cache at close().
        """
        if self._chunks is None:
            from .cache import build_chunkindex_from_repo

            self._chunks = build_chunkindex_from_repo(self)
        return self._chunks

    @chunks.setter
    def chunks(self, value):
        # The index is normally built lazily; this setter exists for the few callers
        # that must install a specific index (e.g. wiping the cache, or restoring an
        # index captured before close()).  To drop a stale index so it rebuilds, do not
        # assign None here -- call invalidate_chunk_index() instead.
        self._chunks = value

    def invalidate_chunk_index(self):
        """Drop the in-memory chunk index so close() will not persist a stale copy.

        Called when the on-disk chunk index is deleted; the next access to
        .chunks rebuilds the index from actual repository contents.  PackWriter
        reads the index through this Repository, so it follows automatically.
        """
        self._chunks = None

    @property
    def is_chunk_index_loaded(self):
        """Whether the in-memory chunk index has been built/loaded this session.

        Lets the few flag-style checks ask "is it loaded?" without going through the
        .chunks property (which would build it on demand).  self._chunks should not be
        read directly elsewhere; use .chunks for the index or this for the loaded flag.
        """
        return self._chunks is not None

    def flush(self):
        """Flush any buffered pack writer chunks."""
        if self._pack_writer is not None:
            self._lock_refresh()
            self._pack_writer.flush()  # PackWriter updates _chunks internally

    def close(self):
        if self._pack_writer is not None:
            assert not self._pack_writer._pieces, "PackWriter has unflushed chunks; call flush() before close()"
        # close() may run again after the store was already closed (idempotent close), so we can
        # only persist while the store is open. Persisting is also a no-op unless chunks were added
        # this session (only F_NEW entries are serialized, and an empty incremental write is skipped).
        # guard on is_chunk_index_loaded so we never trigger a lazy rebuild just to persist on close.
        if self.store_opened and self.is_chunk_index_loaded:
            from .cache import write_chunkindex_to_repo

            write_chunkindex_to_repo(self, self.chunks, incremental=True)
        if self.lock:
            # ignore_not_found: close() runs during normal teardown, but also while unwinding an
            # exception. if the lock was already gone (e.g. it went stale and another client killed
            # it, or refresh() aborted with LockTimeout), a NotLocked raised here would mask the
            # original error. we are closing anyway, so treat a missing lock as nothing to release.
            self.lock.release(ignore_not_found=True)
            self.lock = None
        if self.store_opened:
            self.store.close()
            self.store_opened = False
        self.opened = False
        self._pack_cache.clear()

    def info(self):
        """return some infos about the repo (must be opened first)"""
        # note: don't do anything expensive here or separate the lock refresh into a separate method.
        self._lock_refresh()  # do not remove, see do_with_lock()
        info = dict(id=self.id, version=self.version)
        return info

    def check(self, repair=False, max_duration=0):
        """Check repository consistency.

        packs/ and index/ objects are named by the sha256 of their content, so a pack or index file
        is intact iff store.hash(name) still equals name. The whole pack is hashed; the REST backend
        computes the hash server-side, so for it nothing is downloaded.

        The index is hashed first and the packs only if it is intact. The packs could be hashed even
        with a corrupt index, but a corrupt index already means the user has to repair it, and that
        rebuild re-reads every pack anyway - so a read-only check just stops and reports it instead of
        continuing. The index is never rebuilt here in any case: reading every pack to do so would be
        far too slow and expensive for a routine (e.g. cron) check. Salvaging good objects out of
        corrupt packs and dropping those packs is left to repair, refs #8572.
        """

        def verify(namespace, name):
            # name is the sha256 of the object's content, so it is intact iff store.hash() matches.
            key = f"{namespace}/{name}"
            try:
                ok = self.store.hash(key) == name
            except StoreObjectNotFound:
                return True  # vanished since store.list(); not an error
            if not ok:
                logger.error(f"Store object {key} is corrupted: content does not match its name (sha256).")
            return ok

        def store_list(namespace):
            try:
                return list(self.store.list(namespace))
            except StoreObjectNotFound:
                return []  # namespace does not exist

        partial = bool(max_duration)
        assert not (repair and partial)
        mode = "partial" if partial else "full"
        logger.info(f"Starting {mode} repository check")
        tracker = PackTracker(self.store)
        if partial:
            tracker.load()  # resume the cycle
        else:
            tracker.clear()  # a full check verifies every pack, so start a new cycle
        if len(tracker):
            logger.info(f"Continuing check cycle, {len(tracker)} packs already checked.")
        else:
            logger.info("Starting from beginning.")
        t_start = time.monotonic()
        t_last_checkpoint = t_start
        index_files = index_errors = 0
        pack_files = pack_errors = 0
        # index and packs get separate progress indicators, each running from 0% to 100%.
        # the index is checked first and in full, on partial checks too: it is small, and index errors
        # stop the pack check below.
        index_infos = store_list("index")
        index_pi = ProgressIndicatorPercent(total=len(index_infos), msg="Checking index %3.0f%%", msgid="check.index")
        for info in index_infos:
            self._lock_refresh()
            index_pi.show(increase=1)
            index_files += 1
            if not verify("index", info.name):
                index_errors += 1
        if index_infos:
            index_pi.show(current=len(index_infos))  # finish at 100%
        index_pi.finish()
        if index_errors == 0:
            # packs are the bulk of the work and the part --max-duration spreads over several checks.
            pack_infos = store_list("packs")
            pack_pi = ProgressIndicatorPercent(total=len(pack_infos), msg="Checking packs %3.0f%%", msgid="check.packs")
            for info in pack_infos:
                self._lock_refresh()
                pack_pi.show(increase=1)  # advance for skipped packs too, so the bar tracks packs/, not work done
                pack_id = hex_to_bin(info.name)
                if tracker.is_intact(pack_id):  # verified intact earlier in this cycle
                    continue
                pack_files += 1
                ok = verify("packs", info.name)
                if not ok:
                    pack_errors += 1
                tracker.record(pack_id, ok)
                now = time.monotonic()
                # a checkpoint rewrites the whole table (41 bytes per pack), so keep the interval long.
                if now > t_last_checkpoint + 30 * 60:
                    t_last_checkpoint = now
                    logger.info(f"Checkpointing at pack {info.name}.")
                    tracker.save()
                if partial and now > t_start + max_duration:
                    logger.info(f"Finished partial repository check, {len(tracker)} packs checked so far.")
                    tracker.save()
                    break
            else:
                # scanned all packs without hitting the time limit: the cycle is done, drop the set.
                if pack_infos:
                    pack_pi.show(current=len(pack_infos))  # finish at 100%
                logger.info("Finished checking packs.")
                tracker.clear()
            pack_pi.finish()
        else:
            # TODO: --repair will rebuild the index from the packs here instead of stopping (refs #8572).
            logger.error("Repository index is corrupted and must be repaired; skipping the pack check.")
        objs_errors = index_errors + pack_errors
        logger.info(
            f"Checked {index_files} index files ({index_errors} errors) and {pack_files} packs ({pack_errors} errors)."
        )
        if objs_errors == 0:
            logger.info(f"Finished {mode} repository check, no problems found.")
        elif repair:
            logger.error(f"Finished {mode} repository check, errors found (repository repair not implemented).")
        else:
            logger.error(f"Finished {mode} repository check, errors found.")
        return objs_errors == 0 or repair

    def list(self, limit=None, marker=None):
        """
        list <limit> infos starting from after id <marker>.
        each info is a tuple (id, storage_size).
        """
        # Yield chunk_ids from the chunk index. (Listing the packs/ dir would yield pack file names,
        # i.e. pack_ids, which are not chunk_ids.) iteritems() has no marker arg, so we skip to
        # <marker> ourselves; index order is stable unless the index is mutated, which is all the
        # marker pagination needs.
        self._lock_refresh()
        collect = marker is None
        result = []
        for chunk_id, entry in self.chunks.iteritems():
            if self.chunks.is_pending(chunk_id):
                continue  # buffered in PackWriter, not flushed to a pack yet
            if collect:
                result.append((chunk_id, entry.obj_size))
                if len(result) == limit:
                    break
            elif chunk_id == marker:
                collect = True  # start collecting after the marker; do not include the marker itself
        return result

    def get(self, id, read_data=True, raise_missing=True):
        self._lock_refresh()
        entry = self.chunks.get(id)
        if entry is None:
            if raise_missing:
                raise self.ObjectNotFound(id, str(self._location))
            return None
        if self.chunks.is_pending(id):
            # buffered but not flushed; a chunk must be flushed before any read, so this is a code
            # bug (wrong flush/index ordering), not a missing object: raise regardless of raise_missing.
            raise self.PackLocationUnknown(id, str(self._location))
        pack_id, obj_offset, obj_size = entry.pack_id, entry.obj_offset, entry.obj_size
        id_hex = bin_to_hex(id)
        # slice from the cached whole pack if get_many (or an earlier get) already loaded it;
        # otherwise read ranges from the store without loading and caching the whole pack.
        reader = self._pack_cache.get(pack_id)
        if reader is None:
            reader = PackReader(store=self.store, pack_id=pack_id)
        try:
            if read_data:
                return reader.read(obj_offset, obj_size)
            else:
                # RepoObj layout supports separately encrypted metadata and data.
                # We return enough bytes so the client can decrypt the metadata.
                hdr_size = RepoObj.obj_header.size
                extra_size = 1024 - hdr_size  # load a bit more, 1024b, reduces round trips
                load_size = hdr_size + extra_size
                # keep the read inside this object: a pack holds neighbouring objects, so don't pull
                # bytes past obj_size into the next one. (an overshoot would be harmless -- parse_meta
                # uses the header's length and ignores trailing bytes -- this is just tidy.) obj_size
                # comes from the same index we already route with.
                load_size = min(load_size, obj_size)
                obj = reader.read(obj_offset, load_size)
                hdr = obj[0:hdr_size]
                if len(hdr) != hdr_size:
                    raise IntegrityError(f"Object too small [id {id_hex}]: expected {hdr_size}, got {len(hdr)} bytes")
                meta_size = RepoObj.ObjHeader(*RepoObj.obj_header.unpack(hdr)).meta_size
                if meta_size > extra_size:
                    # we did not get enough, need to load more, but not all.
                    # this should be rare, as chunk metadata is rather small usually.
                    retry_size = hdr_size + meta_size
                    # same boundary as above: normally a no-op, just keeps the retry within this object.
                    retry_size = min(retry_size, obj_size)
                    obj = reader.read(obj_offset, retry_size)
                meta = obj[hdr_size : hdr_size + meta_size]
                if len(meta) != meta_size:
                    raise IntegrityError(f"Object too small [id {id_hex}]: expected {meta_size}, got {len(meta)} bytes")
                return hdr + meta
        except StoreObjectNotFound:
            if raise_missing:
                raise self.ObjectNotFound(id, str(self._location)) from None
            else:
                return None

    def _cached_pack_reader(self, pack_id):
        """Return a PackReader holding the whole pack, loading it into the cache on a miss."""
        reader = self._pack_cache.get(pack_id)
        if reader is None:
            key = "packs/" + bin_to_hex(pack_id)
            reader = PackReader(pack_id=pack_id, pack_contents=self.store.load(key))
            self._pack_cache[pack_id] = reader
        return reader

    def get_many(self, ids, read_data=True, raise_missing=True):
        if not read_data:
            # read_data=False returns only each object's header+meta, sized per object by get().
            for id_ in ids:
                yield self.get(id_, read_data=read_data, raise_missing=raise_missing)
            return

        for id_ in ids:
            self._lock_refresh()
            entry = self.chunks.get(id_)
            if entry is None or self.chunks.is_pending(id_):
                # id unknown or still buffered: get() raises or returns None accordingly
                yield self.get(id_, read_data=True, raise_missing=raise_missing)
                continue
            try:
                reader = self._cached_pack_reader(entry.pack_id)
            except StoreObjectNotFound:
                if raise_missing:
                    raise self.PackNotFound(id_, entry.pack_id, str(self._location)) from None
                yield None
            else:
                yield reader.read(entry.obj_offset, entry.obj_size)

    def put(self, id, data):
        """put a repo object

        Buffers the chunk in the pack writer.  When the chunk fills the pack and
        triggers a flush, returns a list of (chunk_id, pack_id, obj_offset, obj_size)
        tuples, one per chunk written to disk by that flush; otherwise returns None.
        """
        self._lock_refresh()
        data_size = len(data)
        if data_size > MAX_DATA_SIZE:
            raise IntegrityError(f"More than allowed put data [{data_size} > {MAX_DATA_SIZE}]")
        # PackWriter shares this repository's index, so add() triggers the lazy build itself.
        return self._pack_writer.add(id, data)

    def delete(self, id, *, update_index=True):
        """Delete a single repo object by rewriting its pack without it (via compact_pack).

        With update_index=True the full chunk index is written back so the next borg process sees the
        deletion; callers that rebuild the index themselves (check --repair) pass update_index=False to
        skip the per-object index rewrite.
        """
        self._lock_refresh()
        entry = self.chunks.get(id)
        if entry is None:
            raise self.ObjectNotFound(id, str(self._location))
        pack_id = entry.pack_id
        # keep every object the chunk index lists for this pack, except the one being deleted.
        keep_ids = {cid for cid, e in self.chunks.iteritems() if e.pack_id == pack_id}
        keep_ids.discard(id)
        self.compact_pack(pack_id, keep_ids=keep_ids, drop_ids={id})
        if update_index:
            # close() only persists new entries incrementally, so write the full index here to record
            # the removal for the next borg process.
            from .cache import write_chunkindex_to_repo

            write_chunkindex_to_repo(self, self.chunks, incremental=False, force_write=True, delete_other=True)

    def compact_pack(self, pack_id, *, keep_ids: set, drop_ids: set, chunks=None):
        """Rewrite pack <pack_id>, keeping <keep_ids> and dropping <drop_ids>, then delete the old pack.

        keep_ids: chunk ids in this pack to copy into the new pack.
        drop_ids: chunk ids in this pack to discard. Must not overlap keep_ids.
        chunks: the ChunkIndex to look up the objects' pack locations in and to apply the index
            updates to. Must be the index keep_ids and drop_ids were derived from. Default: self.chunks.

        Together, keep_ids and drop_ids must cover every object the chunk index lists for this pack;
        an unlisted indexed object would keep its bytes in the new pack but its index entry would go
        stale when the old pack is deleted. Bytes that no index entry covers appear as gaps between the
        listed objects: a gap object whose chunk id is in the index is a superseded duplicate (its
        authoritative copy is elsewhere) and is dropped; a gap object whose id is not in the index is
        copied into the new pack unchanged, to be handled by "borg check --repair". An overlap between
        listed objects, or an object claiming to end past the pack file, means index corruption and
        raises IntegrityError.

        The new pack is the old pack minus the dropped objects, built via store.defrag; kept objects are
        repointed in the chunk index and dropped objects' chunk index entries are removed.

        Returns (new_pack_id, dropped_bytes): new_pack_id is None if every byte was dropped, or the
        unchanged pack_id if nothing was dropped; dropped_bytes is the on-disk bytes this rewrite freed
        (unused indexed objects plus superseded duplicates), for --stats accounting.

        Updates the in-memory chunk index only; the caller holds the exclusive lock and writes the
        index back to the store afterwards.
        """
        self._lock_refresh()
        if chunks is None:
            chunks = self.chunks
        pack_key = "packs/" + bin_to_hex(pack_id)

        assert keep_ids & drop_ids == set(), "an id cannot appear in both keep_ids and drop_ids"

        # collect every listed object's range, tagged with whether it is kept, ordered by offset.
        located = []  # (obj_offset, obj_id, obj_size, keep)
        for obj_id in keep_ids | drop_ids:
            keep = obj_id in keep_ids
            entry = chunks[obj_id]
            assert entry.pack_id == pack_id, f"{bin_to_hex(obj_id)} is not in pack {bin_to_hex(pack_id)}"
            located.append((entry.obj_offset, obj_id, entry.obj_size, keep))
        located.sort()

        # walk objects in offset order. covered is the end offset of the last object; an overlap
        # (offset < covered) is index corruption. record the dropped objects' byte ranges; every other
        # byte (kept objects and gaps that no index entry covers) is copied into the new pack unchanged.
        drop_ranges = []  # (obj_offset, obj_size) of dropped objects, offset-ordered
        covered = 0
        for offset, obj_id, size, keep in located:
            if offset < covered:
                raise IntegrityError(
                    f"pack {bin_to_hex(pack_id)}: overlapping objects at offset {offset} (index corruption), "
                    f'run "borg check"'
                )
            covered = offset + size
            if not keep:
                drop_ranges.append((offset, size))

        # reject an object that ends past the pack file: store.defrag would short-read it into a
        # truncated object in the new pack, then the intact source pack is deleted.
        pack_size = self.store.info(pack_key).size
        if covered > pack_size:
            raise IntegrityError(
                f"pack {bin_to_hex(pack_id)}: object extends past end of file at offset {covered} "
                f'(index corruption), run "borg check"'
            )

        # find the gaps: byte ranges no listed object covers (a chunk copy stored again elsewhere, or
        # objects from a backup that crashed before writing its index).
        gaps = []  # (start, end) of each gap, offset-ordered
        cursor = 0
        for offset, obj_id, size, keep in located:
            if offset > cursor:
                gaps.append((cursor, offset))
            cursor = offset + size
        if cursor < pack_size:
            gaps.append((cursor, pack_size))

        # walk each gap's object headers. drop an object whose chunk id the index maps to a different
        # location: that entry is the authoritative copy (the id is a keyed MAC of the plaintext, so
        # equal ids mean equal content) and these bytes are redundant. keep an object whose id is not in
        # the index (borg check --repair re-indexes it) or whose entry points back at this offset (its
        # only copy). a header that does not parse or overruns its gap ends the walk over that gap.
        # TODO(#9868 follow-up): classify gaps in compact_packs pass 1 too, so superseded bytes count
        # toward the rewrite threshold and a wholly superseded orphan pack can be dropped outright.
        reader = PackReader(store=self.store, pack_id=pack_id)
        hdr_size = RepoObj.obj_header.size
        for gstart, gend in gaps:
            offset = gstart
            while offset < gend:
                hdr_data = reader.read(offset, hdr_size)
                if len(hdr_data) < hdr_size:
                    break
                hdr = RepoObj.ObjHeader(*RepoObj.obj_header.unpack(hdr_data))
                obj_size = hdr_size + hdr.meta_size + hdr.data_size
                if hdr.magic != OBJ_MAGIC or offset + obj_size > gend:
                    break
                if hdr.chunk_id in chunks:
                    entry = chunks[hdr.chunk_id]
                    if entry.pack_id != pack_id or entry.obj_offset != offset:
                        drop_ranges.append((offset, obj_size))
                offset += obj_size
        drop_ranges.sort()
        dropped_bytes = sum(size for _, size in drop_ranges)  # on-disk bytes this rewrite frees, for --stats

        # the new pack is the whole file minus the dropped ranges: copy the byte spans between them.
        sources = []  # (pack_hex, offset, size) to copy, offset-ordered
        pack_hex = bin_to_hex(pack_id)
        cursor = 0
        for offset, size in drop_ranges:
            if offset > cursor:
                sources.append((pack_hex, cursor, offset - cursor))
            cursor = offset + size
        if cursor < pack_size:
            sources.append((pack_hex, cursor, pack_size - cursor))

        # write the new pack (named sha256 of its content) from those spans before touching the index
        # or the old pack, so a failed read-back leaves everything unchanged. a span reading back short
        # (defrag raises ReadRangeError) means the pack file is truncated or corrupt.
        if sources:
            try:
                new_pack_id = hex_to_bin(self.store.defrag(sources, algorithm="sha256", namespace="packs"))
            except ReadRangeError as e:
                raise IntegrityError(f'pack {pack_hex}: {e}, run "borg check"') from e
        else:
            new_pack_id = None  # every byte was dropped: no replacement pack

        for drop_id in drop_ids:  # remove dropped objects from the index
            del chunks[drop_id]

        if new_pack_id is None:  # nothing kept: drop the pack, no replacement
            self.store_delete(pack_key)
            return None, dropped_bytes

        # repoint kept objects at the new pack; an object's new offset is its old offset minus the
        # dropped bytes lying before it. both lists are offset-ordered, so a single walk over the
        # drop ranges keeps the running total of dropped bytes.
        new_locations = []
        dropped_before = 0
        di = 0
        for offset, obj_id, size, keep in located:
            while di < len(drop_ranges) and drop_ranges[di][0] < offset:
                dropped_before += drop_ranges[di][1]
                di += 1
            if keep:
                new_locations.append((obj_id, new_pack_id, offset - dropped_before, size))
        chunks.update_pack_info(new_locations)

        # delete the old pack last, after the new one is stored and indexed, so kept bytes are never the
        # only copy. with nothing dropped, defrag reproduced the pack (new_pack_id == pack_id) and
        # deleting it would drop what we kept, so skip.
        if new_pack_id != pack_id:
            self.store_delete(pack_key)
        return new_pack_id, dropped_bytes

    def merge_packs(self, pack_ids, *, chunks=None, max_size=None):
        """Combine several small packs into fewer, larger ones to reduce the pack count.

        pack_ids: the packs to merge, whole files; afterwards the source packs are deleted.
        chunks: the ChunkIndex to read object locations from and to apply the index updates to.
            Must be the index pack_ids were derived from. Default: self.chunks.
        max_size: byte cap for each merged pack. Default: the repository's configured pack size limit.

        Whole pack files are copied, not individual indexed objects, so bytes no index entry covers
        (a chunk copy superseded by a later put, or objects from a backup that crashed before
        writing its index) are carried into the merged pack too.

        Each source pack's index entries are checked for overlap or for claiming bytes past the
        pack's actual end before anything is written; either means a corrupt index. Raises
        IntegrityError in that case and leaves the store untouched; repair is "borg check --repair".

        Packs are merged one batch at a time, each batch's sources deleted once its merged pack is
        stored and indexed. So a crash or Ctrl-C between batches never destroys the only stored copy
        of an object, and the store holds at most one batch of extra packs at a time. The packs not
        yet merged are merged on the next run.
        """
        self._lock_refresh()
        if chunks is None:
            chunks = self.chunks
        if max_size is None:
            max_size = self.pack_max_size
        pack_ids = set(pack_ids)

        # collect every still-indexed object of the selected packs, grouped per source pack, ordered by offset.
        per_pack = defaultdict(list)  # pack_id -> [(obj_offset, obj_id, obj_size), ...]
        for obj_id, entry in chunks.iteritems():
            if entry.pack_id in pack_ids:
                per_pack[entry.pack_id].append((entry.obj_offset, obj_id, entry.obj_size))
        for objs in per_pack.values():
            objs.sort()

        # get each source pack's real file size; drop any pack already gone from the store (its
        # index entry is stale). store.info() reports a missing object via info.exists, not by raising.
        pack_size = {}
        for pid in list(pack_ids):
            info = self.store.info("packs/" + bin_to_hex(pid))
            if not info.exists:
                logger.warning(f"Pack {bin_to_hex(pid)} to merge was already gone.")
                pack_ids.discard(pid)
                per_pack.pop(pid, None)
                continue
            pack_size[pid] = info.size

        # validate every remaining pack before writing anything (see docstring).
        for pid in pack_ids:
            covered = 0
            for offset, _, size in per_pack[pid]:
                if offset < covered:
                    raise IntegrityError(
                        f"pack {bin_to_hex(pid)}: overlapping objects at offset {offset} "
                        f'(index corruption), run "borg check"'
                    )
                covered = offset + size
            if covered > pack_size[pid]:
                raise IntegrityError(
                    f"pack {bin_to_hex(pid)}: object extends past end of file at offset {covered} "
                    f'(index corruption), run "borg check"'
                )

        # greedily batch whole pack files so each output pack stays within max_size, in sorted id
        # order so batch composition is reproducible.
        batches = []  # each batch: [pack_id, ...]
        current, current_size = [], 0
        for pid in sorted(pack_ids):
            size = pack_size[pid]
            if current and current_size + size > max_size:
                batches.append(current)
                current, current_size = [], 0
            current.append(pid)
            current_size += size
        if current:
            batches.append(current)

        # write each batch as a new pack (named sha256 of its content) and repoint its objects: an
        # object's new offset is the running byte total of the packs before its pack in the batch,
        # plus its old offset within that pack.
        pi = ProgressIndicatorPercent(total=len(batches), msg="Merging packs %3.0f%%", msgid="repository.merge_packs")
        produced = set()  # merged pack ids; a one-pack batch reproduces its source's id
        for batch in batches:
            if sig_int:
                break
            self._lock_refresh()  # refresh the lock per batch, the loop can run for a while
            sources = [(bin_to_hex(pid), 0, pack_size[pid]) for pid in batch]
            try:
                new_pack_id = hex_to_bin(self.store.defrag(sources, algorithm="sha256", namespace="packs"))
            except ReadRangeError as e:  # a source pack shrank or is corrupt
                raise IntegrityError(f'merge_packs: {e}, run "borg check"') from e
            produced.add(new_pack_id)
            new_locations = []
            pack_base = 0
            for pid in batch:
                for offset, obj_id, size in per_pack[pid]:
                    new_locations.append((obj_id, new_pack_id, pack_base + offset, size))
                pack_base += pack_size[pid]
            chunks.update_pack_info(new_locations)
            # delete this batch's sources; skip any pack a batch reproduced (a one-pack batch hashes
            # to the same content-addressed name), which now holds the merged data.
            for pid in batch:
                if pid in produced:
                    continue
                try:
                    self.store_delete("packs/" + bin_to_hex(pid))
                except StoreObjectNotFound:
                    logger.warning(f"Pack {bin_to_hex(pid)} to merge was already gone.")
            pi.show(increase=1)
        pi.finish()

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

    def store_load(self, name, *, size=None, offset=0):
        self._lock_refresh()
        return self.store.load(name, size=size, offset=offset)

    def store_store(self, name, value):
        self._lock_refresh()
        return self.store.store(name, value)

    def store_delete(self, name, *, deleted=False):
        self._lock_refresh()
        return self.store.delete(name, deleted=deleted)

    def assert_writable(self):
        """Raise PermissionDenied if the repo permissions forbid compaction.

        Compaction stores new packs and index fragments and deletes the old ones, so it needs
        write (w/W) and delete (D) access to the packs/ and index/ namespaces. self.permissions
        is None when no restrictions apply (BORG_REPO_PERMISSIONS=all).
        """
        if self.permissions is None:
            return
        for namespace in ("packs", "index"):
            granted = set(self.permissions.get(namespace, self.permissions.get("", "")))
            if not (granted & set("wW")) or "D" not in granted:
                raise self.PermissionDenied(
                    f"compaction needs write (w/W) and delete (D) permissions on {namespace}/, "
                    f"but only {''.join(sorted(granted))!r} is granted (BORG_REPO_PERMISSIONS)."
                )

    def store_move(self, name, new_name=None, *, delete=False, undelete=False, deleted=False):
        self._lock_refresh()
        return self.store.move(name, new_name, delete=delete, undelete=undelete, deleted=deleted)

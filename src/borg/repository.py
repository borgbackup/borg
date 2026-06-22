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
from .hashindex import ChunkIndex
from .helpers import Error, ErrorWithTraceback, IntegrityError
from .helpers import Location
from .helpers import bin_to_hex, hex_to_bin
from .helpers import ProgressIndicatorPercent
from .storelocking import Lock
from .logger import create_logger
from .manifest import NoManifestError
from .repoobj import RepoObj
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
                "cache": "lrwWD",  # WD for last-pack-checked, ...
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
    """Buffers chunks into a pack file and writes to the store when full.

    Collects (chunk_id, cdata) pairs in a list and flushes once max_count is
    reached.  PackWriter maintains the ChunkIndex directly: each add() marks the
    chunk as pending (pack_id=UNKNOWN_BYTES32); flush() then assigns the real
    pack_id, offset and size to every pending entry once the pack is on disk.

    The index is not owned here.  Construction requires either a repository or an
    explicit chunks index; there is no silent default.  With a repository, the writer
    uses that repository's single, authoritative index (see the chunks property), so
    there is never a second copy to keep in sync.  Unit tests pass an explicit index.

    max_count bounds how many chunks a pack accumulates before flush() writes it.
    Raising it produces larger packs without changing this class's interface.
    """

    def __init__(self, store, *, max_count=1, chunks=None, repository=None):
        if repository is None and chunks is None:
            raise ValueError("PackWriter requires either a repository or an explicit chunks index")
        self.store = store
        self.max_count = max_count
        self.repository = repository  # when set, the one and only index lives there
        self._chunks = chunks  # explicit index for repository-less use (tests)
        self._pieces = []  # list of (chunk_id, cdata)

    @property
    def chunks(self):
        """The ChunkIndex this writer updates.

        With a repository, this is the repository's single index (shared, not copied).
        Without one, it is the explicit index passed at construction.
        """
        if self.repository is not None:
            return self.repository.chunks
        return self._chunks

    def add(self, chunk_id, cdata):
        """Buffer a chunk.  Returns flush results if the pack is now full, else None."""
        # Mark the chunk as pending (pack_id=UNKNOWN_BYTES32).  flush() assigns the real
        # pack_id and offset for every piece, so the placeholder offset 0 here is never read:
        # get() refuses a pending entry (PackLocationUnknown) before any offset would matter.
        # Precondition: callers add only chunks not already stored (the cache dedups via
        # seen_chunk() first), so add(chunk_id, 0) never resets a real size on an existing entry.
        # This is also what keeps ChunkIndex.add's "v.size == 0 or v.size == size" assertion happy:
        # a fresh id has no entry, so the size=0 we pass here is never compared against a real size.
        self.chunks.add(chunk_id, 0)  # size filled in by cache layer
        self.chunks.update_pack_info([(chunk_id, UNKNOWN_BYTES32, 0, len(cdata))])
        self._pieces.append((chunk_id, cdata))
        if len(self._pieces) >= self.max_count:
            return self.flush()
        return None

    def flush(self):
        """Write the current pack to the store.

        Returns a list of (chunk_id, pack_id, obj_offset, obj_size) tuples --
        one entry per chunk that was written.  Returns None if there was nothing
        to flush.  Always updates the ChunkIndex with the real pack_id.
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
        # ids this flush pre-marked in the index via add() (pack_id still UNKNOWN_BYTES32).
        pending_ids = [chunk_id for chunk_id, _ in self._pieces]
        try:
            self.store.store(key, pack_data)
        except Exception:
            # The pack was not durably stored, so every entry add() pre-marked for it now
            # points at data that does not exist.  Leaving them would make seen_chunk() report
            # these ids as present, letting a later identical chunk dedup against bytes that were
            # never written -- silent data loss.  These entries were created this session and never
            # received a real pack_id, so dropping them restores the index to its pre-add() state
            # (matching master, where the index only ever reflected successfully stored chunks).
            for chunk_id in pending_ids:
                entry = self.chunks.get(chunk_id)
                if entry is not None and entry.pack_id == UNKNOWN_BYTES32:
                    del self.chunks[chunk_id]
            raise
        finally:
            self._pieces = []  # reset even on failure to prevent re-bundling a failed chunk
        self.chunks.update_pack_info(results)  # replace UNKNOWN_BYTES32 with real pack_id
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

    def _read(self, offset, size):
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
            hdr_data = self._read(offset, hdr_size)
            if len(hdr_data) < hdr_size:
                break  # clean EOF, or trailing partial bytes
            hdr = RepoObj.ObjHeader(*RepoObj.obj_header.unpack(hdr_data))
            obj_size = hdr_size + hdr.meta_size + hdr.data_size
            yield hdr.chunk_id, offset, obj_size
            offset += obj_size


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
            "index/": {"levels": [0]},
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
        self._chunks = None  # ChunkIndex; loaded lazily on first access to .chunks

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
        self._pack_writer = PackWriter(self.store, max_count=1, repository=self)
        self.opened = True

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

        Called when the on-disk chunk index cache is deleted; the next access to
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
        LAST_PACK_CHECKED = "cache/last-pack-checked"
        logger.info(f"Starting {mode} repository check")
        if partial:
            # continue a past partial check (if any) or from a checkpoint or start one from beginning
            try:
                last_pack_checked = self.store.load(LAST_PACK_CHECKED).decode()
            except StoreObjectNotFound:
                last_pack_checked = ""
        else:
            # start from the beginning and also forget about any potential past partial checks
            last_pack_checked = ""
            try:
                self.store.delete(LAST_PACK_CHECKED)
            except StoreObjectNotFound:
                pass
        if last_pack_checked:
            logger.info(f"Skipping to packs after {last_pack_checked}.")
        else:
            logger.info("Starting from beginning.")
        t_start = time.monotonic()
        t_last_checkpoint = t_start
        index_files = index_errors = 0
        pack_files = pack_errors = 0
        # check index and packs with separate progress indicators, each running from 0% to 100%.
        # hash the index first, on full and partial checks alike: it is small, and a corrupt index
        # already means the user must repair it (rebuilding the index re-reads all packs anyway), so we
        # stop and report that rather than continue. matters for partial checks too, whose runs can be
        # days apart (e.g. a weekend cron job).
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
            # list the packs only now: a corrupt index skips this entirely. packs are the bulk of the
            # work and the part --max-duration splits.
            pack_infos = store_list("packs")
            pack_pi = ProgressIndicatorPercent(total=len(pack_infos), msg="Checking packs %3.0f%%", msgid="check.packs")
            for info in pack_infos:
                self._lock_refresh()
                pack_pi.show(increase=1)  # advance for every pack, including ones a partial resume skips below
                key = "packs/%s" % info.name
                if key <= last_pack_checked:  # needs sorted keys
                    continue
                pack_files += 1
                if not verify("packs", info.name):
                    pack_errors += 1  # repair (salvage into a new pack, fix index) is not implemented yet
                now = time.monotonic()
                if now > t_last_checkpoint + 300:  # checkpoint every 5 mins
                    t_last_checkpoint = now
                    logger.info(f"Checkpointing at pack {key}.")
                    self.store.store(LAST_PACK_CHECKED, key.encode())
                if partial and now > t_start + max_duration:
                    logger.info(f"Finished partial repository check, last pack checked is {key}.")
                    self.store.store(LAST_PACK_CHECKED, key.encode())
                    break
            else:
                # the pack scan reached the end (no partial timeout): the check is complete, drop the checkpoint.
                if pack_infos:
                    pack_pi.show(current=len(pack_infos))  # finish at 100%
                logger.info("Finished checking packs.")
                try:
                    self.store.delete(LAST_PACK_CHECKED)
                except StoreObjectNotFound:
                    pass
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
            if entry.pack_id == UNKNOWN_BYTES32:
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
        if entry.pack_id == UNKNOWN_BYTES32:
            # chunk is buffered in PackWriter, not yet flushed to a pack. at N=1 put() flushes
            # immediately, so reaching here points at a flush / index-update ordering bug, not a
            # genuinely missing object. this is a code bug, so we crash loudly regardless of
            # raise_missing instead of pretending the object is absent.
            raise self.PackLocationUnknown(id, str(self._location))
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
                # keep the read inside this object: at N>1 a pack holds neighbouring objects, so
                # don't pull bytes past obj_size into the next one. (an overshoot would be harmless
                # -- parse_meta uses the header's length and ignores trailing bytes -- this is just
                # tidy.) obj_size comes from the same index we already route with.
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
                    # same boundary as above: normally a no-op, just keeps the retry within this object.
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

    def put(self, id, data):
        """put a repo object

        Returns a list of (chunk_id, pack_id, obj_offset, obj_size) tuples for
        every chunk written to disk this call.  At max_count=1 this is always
        one entry.
        """
        self._lock_refresh()
        data_size = len(data)
        if data_size > MAX_DATA_SIZE:
            raise IntegrityError(f"More than allowed put data [{data_size} > {MAX_DATA_SIZE}]")
        # PackWriter shares this repository's index, so add() triggers the lazy build itself.
        return self._pack_writer.add(id, data)

    def delete(self, id):
        """delete a repo object"""
        self._lock_refresh()
        # We can not remove one object by dropping its whole pack without losing the pack's other
        # objects; real removal is store_delete at the pack level (compact). For now just check the
        # object exists (ObjectNotFound contract), log, and do nothing.
        # TODO: delete a single object once a pack can hold more than one (N>1).
        entry = self.chunks.get(id)
        if entry is None:
            raise self.ObjectNotFound(id, str(self._location))
        logger.warning("ignoring deletion of %s in %s", bin_to_hex(id), bin_to_hex(entry.pack_id))

    def compact_pack(self, pack_id, keep_ids, drop_ids):
        """Rewrite pack <pack_id>, keeping <keep_ids> and dropping <drop_ids>, then delete the old pack.

        keep_ids and drop_ids must together cover the whole pack (asserted: their ranges tile it with no
        gap or overlap). Kept objects are copied into a new pack via store.defrag and repointed in the
        chunk index; dropped objects' index entries are removed.

        Returns the new pack_id, None if nothing is kept (pack dropped), or <pack_id> unchanged if the
        kept objects reproduce the old pack (same sha256 name, nothing to delete).

        Updates the in-memory chunk index only. The caller holds the exclusive lock and owns index
        durability: invalidate the cached index before calling, write it back after, as compact does.
        """
        self._lock_refresh()
        pack_key = "packs/" + bin_to_hex(pack_id)

        # collect every object's range, tagged with whether it is kept, ordered by offset.
        located = []  # (obj_offset, obj_id, obj_size, keep)
        for keep_id in keep_ids:
            entry = self.chunks[keep_id]
            assert entry.pack_id == pack_id, f"{bin_to_hex(keep_id)} is not in pack {bin_to_hex(pack_id)}"
            located.append((entry.obj_offset, keep_id, entry.obj_size, True))
        for drop_id in drop_ids:
            entry = self.chunks[drop_id]
            assert entry.pack_id == pack_id, f"{bin_to_hex(drop_id)} is not in pack {bin_to_hex(pack_id)}"
            located.append((entry.obj_offset, drop_id, entry.obj_size, False))
        located.sort()

        # keep + drop must tile the whole pack; pick out the survivors in the same pass.
        survivors = []  # (obj_offset, obj_id, obj_size), offset-ordered
        covered = 0
        for offset, obj_id, size, keep in located:
            assert offset == covered, f"gap or overlap in pack {bin_to_hex(pack_id)} at offset {covered}"
            covered += size
            if keep:
                survivors.append((offset, obj_id, size))
        assert covered == self.store.info(pack_key).size, f"pack {bin_to_hex(pack_id)} not fully covered"

        for drop_id in drop_ids:  # remove dropped objects from the index; their bytes are not copied forward
            del self.chunks[drop_id]

        if not survivors:  # nothing kept: drop the pack, no replacement
            self.store_delete(pack_key)
            return None

        # copy survivors into a new pack (named sha256 of its content)
        sources = [(bin_to_hex(pack_id), offset, size) for offset, _, size in survivors]
        new_pack_id = hex_to_bin(self.store.defrag(sources, algorithm="sha256", namespace="packs"))

        # repoint survivors at the new pack; new offset is the running sum of kept sizes
        new_locations = []
        offset = 0
        for _, keep_id, size in survivors:
            new_locations.append((keep_id, new_pack_id, offset, size))
            offset += size
        self.chunks.update_pack_info(new_locations)

        # delete the old pack last, after the new one is stored and indexed, so kept bytes are never the
        # only copy. if every object was kept in order, defrag reproduced the pack (new_pack_id == pack_id)
        # and deleting it would drop what we kept, so skip.
        if new_pack_id != pack_id:
            self.store_delete(pack_key)
        return new_pack_id

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

    def store_move(self, name, new_name=None, *, delete=False, undelete=False, deleted=False):
        self._lock_refresh()
        return self.store.move(name, new_name, delete=delete, undelete=undelete, deleted=deleted)

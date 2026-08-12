import io
import os
import re
import sys
import threading
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
from .helpers import replace_placeholders
from .helpers import sig_int
from .helpers import ProgressIndicatorPercent
from .helpers.lrucache import LRUCache
from .storelocking import Lock
from .logger import create_logger
from .manifest import NoManifestError
from .repoobj import RepoObj, OBJ_MAGIC
from .crypto.key import is_keyfile

logger = create_logger(__name__)

# an object name is its sha256 as 64 lowercase hex digits.
_valid_object_name = re.compile(r"[0-9a-f]{64}").fullmatch


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
    remote_path = replace_placeholders(os.environ.get("BORG_REMOTE_PATH", "borg"))
    return ssh_cmd(location.user, location.host, location.port) + [
        remote_path,
        "serve",
        "--rest",
        "--backend",
        backend_arg,
    ]


def propagate_rsh():
    """Give borgstore the remote shell command borg uses.

    borg has BORG_RSH, borgstore has its own BORGSTORE_RSH - if only the borg one is set,
    borgstore shall use it, too. An explicitly set BORGSTORE_RSH always wins.
    """
    borg_rsh = os.environ.get("BORG_RSH")
    if borg_rsh and not os.environ.get("BORGSTORE_RSH"):
        os.environ["BORGSTORE_RSH"] = borg_rsh


def build_rest_backend(location):
    """Return a borgstore REST backend for a rest:// *location*, served by "borg serve --rest"."""
    return REST(base_url="http://stdio-backend", command=rest_serve_command(location))


class PackWriter:
    """Buffers chunks into a pack file and writes it to the store when full.

    add() buffers a (chunk_id, cdata) pair and marks the chunk pending (F_PENDING);
    when the pack is full, it is built, hashed and stored, and each entry's pack_id,
    obj_offset and obj_size are set, clearing F_PENDING.

    With async_store (the default), a full pack is handed to a background store-thread
    (at most one in flight), so the caller can assemble the next pack while the previous
    one is hashed and stored (#9988).  The ChunkIndex is only ever touched by the calling
    thread: the store-thread's results (or error) are applied when it is joined, at the
    next pack boundary or flush().  Consequently, add() returns the *previous* pack's
    results while the current pack's store is in flight, and a store error surfaces one
    pack later, from whichever add()/flush() call joins the store-thread.

    flush() is a barrier: it joins an in-flight store and writes the current buffer
    synchronously, so afterwards nothing is buffered or in flight and no chunk written
    through this writer is F_PENDING anymore.

    The ChunkIndex comes from the repository, or from an explicit chunks index when
    there is no repository (see the chunks property).

    max_count bounds how many chunks a pack holds; max_size bounds its byte size.
    A pack is written when either limit is reached.  Set a limit to None to disable it;
    at least one must be set, otherwise the pack buffer is unbounded.
    """

    class _Outcome:
        """What one pack store produced: filled in by _store_pieces, applied by _apply_outcome."""

        def __init__(self, pending_ids):
            self.pending_ids = pending_ids  # chunk ids to drop from the index if the store fails
            self.results = None  # list of (chunk_id, pack_id, obj_offset, obj_size) on success
            self.error = None  # the store exception on failure

    def __init__(self, store, *, max_count=None, max_size=None, chunks=None, repository=None, async_store=True):
        if repository is None and chunks is None:
            raise ValueError("PackWriter requires either a repository or an explicit chunks index")
        if max_count is None and max_size is None:
            raise ValueError("PackWriter needs max_count or max_size, otherwise the pack buffer is unbounded")
        self.store = store
        self.max_count = max_count  # None = no count limit
        self.max_size = max_size  # None = no size limit
        self.repository = repository
        self.async_store = async_store
        # BORG_PACK_TRACE=yes prints store-thread lifecycle markers to stderr, see _trace.
        self.trace_store = os.environ.get("BORG_PACK_TRACE", "no") == "yes"
        self._chunks = chunks  # used when there is no repository
        self._pieces = []  # list of (chunk_id, cdata)
        self._size = 0  # byte size of buffered pieces
        self._inflight = None  # (thread, outcome) of the pack store-thread, at most one in flight

    @property
    def chunks(self):
        """The ChunkIndex this writer updates: the repository's index, or the
        explicit index passed at construction when there is no repository."""
        if self.repository is not None:
            return self.repository.chunks
        return self._chunks

    def add(self, chunk_id, cdata):
        """Buffer a chunk.

        When the chunk fills the pack, the pack is written and the results of the
        *previously* written pack (with async_store) or of this pack (without) are
        returned as a list of (chunk_id, pack_id, obj_offset, obj_size) tuples.
        Returns None when there is nothing to report.
        """
        self.chunks.add(chunk_id, 0)  # size: plaintext chunk size, set by the cache layer
        self._pieces.append((chunk_id, cdata))
        self._size += len(cdata)
        if (self.max_count is not None and len(self._pieces) >= self.max_count) or (
            self.max_size is not None and self._size >= self.max_size
        ):
            if self.async_store:
                results = self.join_inflight()  # apply the previous pack's store, or raise its error
                self._handoff()  # current pack -> background store-thread
                return results
            return self.flush()
        return None

    def _take_pieces(self):
        """Take the buffered pieces, leaving an empty buffer."""
        pieces, self._pieces, self._size = self._pieces, [], 0
        return pieces

    @staticmethod
    def _trace(char, trace):
        """Emit one lifecycle marker of the background store-thread to stderr:
        < thread started, H hashing starts, S storing starts, > thread finished.
        Only active with BORG_PACK_TRACE=yes (debugging aid: visualizes how pack
        stores overlap with the assembly of the next pack, #9988)."""
        if trace:
            sys.stderr.write(char)
            sys.stderr.flush()

    def _store_pieces(self, pieces, outcome, trace=False):
        """Build, hash and store one pack; record the results or the error in *outcome*.

        Runs in the store-thread (async, trace=True) or inline in the calling thread
        (sync/flush).  Touches only the store (borgstore >= 0.6 serializes all Store
        operations internally, see borgstore #206), never the ChunkIndex.
        """
        self._trace("<", trace)
        try:
            # Build the pack bytes once by joining all pieces (avoids O(n^2) copies
            # that incremental string concatenation would cause in Python).
            pack_data = b"".join(cdata for _, cdata in pieces)

            # Name the pack by the SHA-256 of its bytes: the name commits to the stored content,
            # so borgstore can verify and cache the file.
            self._trace("H", trace)
            pack_id = sha256(pack_data).digest()

            # Record (chunk_id, pack_id, obj_offset, obj_size) for every piece.
            results = []
            offset = 0
            for chunk_id, cdata in pieces:
                obj_size = len(cdata)
                results.append((chunk_id, pack_id, offset, obj_size))
                offset += obj_size

            self._trace("S", trace)
            self.store.store("packs/" + bin_to_hex(pack_id), pack_data)
        except BaseException as exc:  # incl. KeyboardInterrupt: it must not vanish with the thread
            outcome.error = exc
        else:
            outcome.results = results
        finally:
            self._trace(">", trace)

    def _apply_outcome(self, outcome):
        """Apply one finished pack store to the ChunkIndex (calling thread only).

        On success, set the real pack locations (clearing F_PENDING) and return the results;
        on failure, drop the failed pack's index entries and raise the store error.
        """
        if outcome.error is not None:
            # the pack was not stored: drop the index entries for its chunks.
            for chunk_id in outcome.pending_ids:
                if chunk_id in self.chunks:  # a chunk_id may appear more than once in this pack
                    del self.chunks[chunk_id]
            raise outcome.error
        self.chunks.update_pack_info(outcome.results)  # set the real location and clear F_PENDING
        return outcome.results

    def _handoff(self):
        """Hand the buffered pieces to a background store-thread (at most one in flight)."""
        assert self._inflight is None, "join_inflight() must run before handing off another pack"
        pieces = self._take_pieces()
        outcome = self._Outcome([chunk_id for chunk_id, _ in pieces])
        # daemon: normally irrelevant, because flush() and close() always join the thread
        # (also while unwinding a Ctrl-C), so it is never still running at interpreter
        # shutdown.  it is a safety net for the pathological case of a store that hangs
        # (e.g. a dead sftp/rest connection without timeout) on a path that never joins:
        # exiting then beats hanging forever in threading._shutdown.  losing an unjoined
        # store costs nothing: its index entries are only applied at the join, and all
        # backends write to a temp name + rename (or have the server verify a content
        # hash), so an aborted store can leave garbage, but never a corrupt pack.
        thread = threading.Thread(
            target=self._store_pieces,
            args=(pieces, outcome),
            kwargs=dict(trace=self.trace_store),
            name="borg-pack-store",
            daemon=True,
        )
        self._inflight = (thread, outcome)
        thread.start()

    def _drop_buffered(self):
        """Drop the buffered pieces and their (still pending) index entries.

        Called when a pack store failed: the caller is aborting, so chunks not yet handed
        to the store die with it.  Dropping their entries keeps the index free of F_PENDING
        leftovers, like the sync store path does, so the close()-time index persist works.
        """
        pieces = self._take_pieces()
        for chunk_id, _ in pieces:
            if chunk_id in self.chunks:  # a chunk_id may appear more than once in the buffer
                del self.chunks[chunk_id]

    def join_inflight(self):
        """Wait for an in-flight pack store and apply it to the index.

        Returns its results, None when nothing was in flight.  If the store failed, the
        writer is emptied (see _drop_buffered) and the store error is raised.
        """
        if self._inflight is None:
            return None
        thread, outcome = self._inflight
        thread.join()
        self._inflight = None
        try:
            return self._apply_outcome(outcome)
        except BaseException:
            self._drop_buffered()
            raise

    def flush(self):
        """Write the current pack to the store.  This is a barrier: any in-flight store
        is joined first and the current buffer is written synchronously, so afterwards
        no chunk written through this writer is F_PENDING anymore.

        Returns a list of (chunk_id, pack_id, obj_offset, obj_size) tuples covering
        every chunk written by this flush (including a joined in-flight pack), or
        None if there was nothing to do.
        """
        results = self.join_inflight() or []
        if self._pieces:
            pieces = self._take_pieces()
            outcome = self._Outcome([chunk_id for chunk_id, _ in pieces])
            self._store_pieces(pieces, outcome)
            results += self._apply_outcome(outcome)
        return results or None


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
        # in-memory pack: return a memoryview into pack_contents. store: range-read bytes.
        if self.pack_contents is not None:
            return memoryview(self.pack_contents)[offset : offset + size]
        return self.store.load(self.key, offset=offset, size=size)

    def size(self):
        """Return the pack size in bytes; for a store-backed pack this is one metadata lookup."""
        if self.pack_contents is not None:
            return len(self.pack_contents)
        return self.store.info(self.key).size

    def iter_headers(self):
        """Yield (chunk_id, offset, size) for each object by walking the fixed object headers.

        Only the headers are read, not the payloads, so locating every object costs one short
        range read per object (or just a slice, when the pack is already in memory), plus one
        store metadata lookup for the pack size.

        Each full header must have OBJ_MAGIC and describe an object that fits into the pack,
        otherwise the pack is corrupt and IntegrityError is raised. Ending the walk instead
        would be worse than raising: the chunks index rebuilt from these headers would just be
        missing the rest of the pack, and borg check --repair would then "fix" the archives by
        dropping chunks that are there.
        A trailing partial header is the clean end of the pack, not corruption.
        """
        pack_hex = bin_to_hex(self.pack_id) if self.pack_id is not None else "<no id>"
        pack_size = self.size()
        hdr_size = RepoObj.obj_header.size
        offset = 0
        while True:
            hdr_data = self.read(offset, hdr_size)
            if len(hdr_data) < hdr_size:
                break  # clean EOF, or trailing partial bytes
            hdr = RepoObj.ObjHeader(*RepoObj.obj_header.unpack(hdr_data))
            if hdr.magic != OBJ_MAGIC:
                raise IntegrityError(
                    f'pack {pack_hex}: no object header at offset {offset} (pack corruption), run "borg check"'
                )
            obj_size = hdr_size + hdr.meta_size + hdr.data_size
            if offset + obj_size > pack_size:
                raise IntegrityError(
                    f"pack {pack_hex}: object extends past end of file at offset {offset} "
                    f'(pack corruption), run "borg check"'
                )
            yield hdr.chunk_id, offset, obj_size
            offset += obj_size


def check_pack_objects(pack_hex, obj_ranges, pack_size):
    """Validate a pack's indexed objects against the pack's file size.

    obj_ranges: the offset-ordered (obj_offset, obj_size) ranges of the pack's indexed objects.
    An overlap between objects, or an object claiming to end past the pack file (pack_size bytes),
    means index corruption and raises IntegrityError.
    """
    covered = 0
    for offset, size in obj_ranges:
        if offset < covered:
            raise IntegrityError(
                f'pack {pack_hex}: overlapping objects at offset {offset} (index corruption), run "borg check"'
            )
        covered = offset + size
    if covered > pack_size:
        raise IntegrityError(
            f'pack {pack_hex}: object extends past end of file at offset {covered} (index corruption), run "borg check"'
        )


def superseded_gap_ranges(reader, chunks, pack_id, obj_ranges, pack_size):
    """Find the superseded duplicates among a pack's gap bytes (bytes no index entry covers).

    A gap holds a chunk copy stored again elsewhere, or objects from a backup that crashed before
    writing its index. Walk each gap's object headers: an object whose chunk id the index maps to a
    different location is a superseded duplicate (the id is a keyed MAC of the plaintext, so equal
    ids mean equal content) and its bytes are redundant. An object whose id is not in the index
    (borg check --repair re-indexes it) or whose entry points back at this offset (its only copy)
    is not reported. A header that does not parse or overruns its gap ends the walk over that gap.

    obj_ranges: the offset-ordered, validated (obj_offset, obj_size) ranges of the pack's indexed
    objects; the gaps are the byte ranges between (and after) them.
    Returns the offset-ordered list of (offset, size) ranges holding superseded duplicates.
    """
    # find the gaps: byte ranges no indexed object covers.
    gaps = []  # (start, end) of each gap, offset-ordered
    cursor = 0
    for offset, size in obj_ranges:
        if offset > cursor:
            gaps.append((cursor, offset))
        cursor = offset + size
    if cursor < pack_size:
        gaps.append((cursor, pack_size))

    drop_ranges = []  # (obj_offset, obj_size) of superseded duplicates, offset-ordered
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
    return drop_ranges


class PackTracker:
    """Pack verification results, mapping pack_id -> (timestamp, result).

    Records are kept across checks: intact records (result=1) are reused by checks run with
    max_age, corrupt records (result=0) are kept for repair and always re-verified. Records of
    packs no longer listed in packs/ are pruned when a check finishes scanning packs/.
    Stored at cache/checked-packs as the serialized table with a sha256 over it appended.
    new() starts an empty tracker, load() reads the stored one.
    """

    NAME = "cache/checked-packs"
    KEY_SIZE = 32  # pack id
    DIGEST_SIZE = 32  # sha256
    Entry = namedtuple("Entry", "timestamp result")
    EntryFormatT = namedtuple("EntryFormatT", "timestamp result")
    _EntryFormat = EntryFormatT(timestamp="Q", result="B")  # unix ts, 1=ok 0=corrupt

    def __init__(self, store, table):
        self.store = store
        self.table = table

    @classmethod
    def new(cls, store):
        """Return a tracker with an empty table."""
        table = HashTableNT(key_size=cls.KEY_SIZE, value_type=cls.Entry, value_format=cls._EntryFormat)
        return cls(store, table)

    @classmethod
    def load(cls, store):
        """Return a tracker holding the stored table.

        Return an empty one if cache/checked-packs is missing, its appended sha256 does not match,
        it does not deserialize, or its entries do not have this class's key size and Entry layout.
        """
        try:
            data = store.load(cls.NAME)
        except StoreObjectNotFound:
            return cls.new(store)
        if len(data) < cls.DIGEST_SIZE or sha256(data[: -cls.DIGEST_SIZE]).digest() != data[-cls.DIGEST_SIZE :]:
            logger.warning("Ignoring corrupted checked-packs set.")
            return cls.new(store)
        try:
            with io.BytesIO(data[: -cls.DIGEST_SIZE]) as f:
                table = HashTableNT.read(f)
        except ValueError:
            logger.warning("Ignoring unreadable checked-packs set.")
            return cls.new(store)
        # read() takes key size and value type from the blob itself, so the table needs a layout check
        # against Entry here. All entries in a table share one layout, so checking one entry suffices.
        sample = next(iter(table.items()), None)
        if sample is not None:
            key, value = sample
            if len(key) != cls.KEY_SIZE or value._fields != cls.Entry._fields:
                logger.warning("Ignoring checked-packs set with an unexpected layout.")
                return cls.new(store)
        return cls(store, table)

    def __len__(self):
        return len(self.table)

    def get(self, pack_id):
        """Return the Entry for pack_id, or None if it is not recorded."""
        return self.table.get(pack_id)

    def record(self, pack_id, ok):
        self.table[pack_id] = self.Entry(timestamp=int(time.time()), result=int(ok))

    def corrupt_ids(self):
        """Return the ids of the packs recorded corrupt, sorted."""
        return sorted(pack_id for pack_id, entry in self.table.items() if not entry.result)

    def prune(self, pack_ids):
        """Drop the records whose pack id is not in pack_ids (the set of pack ids listed in packs/),
        then store the remaining records (or delete the stored object if none remain).
        """
        # the keys are collected first because the table must not be mutated while iterating it.
        for pack_id in [pack_id for pack_id, _ in self.table.items() if pack_id not in pack_ids]:
            del self.table[pack_id]
        if len(self.table):
            self.save()
        else:
            self.clear()

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

        propagate_rsh()  # borgstore shall use the same remote shell command as borg

        try:
            if location.proto == "rest":
                # rest:// is served by "borg serve --rest" (reachable via ssh if a host is given),
                # talking HTTP over stdio - rather than borgstore's own "borgstore-server-rest" command.
                # permissions are not given to the (remote) backend here; they are enforced on the
                # server side by "borg serve --rest --permissions ...".
                backend = build_rest_backend(location)
                # note: borgstore >= 0.6 Store serializes all its operations internally, so the
                # PackWriter store-thread and the main thread can share it (borgstore #206).
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
        # BORG_PACK_ASYNC=no disables the background store-thread (debugging aid, see PackWriter).
        async_store = os.environ.get("BORG_PACK_ASYNC", "yes") != "no"
        self._pack_writer = PackWriter(
            self.store, repository=self, max_count=max_count, max_size=max_size, async_store=async_store
        )
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
            try:
                # normally a no-op: flush() is a barrier and runs before close().  when close() runs
                # while unwinding an error, a pack store may still be in flight: join it, so a stored
                # pack gets recorded in the index and a failed one gets its index entries dropped.
                self._pack_writer.join_inflight()
            except Exception as exc:
                # do not raise: we are closing, probably unwinding an error already; raising here
                # would just mask that original error.
                logger.warning("pack store failed during close: %s", exc)
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

    def check(self, repair=False, max_duration=0, max_age=0, repo_only=False):
        """Check repository consistency.

        packs/ and index/ objects are named by the sha256 of their content, so a pack or index file
        is intact iff store.hash(name) still equals name. The whole pack is hashed; the REST backend
        computes the hash server-side, so for it nothing is downloaded.

        The index is hashed first and the packs only if it is intact. The packs could be hashed even
        with a corrupt index, but a corrupt index already means the user has to repair it, and that
        rebuild re-reads every pack anyway - so a read-only check just stops and reports it instead of
        continuing. A read-only check never rebuilds the index: reading every pack to do so would be
        far too slow and expensive for a routine (e.g. cron) check. With repair=True and a corrupt
        index, and if every pack is intact, the index is rebuilt from the packs' object headers and
        persisted; on a full check the archives phase rebuilds and re-persists it afterwards, see
        ArchiveChecker.finish. Packs are verified by sha256, which is content-addressing rather than a
        MAC, so this rebuild detects accidental corruption but not tampering, refs #9901, #10026. If any
        pack is corrupt the index is left unchanged, refs #8572, #10026. Pack ids found corrupt are kept
        in cache/checked-packs, refs #9696.

        A pack recorded corrupt fails the check, also on a partial run that stops before re-reaching
        it. The record clears at the check that finds the pack intact again or gone (removed by
        compact; TODO: also when repair salvages and drops it, refs #8572); prune() does this from packs/.

        It also reports missing packs (refs #9898): pack ids the chunk index references but that are
        absent from packs/. The index is read from its fragments only and its referenced pack ids are
        compared with the packs present in the store. This cross-check runs before the pack loop, so
        max_duration bounds it and it runs on partial runs too. It is skipped, and the check still
        passes, when the index cannot be read from its fragments (an invalid index is regenerated from
        the packs on next use, so it can never reference a missing pack; a pack that is truly gone then
        surfaces as missing chunks in the archives check).

        max_age (seconds, 0 = verify every pack): skip packs whose intact record is younger than
        max_age, accepting a future timestamp up to MAX_CLOCK_SKEW (clock skew). Results are recorded
        regardless of max_age.

        repo_only: whether this is a repository-only run. In repair mode it sets the return value for a
        corrupt pack, which repair does not fix: fail if repo_only, else defer (a full check's archives
        phase can repair a corrupt pack holding metadata, or file content with --verify-data).
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
        tracker = PackTracker.load(self.store)
        if not len(tracker):
            logger.info("Starting from beginning.")
        elif max_age:
            logger.info(f"{len(tracker)} pack check results on record, reusing those younger than --max-age.")
        elif partial:
            logger.info(
                f"{len(tracker)} pack check results on record, verifying the least-recently-checked packs first."
            )
        else:
            logger.info(f"{len(tracker)} pack check results on record, verifying every pack.")
        t_start = time.monotonic()
        t_last_checkpoint = t_start
        index_files = index_errors = 0
        pack_files = pack_errors = pack_skipped = 0
        missing_pack_ids = []  # packs referenced by the index but absent from packs/ (refs #9898)
        index_repaired = False
        packs_scanned = False
        # index and packs get separate progress indicators, each running from 0% to 100%.
        # the index is checked first and in full, on partial checks too: it is small, and index errors
        # stop the pack check below.
        index_infos = store_list("index")
        # an interrupted fragment deletion leaves the invalid marker set; the index is rebuilt on next
        # use, so warn rather than fail.
        from .cache import chunkindex_is_invalid, build_chunkindex_from_repo

        index_invalid = chunkindex_is_invalid(self)
        if index_invalid:
            logger.warning("chunk index is invalid (interrupted operation); it will be rebuilt on next use.")
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
        if index_errors == 0 or repair:
            # verify the packs; during repair, rebuild the corrupt index from them afterwards.
            # --repair forbids --max-duration and --max-age, so the partial and max_age handling in
            # the loop stays inactive during a repair.
            packs_scanned = True
            if index_errors:
                logger.warning("Repository index is corrupted; verifying all packs before rebuilding it from them.")
            # packs are the bulk of the work and the part --max-duration spreads over several checks.
            pack_infos = store_list("packs")
            # drop objects whose name is not a valid pack name and count them as errors; the code
            # below decodes each name via hex_to_bin, which only accepts valid names.
            valid_pack_infos = []
            for info in pack_infos:
                if _valid_object_name(info.name):
                    valid_pack_infos.append(info)
                else:
                    logger.error(f"Store object packs/{info.name} has an invalid name.")
                    pack_errors += 1
            pack_infos = valid_pack_infos
            present_pack_ids = {hex_to_bin(info.name) for info in pack_infos}
            # cross-check the chunk index against packs/ to find referenced-but-absent packs (refs #9898).
            # run before the pack loop so max_duration bounds it and partial checks cover it too. read
            # the index from its fragments only: a full rebuild reads every pack (too slow) and writes
            # to the repo (a check must not).
            if not index_invalid and not sig_int:
                chunks = build_chunkindex_from_repo(self, fragments_only=True)
                if chunks is None:
                    logger.warning(
                        "Cannot cross-check packs against the chunk index: the index could not be loaded "
                        "from its fragments; skipping missing-pack detection."
                    )
                else:
                    referenced_pack_ids = {
                        entry.pack_id
                        for _, entry in chunks.iteritems()
                        # F_PENDING marks a chunk whose pack location is unresolved, so its pack_id
                        # is a placeholder rather than a real pack; skip such entries.
                        if not (entry.flags & ChunkIndex.F_PENDING)
                    }
                    # set the session chunk index (.chunks) so later reads reuse it; clear_new() has
                    # run, so close() does not write it back.
                    self.chunks = chunks
                    # index entries pointing to a pack absent from packs/: data loss.
                    missing_pack_ids = sorted(referenced_pack_ids - present_pack_ids)
                    # packs no index entry references: not an error, so info + ids at debug only.
                    orphan_pack_ids = sorted(present_pack_ids - referenced_pack_ids)
                    if orphan_pack_ids:
                        logger.info(f"{len(orphan_pack_ids)} pack(s) are not referenced by the index.")
                        for pack_id in orphan_pack_ids:
                            logger.debug(f"Orphan pack: {bin_to_hex(pack_id)}")
            if partial:
                # a partial check stops after max_duration; verify the least-recently-checked packs
                # first so repeated runs cover every pack. sort by recorded check time, unrecorded
                # (time 0) first.
                def recorded_ts(info):
                    entry = tracker.get(hex_to_bin(info.name))
                    return entry.timestamp if entry is not None else 0

                pack_infos.sort(key=recorded_ts)
            pack_pi = ProgressIndicatorPercent(total=len(pack_infos), msg="Checking packs %3.0f%%", msgid="check.packs")
            for info in pack_infos:
                if sig_int:  # on Ctrl-C, stop; tracker.prune() below persists the records past the loop
                    logger.info(f"Interrupted repository check, {pack_files} packs checked so far.")
                    break
                self._lock_refresh()
                pack_pi.show(increase=1)  # advance for skipped packs too, so the bar tracks packs/, not work done
                pack_id = hex_to_bin(info.name)
                entry = tracker.get(pack_id)
                # skip a pack recorded intact within the last max_age seconds. the timestamp is set
                # by the client that ran the earlier check; accept a future one (negative age) up to
                # MAX_CLOCK_SKEW, and re-verify anything at or past max_age.
                if entry is not None and entry.result and max_age:
                    age = time.time() - entry.timestamp
                    if -min(MAX_CLOCK_SKEW, max_age) <= age < max_age:
                        pack_skipped += 1
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
                    logger.info(f"Finished partial repository check, {len(tracker)} pack check results on record.")
                    break
            else:
                if pack_infos:
                    pack_pi.show(current=len(pack_infos))  # finish at 100%
                logger.info("Finished checking packs.")
            tracker.prune(present_pack_ids)
            pack_pi.finish()
            # rebuild only if the index was the sole problem and every pack was verified intact this
            # run: sig_int breaks the loop early, so "no pack errors" must be paired with "all packs
            # scanned" (pack_files == len(pack_infos)) to not rebuild from unverified packs.
            if index_errors and pack_errors == 0 and not sig_int and pack_files == len(pack_infos):
                from .cache import build_chunkindex_from_repo

                # the exclusive check lock keeps the pack set fixed, so re-listing packs/ inside
                # build_chunkindex_from_repo matches this verification. write_immediately persists the
                # index and drops the corrupt fragments.
                build_chunkindex_from_repo(self, slow_rebuild=True, write_immediately=True)
                self.invalidate_chunk_index()  # the rebuilt index is persisted; drop the in-memory copy
                index_repaired = True
        else:
            logger.error("Repository index is corrupted and must be repaired; skipping the pack check.")
        objs_errors = index_errors + pack_errors + len(missing_pack_ids)
        summary = (
            f"Checked {index_files} index files ({index_errors} errors) "
            f"and {pack_files} packs ({pack_errors} errors)."
        )
        if pack_skipped:
            summary += f" Reused {pack_skipped} recent pack check result(s)."
        logger.info(summary)
        if missing_pack_ids:
            # one id per line (the list can be long).
            logger.error(f"{len(missing_pack_ids)} pack(s) referenced by the index are missing:")
            for pack_id in missing_pack_ids:
                logger.error(f"Missing pack: {bin_to_hex(pack_id)}")
            logger.error(
                "The chunks stored in these packs are lost. Repairing the index (dropping the "
                "stale references) is tracked in https://github.com/borgbackup/borg/issues/8572."
            )
        if index_repaired:
            logger.info("Repository index was corrupted and has been rebuilt from the packs.")
        # corrupt_ids() includes packs recorded corrupt in earlier runs; report them only when this
        # run scanned the packs.
        corrupt_ids = tracker.corrupt_ids() if packs_scanned else []
        if corrupt_ids:
            # one id per line, the list can be long.
            logger.error(f"Found {len(corrupt_ids)} corrupt pack(s):")
            for pack_id in corrupt_ids:
                logger.error(f"Corrupt pack: {bin_to_hex(pack_id)}")
        # fail if this run found errors, or any pack is recorded corrupt.
        problems = objs_errors != 0 or bool(corrupt_ids)
        # On Ctrl-C the check stopped early, so the summary only covers the packs seen so far.
        done, so_far = ("Interrupted", " so far") if sig_int else ("Finished", "")
        if not problems:
            logger.info(f"{done} {mode} repository check, no problems found{so_far}.")
        elif not repair:
            logger.error(f"{done} {mode} repository check, errors found{so_far}.")
        elif index_repaired and not (pack_errors or corrupt_ids):
            # the index was the only problem and it has been rebuilt from the packs.
            logger.info(f"{done} {mode} repository check, repaired{so_far}.")
        elif pack_errors or corrupt_ids:
            if repo_only:
                logger.error(
                    f"{done} {mode} repository check, corrupt pack(s) found{so_far}; repairing a repository "
                    "with corrupt packs is not implemented yet (refs #8572)."
                )
            else:
                # a full check's archives phase reads archive/item metadata (and file content with
                # --verify-data), so it repairs a corrupt pack holding such objects; warn rather than fail.
                logger.warning(f"{done} {mode} repository check, corrupt pack(s) found{so_far}.")
        else:
            # the index is corrupt but was not rebuilt, e.g. the pack verification was interrupted
            # before every pack was confirmed intact; the corrupt index is left in place.
            logger.error(f"{done} {mode} repository check, index still corrupt{so_far}.")
        # in repair mode a corrupt index left unrebuilt is a failure; a corrupt pack fails only a
        # repository-only run, while a full check defers it to the archives phase.
        if repair:
            if index_errors and not index_repaired:
                return False
            return not (repo_only and (pack_errors or corrupt_ids))
        return not problems

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
                continue  # buffered in PackWriter (or its store still in flight), not read-able yet
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
            # the chunk may be in a pack whose background store is still in flight:
            # join it, which resolves the chunk's pack location (read barrier).
            self._pack_writer.join_inflight()
            entry = self.chunks.get(id)  # re-fetch, the join updated the entry
        if entry is None or self.chunks.is_pending(id):
            # still pending: buffered but not flushed; a chunk must be flushed before any read, so this
            # is a code bug (wrong flush/index ordering), not a missing object: raise regardless of
            # raise_missing.  entry None: the join failed sometime earlier and dropped the entry.
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
                # hdr, meta are memoryviews for an in-memory pack; return them concatenated as bytes.
                return bytes(hdr) + bytes(meta)
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
        triggers a pack write, returns a list of (chunk_id, pack_id, obj_offset, obj_size)
        tuples, one per written chunk; otherwise returns None.  With the background
        store-thread (see PackWriter), the returned tuples are those of the *previous*
        pack, whose store was joined before handing off the current one.
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

        # validate the listed objects. an overlap is index corruption; so is an object ending past
        # the pack file: store.defrag would short-read it into a truncated object in the new pack,
        # then the intact source pack is deleted.
        pack_size = self.store.info(pack_key).size
        obj_ranges = [(offset, size) for offset, _, size, _ in located]
        check_pack_objects(bin_to_hex(pack_id), obj_ranges, pack_size)

        # record the dropped objects' byte ranges; every other byte (kept objects and gaps that no
        # index entry covers) is copied into the new pack unchanged. superseded duplicates found in
        # the gaps are dropped along with them (see superseded_gap_ranges).
        # TODO(#9868 follow-up): classify gaps in compact_packs pass 1 too, so superseded bytes count
        # toward the rewrite threshold and a wholly superseded orphan pack can be dropped outright.
        drop_ranges = [(offset, size) for offset, _, size, keep in located if not keep]
        reader = PackReader(store=self.store, pack_id=pack_id)
        drop_ranges += superseded_gap_ranges(reader, chunks, pack_id, obj_ranges, pack_size)
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
            check_pack_objects(bin_to_hex(pid), ((offset, size) for offset, _, size in per_pack[pid]), pack_size[pid])

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

    def transform_pack(self, pack_id, ids, transform, *, chunks=None, before_change=None):
        """Rewrite pack <pack_id>, passing each indexed object's bytes through <transform>.

        ids: the chunk ids of this pack's objects. Must cover every object the chunk index lists
            for this pack (same contract as compact_pack's keep_ids/drop_ids): an unlisted indexed
            object would keep its bytes in the new pack, but its index entry would go stale when
            the old pack is deleted.
        transform: called as transform(chunk_id, obj_bytes) with an object's stored bytes; returns
            the replacement bytes, or obj_bytes itself (the identical bytes object) to keep the
            object unchanged. The chunk id (and thus the plaintext) must not change; sizes may.
        chunks: the ChunkIndex to look up the objects' pack locations in and to apply the index
            updates to. Must be the index <ids> was derived from. Default: self.chunks.
        before_change: called once, just before the first store modification; use it to invalidate
            stored chunk indexes for crash safety (see #9748). Not called when the pack is kept.

        The whole pack file is loaded into memory (bounded by the pack size limit). Gap bytes
        (bytes no index entry covers) are handled like in compact_pack: an object superseded by a
        copy stored elsewhere is dropped, all other unindexed bytes are copied into the new pack
        unchanged, to be handled by "borg check --repair". An overlap between indexed objects, or
        an object claiming to end past the pack file, means index corruption and raises
        IntegrityError, before anything is written.

        If every object is kept and no gap bytes are dropped, the store and the chunk index are not
        touched at all. Otherwise the new pack (named sha256 of its content) is stored, the indexed
        objects are repointed at it, and the old pack is deleted last, so the objects' bytes are
        never the only copy.

        Returns (new_pack_id, new_size): the rewritten pack's id and byte size, or
        (pack_id, <old size>) when the pack was kept unchanged.

        Updates the in-memory chunk index only; the caller holds the exclusive lock and writes the
        index back to the store afterwards.
        """
        self._lock_refresh()
        if chunks is None:
            chunks = self.chunks
        pack_hex = bin_to_hex(pack_id)
        pack_key = "packs/" + pack_hex

        pack_contents = self.store.load(pack_key)
        pack_size = len(pack_contents)
        reader = PackReader(pack_id=pack_id, pack_contents=pack_contents)

        # collect the listed objects' ranges, ordered by offset, and validate them (see docstring).
        located = []  # (obj_offset, obj_id, obj_size)
        for obj_id in ids:
            entry = chunks[obj_id]
            assert entry.pack_id == pack_id, f"{bin_to_hex(obj_id)} is not in pack {pack_hex}"
            located.append((entry.obj_offset, obj_id, entry.obj_size))
        located.sort()
        obj_ranges = [(offset, size) for offset, _, size in located]
        check_pack_objects(pack_hex, obj_ranges, pack_size)
        drop_ranges = superseded_gap_ranges(reader, chunks, pack_id, obj_ranges, pack_size)

        # assemble the new pack in offset order: transformed objects, dropped ranges skipped, all
        # other bytes copied verbatim. the two range lists never overlap (drops lie in gaps), so a
        # single offset-sorted walk over both handles the interleaving.
        events = [(offset, size, obj_id) for offset, obj_id, size in located]
        events += [(offset, size, None) for offset, size in drop_ranges]  # None: a range to drop
        events.sort(key=lambda event: event[0])
        pieces = []  # byte spans of the new pack, in order
        new_locations = []  # (obj_id, new_offset, new_size) of each object
        changed = bool(drop_ranges)
        cursor = 0  # position in the old pack
        new_offset = 0  # position in the new pack
        for offset, size, obj_id in events:
            if offset > cursor:  # verbatim span (gap bytes) before this event
                pieces.append(pack_contents[cursor:offset])
                new_offset += offset - cursor
            if obj_id is not None:
                obj_bytes = pack_contents[offset : offset + size]
                new_bytes = transform(obj_id, obj_bytes)
                if new_bytes is not obj_bytes:
                    changed = True
                pieces.append(new_bytes)
                new_locations.append((obj_id, new_offset, len(new_bytes)))
                new_offset += len(new_bytes)
            # else: a dropped range, skip its bytes
            cursor = offset + size
        if cursor < pack_size:  # verbatim span after the last event
            pieces.append(pack_contents[cursor:])

        if not changed:
            return pack_id, pack_size
        pack_data = b"".join(pieces)
        new_pack_id = sha256(pack_data).digest()
        if new_pack_id == pack_id:  # the transforms reproduced the pack byte-identically
            return pack_id, pack_size

        if before_change is not None:
            before_change()
        # store the new pack before touching the index or the old pack, so a failure leaves
        # everything unchanged.
        self.store.store("packs/" + bin_to_hex(new_pack_id), pack_data)
        chunks.update_pack_info([(obj_id, new_pack_id, offset, size) for obj_id, offset, size in new_locations])
        # delete the old pack last, after the new one is stored and indexed, so the objects' bytes
        # are never the only copy.
        self.store_delete(pack_key)
        return new_pack_id, len(pack_data)

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

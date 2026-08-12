"""
The read-only "archive as a file system" implementation, shared by all its users.

borg presents archive contents as a browsable directory tree in several places:

- ``borg mount`` via mfusepy (high-level FUSE 2/3), see hlfuse.py
- ``borg mount`` via llfuse / pyfuse3 (low-level FUSE 2/3), see fuse.py
- ``borg webdav`` (WebDAV / HTTP server), see webdav.py

They all need the same thing: build a directory tree from the items of the selected
archives, map borg item metadata to file attributes and read file content out of the
chunk lists. That is what this module does - the modules above are thin protocol
adapters over it, so "what an archive looks like as a file system" is defined here
and only here.

Threading: an ArchiveVFS is not thread-safe by itself. Users that access it from
multiple threads (webdav) pass a lock; all repository access (building an archive's
tree, fetching chunks) happens while holding it, because borgstore connections are
not thread-safe. The lock is also used to keep the repository lock refresher off the
repository while a request is being served, see storelocking.LockRefresher.
"""

import hashlib
import os
import stat
import threading
import time
import unicodedata
from collections import Counter
from typing import NamedTuple

from .archive import Archive, DownloadPipeline, get_item_uid_gid
from .constants import ROBJ_FILE_STREAM
from .hashindex import FuseVersionsIndex
from .helpers import Error, bin_to_hex, format_file_size, remove_surrogates
from .helpers import msgpack
from .helpers.lrucache import LRUCache
from .item import ChunkListEntry, Item
from .logger import create_logger
from .platform import acl_text_to_xattr, uid2user, gid2group
from .platformflags import is_darwin, is_linux, is_win32

logger = create_logger()

# on Linux, the kernel exposes POSIX ACLs via these special, binary encoded xattrs.
# maps the xattr name to the borg item attribute holding the ACL text.
# empty on platforms we can not do this for, so the mount just does not offer these xattrs there.
ACL_XATTRS = {b"system.posix_acl_access": "acl_access", b"system.posix_acl_default": "acl_default"} if is_linux else {}

DEFAULT_DIR_MODE = 0o40755

# size of the cache of unpacked items (see ArchiveVFS.get_item).
# note: such an item can be rather large - Item.chunks can be a long list.
ITEM_CACHE_SIZE = 8


class ChunkMissing(Exception):
    """A chunk of a file's content is missing in the repository."""


class VFSOptions:
    """How the archive contents shall be presented; the defaults suit a plain, read-only view.

    *versions* merges all selected archives into one tree, showing each file as a
    directory that contains all its versions (see ArchiveVFS._load_archive).
    *numeric_ids*, *uid_forced*, *gid_forced* and *umask* control the ownership and
    permissions mapping, *strip_components* and *item_filter* which items are shown,
    *allow_damaged_files* whether reads of files with missing chunks return zeros
    instead of failing, and *dir_item* is the item used for synthesized directories.
    """

    def __init__(
        self,
        *,
        versions=False,
        numeric_ids=False,
        uid_forced=None,
        gid_forced=None,
        umask=0,
        allow_damaged_files=False,
        strip_components=0,
        item_filter=None,
        dir_item=None,
    ):
        self.versions = versions
        self.numeric_ids = numeric_ids
        self.uid_forced = uid_forced
        self.gid_forced = gid_forced
        self.umask = umask
        self.allow_damaged_files = allow_damaged_files
        self.strip_components = strip_components
        self.item_filter = item_filter
        self.dir_item = dir_item


class Attrs(NamedTuple):
    """The file attributes of a node, as far as an archived item defines them."""

    ino: int
    mode: int
    nlink: int
    uid: int
    gid: int
    rdev: int
    size: int
    mtime_ns: int
    atime_ns: int
    ctime_ns: int
    birthtime_ns: int


class VFSNode:
    """A node of the file system tree: a directory (children is a dict) or a leaf.

    A node only knows its place in the tree - the item metadata lives in ArchiveVFS,
    keyed by the inode number. Hard links to the same archived file are separate nodes
    sharing one inode number (and thus one item).
    """

    __slots__ = ("ino", "parent", "children", "nfc_names")

    def __init__(self, ino, parent=None, *, is_dir=False):
        self.ino = ino
        self.parent = parent
        self.children = {} if is_dir else None  # name (str) -> VFSNode
        self.nfc_names = None  # lazily built by ArchiveVFS.lookup(), see there

    @property
    def is_dir(self):
        return self.children is not None


def nfc(name):
    """NFC-normalize *name*; names with surrogates (non-UTF-8 bytes) pass through unchanged."""
    return unicodedata.normalize("NFC", name)


def item_listxattr(item):
    """Return the xattr names (bytes) of *item*."""
    names = list(item.get("xattrs", {}).keys())
    # expose the archived POSIX ACLs, so e.g. getfacl or tools copying from the mount can read them.
    names.extend(xattr_name for xattr_name, attr in ACL_XATTRS.items() if attr in item)
    return names


def item_getxattr(item, name, *, numeric_ids=False):
    """Return the value of xattr *name* (bytes) of *item*.

    Raises KeyError if the item does not have that xattr, ValueError if an archived
    ACL can not be converted to the binary xattr representation.
    """
    if name in ACL_XATTRS:
        acl = item.get(ACL_XATTRS[name])
        if acl is None:
            raise KeyError(name)
        return acl_text_to_xattr(acl, numeric_ids=numeric_ids)  # raises ValueError
    return item.get("xattrs", {})[name] or b""


def lookup_child(node, name):
    """Return (child_name, child_node) for *name* in directory *node*. Raises KeyError.

    An exact match always wins. If there is none, we retry comparing Unicode NFC forms:
    file systems disagree about normalization (macOS decomposes, so its clients ask for
    "gru<combining diaeresis>..." where the archive stores "grü..."), and an exact-only
    lookup would answer "not found" for a file the client just saw in a listing.

    The NFC index is built lazily (only for directories that actually get such a request)
    and skips names that are ambiguous, i.e. where several different names share one NFC
    form - those keep requiring an exact match, so we never silently serve the wrong file.
    """
    children = node.children
    if children is None:
        raise KeyError(name)  # not a directory
    try:
        return name, children[name]
    except KeyError:
        pass
    if node.nfc_names is None:
        index = {}
        for child_name in children:
            key = nfc(child_name)
            index[key] = None if key in index else child_name  # None marks an ambiguous key
        node.nfc_names = index
    child_name = node.nfc_names.get(nfc(name))
    if child_name is None:
        raise KeyError(name)
    return child_name, children[child_name]


def versioned_name(name, version):
    """Build the name a file has in the versions view, e.g. "file.00001.txt"."""
    # keep the original extension at the end, to avoid confusing tools
    name, ext = os.path.splitext(name)
    return f"{name}.{version:05d}{ext}"


class ArchiveVFS:
    """A read-only file system view of the archives selected by *args*.

    The root directory has one directory per (deduplicated) archive name; each of
    these archive trees is built when it is first accessed - building it means
    reading the whole item metadata stream of that archive, which takes a while for
    a big archive. In the versions view, the contents of all selected archives are
    merged into one tree instead, which is built completely upfront.

    Directories are addressable by inode number (get_node); everything else is
    reached by looking up names in a directory node (lookup / resolve).
    """

    def __init__(self, manifest, args, repository=None, *, lock=None, options=None):
        self.manifest = manifest
        self.repository = repository if repository is not None else manifest.repository
        self.args = args
        self.options = options if options is not None else VFSOptions()
        self.lock = lock if lock is not None else threading.RLock()
        self.pipeline = DownloadPipeline(self.repository, manifest.repo_objs)
        self.reader = DataReader(self.pipeline, lock=self.lock, allow_damaged_files=self.options.allow_damaged_files)
        # the ids of the mounting user are what items without a usable uid/gid fall back to.
        # note: borg webdav also runs on Windows, which has no uid/gid (nor os.getuid).
        self.default_uid = 0 if is_win32 else os.getuid()
        self.default_gid = 0 if is_win32 else os.getgid()
        self.archives = {}  # display name -> ArchiveInfo
        self.root_mtime = int(time.time() * 1e9)  # replaced by create_filesystem()
        self._ino_count = 0
        self._items = {}  # inode number -> msgpacked item (None -> options.dir_item)
        self._item_cache = LRUCache(capacity=ITEM_CACHE_SIZE)  # inode number -> Item
        self._nodes = {}  # inode number -> VFSNode, for directories only
        self._nlinks = {}  # inode number -> link count, for hard linked items only
        self._pending = {}  # VFSNode -> ArchiveInfo, archives whose tree is not built yet
        self._versions_index = None
        self.root = self._new_node(None, is_dir=True)
        assert self.root.ino == 1  # the root inode number is 1 by convention

    # -- setting up ---------------------------------------------------------------

    def create_filesystem(self):
        """Populate the root directory (this also selects the archives to be shown)."""
        archives = self.manifest.archives.list_considering(self.args)
        # archives of a series all have the same name, so make the display names unique
        name_counter = Counter(archive.name for archive in archives)
        for archive in archives:
            name = archive.name
            if name_counter[name] > 1:
                name += f"-{bin_to_hex(archive.id):.8}"
            self.archives[name] = archive
        timestamps = [archive.ts for archive in archives]
        self.root_mtime = int(max(timestamps).timestamp() * 1e9) if timestamps else int(time.time() * 1e9)
        self._set_item(self.root.ino, self._dir_item(self.root_mtime))
        if self.options.versions:
            # the versions view merges all archives into one tree, so there is nothing
            # to defer: build it now.
            self._versions_index = FuseVersionsIndex()
            for archive in self.archives.values():
                self._load_archive(archive, self.root)
        else:
            for name, archive in self.archives.items():
                node = self._new_node(self.root, is_dir=True)
                self._set_item(node.ino, self._dir_item(int(archive.ts.timestamp() * 1e9)))
                self.root.children[name] = node
                self._pending[node] = archive

    def _dir_item(self, mtime):
        """Return the item used for a synthesized directory, with mtime *mtime*."""
        item = Item(internal_dict=self._default_dir().as_dict())
        item.mtime = mtime
        return item

    def _default_dir(self):
        """The item used for all synthesized directories that keep the default mtime."""
        if self.options.dir_item is None:
            uid = self.options.uid_forced if self.options.uid_forced is not None else self.default_uid
            gid = self.options.gid_forced if self.options.gid_forced is not None else self.default_gid
            self.options.dir_item = Item(
                mode=DEFAULT_DIR_MODE & ~self.options.umask, mtime=int(time.time() * 1e9), uid=uid, gid=gid
            )
        return self.options.dir_item

    # -- building the tree --------------------------------------------------------

    def ensure_loaded(self, node):
        """Build the tree of an archive directory, if that did not happen yet."""
        if node not in self._pending:
            return  # not an archive directory, or its tree is complete
        with self.lock:
            archive = self._pending.get(node)
            if archive is None:
                return  # another thread built it while we waited for the lock
            self._load_archive(archive, node)
            # only now (with the tree complete) let other threads past the check above.
            del self._pending[node]

    def _load_archive(self, archive_info, root):
        """Add the items of one archive to the tree below *root*."""
        t0 = time.perf_counter()
        archive = Archive(self.manifest, archive_info.id)
        archive_mtime = int(archive_info.ts.timestamp() * 1e9)
        strip_components = self.options.strip_components
        versions = self.options.versions
        hardlinks = {}  # hlid -> node of the first item with that hlid
        for item in archive.iter_items(self.options.item_filter):
            if strip_components:
                item.path = os.sep.join(item.path.split(os.sep)[strip_components:])
            segments = [segment for segment in item.path.split("/") if segment]
            if not segments:
                continue
            parent = self._make_dirs(root, segments[:-1], mtime=archive_mtime)
            name = segments[-1]
            if stat.S_ISDIR(item.mode):
                # the directory may have been synthesized already (as the parent of an
                # item that came first): then just replace its item metadata.
                node = parent.children.get(name)
                if node is None or not node.is_dir:
                    node = self._new_node(parent, is_dir=True)
                    parent.children[name] = node
                self._set_item(node.ino, item)
                continue
            if versions:
                # the file name becomes a directory that contains all versions of that file
                parent = self._make_dirs(parent, [name])
                version = self._file_version(item, item.path)
                if version is not None:  # a regular file, with contents
                    name = versioned_name(name, version)
            hlid = item.get("hlid")
            if hlid is not None:
                first = hardlinks.get(hlid)
                if first is not None:
                    # another link to a file we already have: share its inode (and item),
                    # so the mount shows the hard link as such.
                    self._nlinks[first.ino] = self._nlinks.get(first.ino, 1) + 1
                    parent.children[name] = VFSNode(first.ino, parent)
                    continue
            node = self._new_node(parent, is_dir=False)
            self._set_item(node.ino, item)
            parent.children[name] = node
            if hlid is not None:
                hardlinks[hlid] = node
        duration = time.perf_counter() - t0
        logger.debug("vfs: built the tree of archive %s in %.1f s", remove_surrogates(archive_info.name), duration)

    def _make_dirs(self, node, segments, mtime=None):
        """Return the directory at *segments* below *node*, synthesizing what is missing.

        A synthesized directory gets an item of its own if *mtime* is given (so it can show
        the time of the archive it belongs to) - otherwise it shares the default directory
        item, which is what the many intermediate directories of the versions view do.
        """
        for segment in segments:
            child = node.children.get(segment)
            if child is None or not child.is_dir:
                # a directory we have not seen an item for (yet): synthesize it.
                child = self._new_node(node, is_dir=True)
                if mtime is not None:
                    self._set_item(child.ino, self._dir_item(mtime))
                node.children[segment] = child
            node = child
        return node

    def _new_node(self, parent, *, is_dir):
        self._ino_count += 1
        node = VFSNode(self._ino_count, parent, is_dir=is_dir)
        if is_dir:
            self._nodes[node.ino] = node
        return node

    def _file_version(self, item, path):
        """Return the version number of *item* in the versions view (None if it has no contents).

        Files are versioned by their content: a file keeps its version number as long as
        its chunk list does not change from one archive to the next.
        """
        if "chunks" not in item:
            return None
        # note: using sha256 here because nowadays it is often hw accelerated.
        #       shortening the hashes to 16 bytes to save some memory.
        file_id = hashlib.sha256(path.encode("utf-8", "surrogateescape")).digest()[:16]
        current_version, previous_id = self._versions_index.get(file_id, (0, None))
        contents_id = hashlib.sha256(b"".join(chunk_id for chunk_id, _ in item.chunks)).digest()[:16]
        if contents_id != previous_id:
            current_version += 1
            self._versions_index[file_id] = current_version, contents_id
        return current_version

    # -- looking things up --------------------------------------------------------

    def get_node(self, ino):
        """Return the directory node with inode number *ino*. Raises KeyError."""
        return self._nodes[ino]

    def lookup(self, node, name):
        """Return (canonical_name, child_node) for *name* in directory *node*. Raises KeyError."""
        self.ensure_loaded(node)
        return lookup_child(node, name)

    def resolve(self, segments, node=None):
        """Resolve path *segments* to (canonical_segments, node). Raises KeyError.

        *canonical_segments* are the names as they are stored in the archive, which may
        differ from what was asked for, see lookup().
        """
        node = self.root if node is None else node
        canonical = []
        for segment in segments:
            name, node = self.lookup(node, segment)
            canonical.append(name)
        return canonical, node

    def children(self, node):
        """Return the [(name, child_node), ...] of directory *node*."""
        self.ensure_loaded(node)
        return list(node.children.items())

    def get_item(self, ino):
        """Return the item of the node with inode number *ino*."""
        packed = self._items.get(ino)
        if packed is None:
            return self._default_dir()  # a synthesized directory
        # note: two threads can miss on the same inode and both unpack and store the item.
        # that is a bit of duplicated work, but both get a valid item.
        item = self._item_cache.get(ino)
        if item is None:
            item = Item(internal_dict=msgpack.unpackb(packed))
            if "chunks" in item:  # msgpack does not know about our namedtuple
                item.chunks = [ChunkListEntry(*chunk) for chunk in item.chunks]
            self._item_cache[ino] = item
        return item

    def _set_item(self, ino, item):
        item_dict = item.as_dict()
        # the path is already encoded in the tree structure, so drop it to save memory.
        item_dict.pop("path", None)
        self._items[ino] = msgpack.packb(item_dict)
        self._item_cache.pop(ino, None)

    # -- item metadata ------------------------------------------------------------

    def attrs(self, ino):
        """Return the file attributes of the node with inode number *ino*."""
        item = self.get_item(ino)
        options = self.options
        mode = item.mode & ~options.umask
        nlink = self._nlinks.get(ino, 1)
        if stat.S_ISDIR(mode):
            nlink = max(nlink, 2)  # every directory has at least "." and its entry in the parent
        uid, gid = get_item_uid_gid(
            item,
            numeric=options.numeric_ids,
            uid_default=self.default_uid,
            gid_default=self.default_gid,
            uid_forced=options.uid_forced,
            gid_forced=options.gid_forced,
        )
        # note: old archives only have mtime (not atime nor ctime nor birthtime)
        mtime_ns = item.mtime
        return Attrs(
            ino=ino,
            mode=mode,
            nlink=nlink,
            uid=uid,
            gid=gid,
            rdev=item.get("rdev", 0),
            size=item.get_size(),
            mtime_ns=mtime_ns,
            atime_ns=item.get("atime", mtime_ns),
            ctime_ns=item.get("ctime", mtime_ns),
            birthtime_ns=item.get("birthtime", mtime_ns),
        )

    def listxattr(self, ino):
        """Return the xattr names (bytes) of the node with inode number *ino*."""
        return item_listxattr(self.get_item(ino))

    def getxattr(self, ino, name):
        """Return the value of xattr *name* (bytes) of the node with inode number *ino*.

        Raises KeyError if the item does not have that xattr, ValueError if an archived
        ACL can not be converted to the binary xattr representation.
        """
        return item_getxattr(self.get_item(ino), name, numeric_ids=self.options.numeric_ids)

    def readlink(self, ino):
        """Return the target of the symlink with inode number *ino*."""
        return self.get_item(ino).target

    def log_stats(self):
        """Log some statistics about this file system (used by the SIGUSR1/SIGINFO handler)."""
        logger.debug(
            "vfs: %d inodes, %d items (%s), %d archives not loaded yet",
            self._ino_count,
            len(self._items),
            format_file_size(sum(len(packed) for packed in self._items.values())),
            len(self._pending),
        )
        data_cache = self.reader.data_cache
        logger.debug(
            "vfs: data cache: %d/%d entries, %s",
            len(data_cache),
            data_cache._capacity,
            format_file_size(sum(len(chunk) for _, chunk in data_cache.items())),
        )

    # -- file contents ------------------------------------------------------------

    def read(self, ino, offset, size, *, pos_key=None):
        """Return *size* bytes at *offset* of the file with inode number *ino*."""
        item = self.get_item(ino)
        return self.reader.read(item.get("chunks") or [], offset, size, pos_key=pos_key)


class DataReader:
    """Reads file content out of the chunk lists of items.

    Recently used chunks are kept decrypted in an in-memory cache, so the many small,
    sequential reads a file system does for one big file do not fetch and decrypt the
    same chunk over and over. This complements, but does not duplicate, the repository's
    own pack cache: that one caches the raw (still encrypted and compressed) on-disk
    bytes, whereas we cache the output of the per-chunk RepoObj.parse() that runs on
    every fetch even on a pack cache hit. So the two layers save different work
    (repository I/O vs. per-chunk decrypt + decompress).

    All repository access happens under *lock* (borgstore connections are not thread-safe),
    but the data is returned to the caller outside of it, so a slow consumer (e.g. a slow
    network client) does not block other users of the same repository. The caches are
    thread-safe by themselves, see LRUCache.
    """

    # how many chunk positions to remember for sequential reads (1 per open file)
    POSITIONS = 8

    def __init__(self, pipeline, *, lock=None, capacity=None, allow_damaged_files=False):
        self.pipeline = pipeline
        self.lock = lock if lock is not None else threading.RLock()
        capacity = data_cache_capacity() if capacity is None else capacity
        logger.debug("vfs: data cache capacity: %d chunks", capacity)
        self.data_cache = LRUCache(capacity=capacity)  # chunk id -> decrypted chunk data
        self.allow_damaged_files = allow_damaged_files
        # remembers where a sequential reader is within the chunk list, so a read does
        # not have to walk the list from the beginning again (that would be quadratic).
        self._last_pos = LRUCache(capacity=self.POSITIONS)

    def read(self, chunks, offset, size, *, pos_key=None):
        """Return *size* bytes at *offset* of the content described by the *chunks* list."""
        return b"".join(self.iter_data(chunks, offset, size, pos_key=pos_key))

    def iter_data(self, chunks, offset, size, *, pos_key=None):
        """Yield the bytes at [offset, offset+size) of the content described by *chunks*.

        *pos_key* identifies the reader (e.g. a file handle) for the sequential-read
        optimization. Raises ChunkMissing if a chunk is not in the repository (unless
        allow_damaged_files is set - then all-zero data is returned for it).
        """
        if size <= 0:
            return
        chunk_no, chunk_offset = self._get_pos(pos_key) if pos_key is not None else (0, 0)
        if chunk_offset > offset:
            # this is not a sequential read, so we lost track and start from the beginning again
            chunk_no, chunk_offset = 0, 0
        offset -= chunk_offset
        # note: using index iteration to avoid frequently copying big (sub)lists by slicing
        for idx in range(chunk_no, len(chunks)):
            entry = chunks[idx]
            if entry.size <= offset:
                offset -= entry.size
                chunk_offset += entry.size
                chunk_no += 1
                continue
            n = min(size, entry.size - offset)
            data = self._get_chunk(entry, fully_read=offset + n >= entry.size)
            yield data[offset : offset + n]
            offset = 0
            size -= n
            if not size:
                if pos_key is not None:
                    self._set_pos(pos_key, (chunk_no, chunk_offset))
                break

    def _get_chunk(self, entry, fully_read=False):
        """Return the decrypted data of chunk *entry*, using (and updating) the data cache.

        A chunk that is *fully_read* is not worth keeping: a sequential reader is done
        with it, so it is dropped from the cache instead of evicting something else.
        """
        with self.lock:
            try:
                data = self.data_cache[entry.id]
            except KeyError:
                pass
            else:
                if fully_read:
                    del self.data_cache[entry.id]
                return data
            data = next(
                self.pipeline.fetch_many([entry], ro_type=ROBJ_FILE_STREAM, replacement_chunk=self.allow_damaged_files)
            )
            if data is None:
                raise ChunkMissing(entry.id)
            if not fully_read:
                self.data_cache[entry.id] = data
            return data

    # the read positions are only a hint: a read that starts before the remembered
    # position just starts over, so a racing update costs at most a rescan of the
    # chunk list.

    def _get_pos(self, pos_key):
        return self._last_pos.get(pos_key, (0, 0))

    def _set_pos(self, pos_key, pos):
        self._last_pos[pos_key] = pos

    def forget(self, pos_key):
        """Forget the read position of *pos_key* (call this when a file is closed)."""
        self._last_pos.pop(pos_key, None)


def data_cache_capacity():
    # number of decrypted chunks to keep cached, see borg mount --help.
    # default: number of CPUs (a small, non-zero value).
    capacity = int(os.environ.get("BORG_MOUNT_DATA_CACHE_ENTRIES", os.cpu_count() or 1))
    return max(1, capacity)


def build_item_filter(args):
    """Build the item filter selecting the paths/patterns given on the command line."""
    # lazy import: pulling in the archiver package at module import time would be heavy
    # (it defines all subcommands) and risks an import cycle.
    from .archiver._common import build_matcher, build_filter

    # omitting args.pattern_roots here, restricting to paths only by cli args.paths:
    matcher = build_matcher(getattr(args, "patterns", None) or [], getattr(args, "paths", None) or [])
    return build_filter(matcher, getattr(args, "strip_components", 0))


def pop_option(options, key, present, not_present, wanted_type, int_base=0):
    """Remove mount option *key* from the *options* list and return its value."""
    assert isinstance(options, list)  # we mutate this
    for idx, option in enumerate(options):
        if option == key:
            options.pop(idx)
            return present
        if option.startswith(key + "="):
            options.pop(idx)
            value = option.split("=", 1)[1]
            if wanted_type is bool:
                v = value.lower()
                if v in ("y", "yes", "true", "1"):
                    return True
                if v in ("n", "no", "false", "0"):
                    return False
                raise ValueError("unsupported value in option: %s" % option)
            if wanted_type is int:
                try:
                    return int(value, base=int_base)
                except ValueError:
                    raise ValueError("unsupported value in option: %s" % option) from None
            try:
                return wanted_type(value)
            except ValueError:
                raise ValueError("unsupported value in option: %s" % option) from None
    else:
        return not_present


def parse_mount_options(args, mountpoint, mount_options):
    """Process the "borg mount" options; returns (libfuse options, VFSOptions).

    The borg specific options are removed from the option list here and end up in the
    VFSOptions, everything else is passed on to libfuse.
    """
    # default_permissions enables permission checking by the kernel. Without
    # this, any umask (or uid/gid) would not have an effect and this could
    # cause security issues if used with allow_other mount option.
    # When not using allow_other or allow_root, access is limited to the
    # mounting user anyway.
    options = ["fsname=borgfs", "ro", "default_permissions"]
    if mount_options:
        options.extend(mount_options.split(","))
    if is_darwin:
        # macFUSE supports a volname mount option to give what finder displays on desktop / in directory list.
        volname = pop_option(options, "volname", "", "", str)
        # if the user did not specify it, we make something up,
        # because otherwise it would be "macFUSE Volume 0 (Python)", #7690.
        volname = volname or f"{os.path.basename(mountpoint)} (borgfs)"
        options.append(f"volname={volname}")
    ignore_permissions = pop_option(options, "ignore_permissions", True, False, bool)
    if ignore_permissions:
        # in case users have a use-case that requires NOT giving "default_permissions",
        # this is enabled by the custom "ignore_permissions" mount option which just
        # removes "default_permissions" again:
        pop_option(options, "default_permissions", True, False, bool)
    vfs_options = VFSOptions(
        allow_damaged_files=pop_option(options, "allow_damaged_files", True, False, bool),
        versions=pop_option(options, "versions", True, False, bool),
        uid_forced=pop_option(options, "uid", None, None, int),
        gid_forced=pop_option(options, "gid", None, None, int),
        umask=pop_option(options, "umask", 0, 0, int, int_base=8),  # umask is octal, e.g. 222 or 0222
        numeric_ids=getattr(args, "numeric_ids", False),
        strip_components=getattr(args, "strip_components", 0),
        item_filter=build_item_filter(args),
    )
    dir_uid = vfs_options.uid_forced if vfs_options.uid_forced is not None else os.getuid()
    dir_gid = vfs_options.gid_forced if vfs_options.gid_forced is not None else os.getgid()
    dir_user = uid2user(dir_uid)
    dir_group = gid2group(dir_gid)
    if not isinstance(dir_user, str):
        raise Error(
            f"uid {dir_uid} can not be resolved to a username. "
            f"Please check that the corresponding user exists or do not specify a uid mount option."
        )
    if not isinstance(dir_group, str):
        raise Error(
            f"gid {dir_gid} can not be resolved to a group name. "
            f"Please check that the corresponding group exists or do not specify a gid mount option."
        )
    vfs_options.dir_item = Item(
        mode=DEFAULT_DIR_MODE & ~vfs_options.umask,
        mtime=int(time.time() * 1e9),
        user=dir_user,
        group=dir_group,
        uid=dir_uid,
        gid=dir_gid,
    )
    return options, vfs_options

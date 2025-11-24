import errno
import hashlib
import os
import stat
import time
from collections import Counter

from .constants import ROBJ_FILE_STREAM, zeros, ROBJ_DONTCARE


import mfusepy as mfuse

from .logger import create_logger

logger = create_logger()

from .archiver._common import build_matcher, build_filter
from .archive import Archive, get_item_uid_gid
from .hashindex import FuseVersionsIndex
from .helpers import daemonize, daemonizing, signal_handler, bin_to_hex
from .helpers import HardLinkManager
from .helpers import msgpack
from .helpers.lrucache import LRUCache
from .item import Item
from .platform import uid2user, gid2group
from .platformflags import is_darwin
from .repository import Repository
from .remote import RemoteRepository


def debug_log(msg):
    """Append debug message to fuse_debug.log"""
    import datetime

    timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    with open("/Users/tw/w/borg_ag/fuse_debug.log", "a") as f:
        f.write(f"{timestamp} {msg}\n")


def fuse_main():
    return mfuse.main(workers=1)


class Node:
    def __init__(self, id, item=None, parent=None):
        self.id = id
        self.item = item
        self.parent = parent
        self.children = {}  # name (bytes) -> Node


class FuseBackend:
    """Virtual filesystem based on archive(s) to provide information to fuse"""

    def __init__(self, manifest, args, repository):
        self._args = args
        self.numeric_ids = args.numeric_ids
        self._manifest = manifest
        self.repo_objs = manifest.repo_objs
        self.repository = repository

        self.default_uid = os.getuid()
        self.default_gid = os.getgid()
        self.default_dir = None

        self.node_count = 0
        self.root = self._create_node()
        self.pending_archives = {}  # Node -> Archive

        self.allow_damaged_files = False
        self.versions = False
        self.uid_forced = None
        self.gid_forced = None
        self.umask = 0
        self.archive_root_dir = {}  # archive ID --> directory name

        # Cache for file handles
        self.handles = {}
        self.handle_count = 0

        # Cache for chunks (moved from ItemCache)
        self.chunks_cache = LRUCache(capacity=10)

    def _create_node(self, item=None, parent=None):
        self.node_count += 1
        return Node(self.node_count, item, parent)

    def _create_filesystem(self):
        self.root.item = self.default_dir
        self.versions_index = FuseVersionsIndex()

        if getattr(self._args, "name", None):
            archives = [self._manifest.archives.get(self._args.name)]
        else:
            archives = self._manifest.archives.list_considering(self._args)

        name_counter = Counter(a.name for a in archives)
        duplicate_names = {a.name for a in archives if name_counter[a.name] > 1}

        for archive in archives:
            name = f"{archive.name}"
            if name in duplicate_names:
                name += f"-{bin_to_hex(archive.id):.8}"
            self.archive_root_dir[archive.id] = name

        for archive in archives:
            if self.versions:
                self._process_archive(archive.id)
            else:
                # Create placeholder for archive
                name = self.archive_root_dir[archive.id]
                name_bytes = os.fsencode(name)

                archive_node = self._create_node(parent=self.root)
                # Create a directory item for the archive
                archive_node.item = Item(internal_dict=self.default_dir.as_dict())
                archive_node.item.mtime = int(archive.ts.timestamp() * 1e9)

                self.root.children[name_bytes] = archive_node
                self.pending_archives[archive_node] = archive

    def check_pending_archive(self, node):
        archive_info = self.pending_archives.pop(node, None)
        if archive_info is not None:
            self._process_archive(archive_info.id, node)

    def _iter_archive_items(self, archive_item_ids, filter=None):
        unpacker = msgpack.Unpacker()
        for id, cdata in zip(archive_item_ids, self.repository.get_many(archive_item_ids)):
            _, data = self.repo_objs.parse(id, cdata, ro_type=ROBJ_DONTCARE)
            unpacker.feed(data)
            for item in unpacker:
                item = Item(internal_dict=item)
                if filter and not filter(item):
                    continue
                yield item

    def _process_archive(self, archive_id, root_node=None):
        if root_node is None:
            root_node = self.root

        self.file_versions = {}  # for versions mode: original path -> version

        archive = Archive(self._manifest, archive_id)
        strip_components = self._args.strip_components
        matcher = build_matcher(self._args.patterns, self._args.paths)
        hlm = HardLinkManager(id_type=bytes, info_type=str)

        filter = build_filter(matcher, strip_components)

        for item in self._iter_archive_items(archive.metadata.items, filter=filter):
            if strip_components:
                item.path = os.sep.join(item.path.split(os.sep)[strip_components:])

            path = os.fsencode(item.path)
            segments = path.split(b"/")
            is_dir = stat.S_ISDIR(item.mode)

            # For versions mode, handle files differently
            if self.versions and not is_dir:
                self._process_leaf_versioned(segments, item, root_node, hlm)
            else:
                # Original non-versions logic
                node = root_node
                # Traverse/Create directories
                for segment in segments[:-1]:
                    if segment not in node.children:
                        new_node = self._create_node(parent=node)
                        # We might need a default directory item if it's an implicit directory
                        new_node.item = Item(internal_dict=self.default_dir.as_dict())
                        node.children[segment] = new_node
                    node = node.children[segment]

                # Leaf (file or explicit directory)
                leaf_name = segments[-1]
                if leaf_name in node.children:
                    # Already exists (e.g. implicit dir became explicit)
                    child = node.children[leaf_name]
                    child.item = item  # Update item
                    node = child
                else:
                    new_node = self._create_node(item, parent=node)
                    node.children[leaf_name] = new_node
                    node = new_node

                # Handle hardlinks (non-versions mode)
                if "hlid" in item:
                    link_target = hlm.retrieve(id=item.hlid, default=None)
                    if link_target is not None:
                        target_path = os.fsencode(link_target)
                        target_node = self._find_node_from_root(root_node, target_path)
                        if target_node:
                            # Reuse ID and Item to share inode and attributes
                            node.id = target_node.id
                            node.item = target_node.item
                            if "nlink" not in node.item:
                                node.item.nlink = 1
                            node.item.nlink += 1
                        else:
                            logger.warning("Hardlink target not found: %s", link_target)
                    else:
                        hlm.remember(id=item.hlid, info=item.path)

    def _process_leaf_versioned(self, segments, item, root_node, hlm):
        """Process a file leaf node in versions mode"""
        path = b"/".join(segments)
        original_path = item.path

        # Handle hardlinks in versions mode - check if we've seen this hardlink before
        is_hardlink = "hlid" in item
        link_target = None
        if is_hardlink:
            link_target = hlm.retrieve(id=item.hlid, default=None)
            if link_target is None:
                # First occurrence of this hardlink
                hlm.remember(id=item.hlid, info=original_path)

        # Calculate version for this file
        # If it's a hardlink to a previous file, use that version
        if is_hardlink and link_target is not None:
            link_target_enc = os.fsencode(link_target)
            version = self.file_versions.get(link_target_enc)
        else:
            version = self._file_version(item, path)

        # Store version for this path
        if version is not None:
            self.file_versions[path] = version

        # Navigate to parent directory
        node = root_node
        for segment in segments[:-1]:
            if segment not in node.children:
                new_node = self._create_node(parent=node)
                new_node.item = Item(internal_dict=self.default_dir.as_dict())
                node.children[segment] = new_node
            node = node.children[segment]

        # Create intermediate directory with the filename
        leaf_name = segments[-1]
        if leaf_name not in node.children:
            intermediate_node = self._create_node(parent=node)
            intermediate_node.item = Item(internal_dict=self.default_dir.as_dict())
            node.children[leaf_name] = intermediate_node
        else:
            intermediate_node = node.children[leaf_name]

        # Create versioned filename
        if version is not None:
            versioned_name = self._make_versioned_name(leaf_name, version)

            # If this is a hardlink to a previous file, reuse that node
            if is_hardlink and link_target is not None:
                link_target_enc = os.fsencode(link_target)
                link_segments = link_target_enc.split(b"/")
                link_version = self.file_versions.get(link_target_enc)
                if link_version is not None:
                    # Navigate to the link target
                    target_node = root_node
                    for seg in link_segments[:-1]:
                        if seg in target_node.children:
                            target_node = target_node.children[seg]
                        else:
                            break
                    else:
                        # Get intermediate dir
                        link_leaf = link_segments[-1]
                        if link_leaf in target_node.children:
                            target_intermediate = target_node.children[link_leaf]
                            target_versioned = self._make_versioned_name(link_leaf, link_version)
                            if target_versioned in target_intermediate.children:
                                original_node = target_intermediate.children[target_versioned]
                                # Create new node but reuse the ID and item from original
                                file_node = self._create_node(original_node.item, parent=intermediate_node)
                                file_node.id = original_node.id
                                # Update nlink count
                                if "nlink" not in file_node.item:
                                    file_node.item.nlink = 1
                                file_node.item.nlink += 1
                                intermediate_node.children[versioned_name] = file_node
                                return

            # Not a hardlink or first occurrence - create new node
            file_node = self._create_node(item, parent=intermediate_node)
            intermediate_node.children[versioned_name] = file_node

    def _file_version(self, item, path):
        """Calculate version number for a file based on its contents"""
        if "chunks" not in item:
            return None

        file_id = hashlib.sha256(path).digest()[:16]
        current_version, previous_id = self.versions_index.get(file_id, (0, None))

        contents_id = hashlib.sha256(b"".join(chunk_id for chunk_id, _ in item.chunks)).digest()[:16]

        if contents_id != previous_id:
            current_version += 1
            self.versions_index[file_id] = current_version, contents_id

        return current_version

    def _make_versioned_name(self, name, version):
        """Generate versioned filename like 'file.00001.txt'"""
        # keep original extension at end to avoid confusing tools
        name_str = name.decode("utf-8", "surrogateescape") if isinstance(name, bytes) else name
        name_part, ext = os.path.splitext(name_str)
        version_str = ".%05d" % version
        versioned = name_part + version_str + ext
        return versioned.encode("utf-8", "surrogateescape") if isinstance(name, bytes) else versioned

    def _find_node_from_root(self, root, path):
        if path == b"" or path == b".":
            return root
        segments = path.split(b"/")
        node = root
        for segment in segments:
            if segment in node.children:
                node = node.children[segment]
            else:
                return None
        return node

    def _find_node(self, path):
        if isinstance(path, str):
            path = os.fsencode(path)
        if path == b"/" or path == b"":
            return self.root
        if path.startswith(b"/"):
            path = path[1:]

        segments = path.split(b"/")
        node = self.root
        for segment in segments:
            if node in self.pending_archives:
                self.check_pending_archive(node)
            if segment in node.children:
                node = node.children[segment]
            else:
                return None

        if node in self.pending_archives:
            self.check_pending_archive(node)

        return node

    def _get_handle(self, node):
        self.handle_count += 1
        self.handles[self.handle_count] = node
        return self.handle_count

    def _get_node_from_handle(self, fh):
        return self.handles.get(fh)

    def _make_stat_dict(self, node):
        """Create a stat dictionary from a node."""
        item = node.item
        st = {}
        st["st_ino"] = node.id
        st["st_mode"] = item.mode & ~self.umask
        st["st_nlink"] = item.get("nlink", 1)
        if stat.S_ISDIR(st["st_mode"]):
            st["st_nlink"] = max(st["st_nlink"], 2)
        st["st_uid"], st["st_gid"] = get_item_uid_gid(
            item,
            numeric=self.numeric_ids,
            uid_default=self.default_uid,
            gid_default=self.default_gid,
            uid_forced=self.uid_forced,
            gid_forced=self.gid_forced,
        )
        st["st_rdev"] = item.get("rdev", 0)
        st["st_size"] = item.get_size()
        # Convert nanoseconds to seconds for macOS compatibility
        if getattr(self, "use_ns", False):
            st["st_mtime"] = item.mtime
            st["st_atime"] = item.get("atime", item.mtime)
            st["st_ctime"] = item.get("ctime", item.mtime)
        else:
            st["st_mtime"] = item.mtime / 1e9
            st["st_atime"] = item.get("atime", item.mtime) / 1e9
            st["st_ctime"] = item.get("ctime", item.mtime) / 1e9
        return st


class borgfs(mfuse.Operations, FuseBackend):
    """Export archive as a FUSE filesystem"""

    use_ns = True

    def __init__(self, manifest, args, repository):
        mfuse.Operations.__init__(self)
        FuseBackend.__init__(self, manifest, args, repository)
        data_cache_capacity = int(os.environ.get("BORG_MOUNT_DATA_CACHE_ENTRIES", os.cpu_count() or 1))
        logger.debug("mount data cache capacity: %d chunks", data_cache_capacity)
        self.data_cache = LRUCache(capacity=data_cache_capacity)
        self._last_pos = LRUCache(capacity=4)

    def sig_info_handler(self, sig_no, stack):
        # Simplified instrumentation
        logger.debug("fuse: %d nodes", self.node_count)

    def mount(self, mountpoint, mount_options, foreground=False, show_rc=False):
        """Mount filesystem on *mountpoint* with *mount_options*."""

        def pop_option(options, key, present, not_present, wanted_type, int_base=0):
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

        options = ["fsname=borgfs", "ro", "default_permissions"]
        if mount_options:
            options.extend(mount_options.split(","))
        if is_darwin:
            volname = pop_option(options, "volname", "", "", str)
            volname = volname or f"{os.path.basename(mountpoint)} (borgfs)"
            options.append(f"volname={volname}")
        ignore_permissions = pop_option(options, "ignore_permissions", True, False, bool)
        if ignore_permissions:
            pop_option(options, "default_permissions", True, False, bool)
        self.allow_damaged_files = pop_option(options, "allow_damaged_files", True, False, bool)
        self.versions = pop_option(options, "versions", True, False, bool)
        self.uid_forced = pop_option(options, "uid", None, None, int)
        self.gid_forced = pop_option(options, "gid", None, None, int)
        self.umask = pop_option(options, "umask", 0, 0, int, int_base=8)
        dir_uid = self.uid_forced if self.uid_forced is not None else self.default_uid
        dir_gid = self.gid_forced if self.gid_forced is not None else self.default_gid
        dir_user = uid2user(dir_uid)
        dir_group = gid2group(dir_gid)
        assert isinstance(dir_user, str)
        assert isinstance(dir_group, str)
        dir_mode = 0o40755 & ~self.umask
        self.default_dir = Item(
            mode=dir_mode, mtime=int(time.time() * 1e9), user=dir_user, group=dir_group, uid=dir_uid, gid=dir_gid
        )
        self._create_filesystem()

        # mfuse.FUSE will block if foreground=True, otherwise it returns immediately
        if not foreground:
            # Background mode: daemonize first, then start FUSE (blocking)
            if isinstance(self.repository, RemoteRepository):
                daemonize()
            else:
                with daemonizing(show_rc=show_rc) as (old_id, new_id):
                    logger.debug("fuse: mount local repo, going to background: migrating lock.")
                    self.repository.migrate_lock(old_id, new_id)

        # Run the FUSE main loop in foreground (we might be daemonized already or not)
        with signal_handler("SIGUSR1", self.sig_info_handler), signal_handler("SIGINFO", self.sig_info_handler):
            mfuse.FUSE(self, mountpoint, options, foreground=True)

    def statfs(self, path):
        debug_log(f"statfs(path={path!r})")
        stat_ = {}
        stat_["f_bsize"] = 512
        stat_["f_frsize"] = 512
        stat_["f_blocks"] = 0
        stat_["f_bfree"] = 0
        stat_["f_bavail"] = 0
        stat_["f_files"] = 0
        stat_["f_ffree"] = 0
        stat_["f_favail"] = 0
        stat_["f_namemax"] = 255
        debug_log(f"statfs -> {stat_}")
        return stat_

    def getattr(self, path, fh=None):
        debug_log(f"getattr(path={path!r}, fh={fh})")
        node = self._find_node(path)
        if node is None:
            raise mfuse.FuseOSError(errno.ENOENT)
        st = self._make_stat_dict(node)
        debug_log(f"getattr -> {st}")
        return st

    def listxattr(self, path):
        debug_log(f"listxattr(path={path!r})")
        node = self._find_node(path)
        if node is None:
            raise mfuse.FuseOSError(errno.ENOENT)
        item = node.item
        result = [k.decode("utf-8", "surrogateescape") for k in item.get("xattrs", {}).keys()]
        debug_log(f"listxattr -> {result}")
        return result

    def getxattr(self, path, name, position=0):
        debug_log(f"getxattr(path={path!r}, name={name!r}, position={position})")
        node = self._find_node(path)
        if node is None:
            raise mfuse.FuseOSError(errno.ENOENT)
        item = node.item
        try:
            if isinstance(name, str):
                name = name.encode("utf-8", "surrogateescape")
            result = item.get("xattrs", {})[name] or b""
            debug_log(f"getxattr -> {len(result)} bytes")
            return result
        except KeyError:
            debug_log("getxattr -> ENODATA")
            raise mfuse.FuseOSError(errno.ENODATA) from None

    def open(self, path, fi):
        debug_log(f"open(path={path!r}, fi={fi})")
        node = self._find_node(path)
        if node is None:
            raise mfuse.FuseOSError(errno.ENOENT)
        fh = self._get_handle(node)
        fi.fh = fh
        debug_log(f"open -> fh={fh}")
        return 0

    def release(self, path, fi):
        debug_log(f"release(path={path!r}, fh={fi.fh})")
        self.handles.pop(fi.fh, None)
        self._last_pos.pop(fi.fh, None)
        return 0

    def create(self, path, mode, fi=None):
        debug_log(f"create(path={path!r}, mode={mode}, fi={fi}) -> EROFS")
        raise mfuse.FuseOSError(errno.EROFS)

    def read(self, path, size, offset, fi):
        fh = fi.fh
        debug_log(f"read(path={path!r}, size={size}, offset={offset}, fh={fh})")
        node = self._get_node_from_handle(fh)
        if node is None:
            # Fallback if fh is invalid or not found, try path?
            # But read should be fast.
            raise mfuse.FuseOSError(errno.EBADF)

        item = node.item
        parts = []

        # optimize for linear reads:
        chunk_no, chunk_offset = self._last_pos.get(fh, (0, 0))
        if chunk_offset > offset:
            chunk_no, chunk_offset = (0, 0)

        offset -= chunk_offset
        chunks = item.chunks

        for idx in range(chunk_no, len(chunks)):
            id, s = chunks[idx]
            if s < offset:
                offset -= s
                chunk_offset += s
                chunk_no += 1
                continue
            n = min(size, s - offset)
            if id in self.data_cache:
                data = self.data_cache[id]
                if offset + n == len(data):
                    del self.data_cache[id]
            else:
                try:
                    # Direct repository access
                    cdata = self.repository.get(id)
                except Repository.ObjectNotFound:
                    if self.allow_damaged_files:
                        data = zeros[:s]
                        assert len(data) == s
                    else:
                        raise mfuse.FuseOSError(errno.EIO) from None
                else:
                    _, data = self.repo_objs.parse(id, cdata, ro_type=ROBJ_FILE_STREAM)
                if offset + n < len(data):
                    self.data_cache[id] = data
            parts.append(data[offset : offset + n])
            offset = 0
            size -= n
            if not size:
                if fh in self._last_pos:
                    self._last_pos.replace(fh, (chunk_no, chunk_offset))
                else:
                    self._last_pos[fh] = (chunk_no, chunk_offset)
                break
        result = b"".join(parts)
        debug_log(f"read -> {len(result)} bytes")
        return result

    def readdir(self, path, fh=None):
        debug_log(f"readdir(path={path!r}, fh={fh})")
        node = self._find_node(path)
        if node is None:
            raise mfuse.FuseOSError(errno.ENOENT)

        debug_log("readdir yielding . and .., offsets 1 and 2")
        offset = 1
        yield (".", self._make_stat_dict(node), offset)
        offset += 1
        parent = node.parent if node.parent else node
        yield ("..", self._make_stat_dict(parent), offset)
        offset += 1

        for name, child_node in node.children.items():
            name_str = name.decode("utf-8", "surrogateescape")
            st = self._make_stat_dict(child_node)
            debug_log(f"readdir yielding {name_str} {offset} {st}")
            yield (name_str, st, offset)
            offset += 1

    def readlink(self, path):
        debug_log(f"readlink(path={path!r})")
        node = self._find_node(path)
        if node is None:
            raise mfuse.FuseOSError(errno.ENOENT)
        item = node.item
        result = item.target
        debug_log(f"readlink -> {result!r}")
        return result

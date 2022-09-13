import errno
import functools
import io
import os
import stat
import struct
import sys
import tempfile
import time
from collections import defaultdict
from signal import SIGINT

from .fuse_impl import llfuse, has_pyfuse3


if has_pyfuse3:
    import trio

    def async_wrapper(fn):
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            return fn(*args, **kwargs)

        return wrapper

else:
    trio = None

    def async_wrapper(fn):
        return fn


from .logger import create_logger

logger = create_logger()

from .crypto.low_level import blake2b_128
from .archiver._common import build_matcher, build_filter
from .archive import Archive, get_item_uid_gid
from .hashindex import FuseVersionsIndex
from .helpers import daemonize, daemonizing, signal_handler, format_file_size
from .helpers import HardLinkManager
from .helpers import msgpack
from .helpers.lrucache import LRUCache
from .item import Item
from .platform import uid2user, gid2group
from .remote import RemoteRepository


def fuse_main():
    if has_pyfuse3:
        try:
            trio.run(llfuse.main)
        except:
            return 1  # TODO return signal number if it was killed by signal
        else:
            return None
    else:
        return llfuse.main(workers=1)


# size of some LRUCaches (1 element per simultaneously open file)
# note: _inode_cache might have rather large elements - Item.chunks can be large!
#       also, simultaneously reading too many files should be avoided anyway.
#       thus, do not set FILES to high values.
FILES = 4


class ItemCache:
    """
    This is the "meat" of the file system's metadata storage.

    This class generates inode numbers that efficiently index items in archives,
    and retrieves items from these inode numbers.
    """

    # 2 MiB are approximately ~230000 items (depends on the average number of items per metadata chunk).
    #
    # Since growing a bytearray has to copy it, growing it will converge to O(n^2), however,
    # this is not yet relevant due to the swiftness of copying memory. If it becomes an issue,
    # use an anonymous mmap and just resize that (or, if on 64 bit, make it so big you never need
    # to resize it in the first place; that's free).
    GROW_META_BY = 2 * 1024 * 1024

    indirect_entry_struct = struct.Struct("=cII")
    assert indirect_entry_struct.size == 9

    def __init__(self, decrypted_repository):
        self.decrypted_repository = decrypted_repository
        # self.meta, the "meta-array" is a densely packed array of metadata about where items can be found.
        # It is indexed by the inode number minus self.offset. (This is in a way eerily similar to how the first
        # unices did this).
        # The meta-array contains chunk IDs and item entries (described in iter_archive_items).
        # The chunk IDs are referenced by item entries through relative offsets,
        # which are bounded by the metadata chunk size.
        self.meta = bytearray()
        # The current write offset in self.meta
        self.write_offset = 0

        # Offset added to meta-indices, resulting in inodes,
        # or subtracted from inodes, resulting in meta-indices.
        # XXX: Merge FuseOperations.items and ItemCache to avoid
        #      this implicit limitation / hack (on the number of synthetic inodes, degenerate
        #      cases can inflate their number far beyond the number of archives).
        self.offset = 1000000

        # A temporary file that contains direct items, i.e. items directly cached in this layer.
        # These are items that span more than one chunk and thus cannot be efficiently cached
        # by the object cache (self.decrypted_repository), which would require variable-length structures;
        # possible but not worth the effort, see iter_archive_items.
        self.fd = tempfile.TemporaryFile(prefix="borg-tmp")

        # A small LRU cache for chunks requested by ItemCache.get() from the object cache,
        # this significantly speeds up directory traversal and similar operations which
        # tend to re-read the same chunks over and over.
        # The capacity is kept low because increasing it does not provide any significant advantage,
        # but makes LRUCache's square behaviour noticeable and consumes more memory.
        self.chunks = LRUCache(capacity=10, dispose=lambda _: None)

        # Instrumentation
        # Count of indirect items, i.e. data is cached in the object cache, not directly in this cache
        self.indirect_items = 0
        # Count of direct items, i.e. data is in self.fd
        self.direct_items = 0

    def get(self, inode):
        offset = inode - self.offset
        if offset < 0:
            raise ValueError("ItemCache.get() called with an invalid inode number")
        if self.meta[offset] == ord(b"I"):
            _, chunk_id_relative_offset, chunk_offset = self.indirect_entry_struct.unpack_from(self.meta, offset)
            chunk_id_offset = offset - chunk_id_relative_offset
            # bytearray slices are bytearrays as well, explicitly convert to bytes()
            chunk_id = bytes(self.meta[chunk_id_offset : chunk_id_offset + 32])
            chunk = self.chunks.get(chunk_id)
            if not chunk:
                csize, chunk = next(self.decrypted_repository.get_many([chunk_id]))
                self.chunks[chunk_id] = chunk
            data = memoryview(chunk)[chunk_offset:]
            unpacker = msgpack.Unpacker()
            unpacker.feed(data)
            return Item(internal_dict=next(unpacker))
        elif self.meta[offset] == ord(b"S"):
            fd_offset = int.from_bytes(self.meta[offset + 1 : offset + 9], "little")
            self.fd.seek(fd_offset, io.SEEK_SET)
            return Item(internal_dict=next(msgpack.Unpacker(self.fd, read_size=1024)))
        else:
            raise ValueError("Invalid entry type in self.meta")

    def iter_archive_items(self, archive_item_ids, filter=None, consider_part_files=False):
        unpacker = msgpack.Unpacker()

        # Current offset in the metadata stream, which consists of all metadata chunks glued together
        stream_offset = 0
        # Offset of the current chunk in the metadata stream
        chunk_begin = 0
        # Length of the chunk preceding the current chunk
        last_chunk_length = 0
        msgpacked_bytes = b""

        write_offset = self.write_offset
        meta = self.meta
        pack_indirect_into = self.indirect_entry_struct.pack_into

        for key, (csize, data) in zip(archive_item_ids, self.decrypted_repository.get_many(archive_item_ids)):
            # Store the chunk ID in the meta-array
            if write_offset + 32 >= len(meta):
                self.meta = meta = meta + bytes(self.GROW_META_BY)
            meta[write_offset : write_offset + 32] = key
            current_id_offset = write_offset
            write_offset += 32

            chunk_begin += last_chunk_length
            last_chunk_length = len(data)

            unpacker.feed(data)
            while True:
                try:
                    item = unpacker.unpack()
                    need_more_data = False
                except msgpack.OutOfData:
                    need_more_data = True

                start = stream_offset - chunk_begin
                # tell() is not helpful for the need_more_data case, but we know it is the remainder
                # of the data in that case. in the other case, tell() works as expected.
                length = (len(data) - start) if need_more_data else (unpacker.tell() - stream_offset)
                msgpacked_bytes += data[start : start + length]
                stream_offset += length

                if need_more_data:
                    # Need more data, feed the next chunk
                    break

                item = Item(internal_dict=item)
                if filter and not filter(item) or not consider_part_files and "part" in item:
                    msgpacked_bytes = b""
                    continue

                current_item = msgpacked_bytes
                current_item_length = len(current_item)
                current_spans_chunks = stream_offset - current_item_length < chunk_begin
                msgpacked_bytes = b""

                if write_offset + 9 >= len(meta):
                    self.meta = meta = meta + bytes(self.GROW_META_BY)

                # item entries in the meta-array come in two different flavours, both nine bytes long.
                # (1) for items that span chunks:
                #
                #     'S' + 8 byte offset into the self.fd file, where the msgpacked item starts.
                #
                # (2) for items that are completely contained in one chunk, which usually is the great majority
                #     (about 700:1 for system backups)
                #
                #     'I' + 4 byte offset where the chunk ID is + 4 byte offset in the chunk
                #     where the msgpacked items starts
                #
                #     The chunk ID offset is the number of bytes _back_ from the start of the entry, i.e.:
                #
                #     |Chunk ID| ....          |S1234abcd|
                #      ^------ offset ----------^

                if current_spans_chunks:
                    pos = self.fd.seek(0, io.SEEK_END)
                    self.fd.write(current_item)
                    meta[write_offset : write_offset + 9] = b"S" + pos.to_bytes(8, "little")
                    self.direct_items += 1
                else:
                    item_offset = stream_offset - current_item_length - chunk_begin
                    pack_indirect_into(meta, write_offset, b"I", write_offset - current_id_offset, item_offset)
                    self.indirect_items += 1
                inode = write_offset + self.offset
                write_offset += 9

                yield inode, item

        self.write_offset = write_offset


class FuseBackend:
    """Virtual filesystem based on archive(s) to provide information to fuse"""

    def __init__(self, manifest, args, decrypted_repository):
        self._args = args
        self.numeric_ids = args.numeric_ids
        self._manifest = manifest
        self.repo_objs = manifest.repo_objs
        self.repository_uncached = manifest.repository
        # Maps inode numbers to Item instances. This is used for synthetic inodes, i.e. file-system objects that are
        # made up and are not contained in the archives. For example archive directories or intermediate directories
        # not contained in archives.
        self._items = {}
        # cache up to <FILES> Items
        self._inode_cache = LRUCache(capacity=FILES, dispose=lambda _: None)
        # _inode_count is the current count of synthetic inodes, i.e. those in self._items
        self.inode_count = 0
        # Maps inode numbers to the inode number of the parent
        self.parent = {}
        # Maps inode numbers to a dictionary mapping byte directory entry names to their inode numbers,
        # i.e. this contains all dirents of everything that is mounted. (It becomes really big).
        self.contents = defaultdict(dict)
        self.default_uid = os.getuid()
        self.default_gid = os.getgid()
        self.default_dir = None
        # Archives to be loaded when first accessed, mapped by their placeholder inode
        self.pending_archives = {}
        self.cache = ItemCache(decrypted_repository)
        self.allow_damaged_files = False
        self.versions = False
        self.uid_forced = None
        self.gid_forced = None
        self.umask = 0

    def _create_filesystem(self):
        self._create_dir(parent=1)  # first call, create root dir (inode == 1)
        self.versions_index = FuseVersionsIndex()
        for archive in self._manifest.archives.list_considering(self._args):
            if self.versions:
                # process archives immediately
                self._process_archive(archive.name)
            else:
                # lazily load archives, create archive placeholder inode
                archive_inode = self._create_dir(parent=1, mtime=int(archive.ts.timestamp() * 1e9))
                self.contents[1][os.fsencode(archive.name)] = archive_inode
                self.pending_archives[archive_inode] = archive.name

    def get_item(self, inode):
        item = self._inode_cache.get(inode)
        if item is not None:
            return item
        try:
            # this is a cheap get-from-dictionary operation, no need to cache the result.
            return self._items[inode]
        except KeyError:
            # while self.cache does some internal caching, it has still quite some overhead, so we cache the result.
            item = self.cache.get(inode)
            self._inode_cache[inode] = item
            return item

    def check_pending_archive(self, inode):
        # Check if this is an archive we need to load
        archive_name = self.pending_archives.pop(inode, None)
        if archive_name is not None:
            self._process_archive(archive_name, [os.fsencode(archive_name)])

    def _allocate_inode(self):
        self.inode_count += 1
        return self.inode_count

    def _create_dir(self, parent, mtime=None):
        """Create directory"""
        ino = self._allocate_inode()
        if mtime is not None:
            self._items[ino] = Item(internal_dict=self.default_dir.as_dict())
            self._items[ino].mtime = mtime
        else:
            self._items[ino] = self.default_dir
        self.parent[ino] = parent
        return ino

    def find_inode(self, path, prefix=[]):
        segments = prefix + path.split(b"/")
        inode = 1
        for segment in segments:
            inode = self.contents[inode][segment]
        return inode

    def _process_archive(self, archive_name, prefix=[]):
        """Build FUSE inode hierarchy from archive metadata"""
        self.file_versions = {}  # for versions mode: original path -> version
        t0 = time.perf_counter()
        archive = Archive(self._manifest, archive_name, consider_part_files=self._args.consider_part_files)
        strip_components = self._args.strip_components
        matcher = build_matcher(self._args.patterns, self._args.paths)
        hlm = HardLinkManager(id_type=bytes, info_type=str)  # hlid -> path

        filter = build_filter(matcher, strip_components)
        for item_inode, item in self.cache.iter_archive_items(
            archive.metadata.items, filter=filter, consider_part_files=self._args.consider_part_files
        ):
            if strip_components:
                item.path = os.sep.join(item.path.split(os.sep)[strip_components:])
            path = os.fsencode(item.path)
            is_dir = stat.S_ISDIR(item.mode)
            if is_dir:
                try:
                    # This can happen if an archive was created with a command line like
                    # $ borg create ... dir1/file dir1
                    # In this case the code below will have created a default_dir inode for dir1 already.
                    inode = self.find_inode(path, prefix)
                except KeyError:
                    pass
                else:
                    self._items[inode] = item
                    continue
            segments = prefix + path.split(b"/")
            parent = 1
            for segment in segments[:-1]:
                parent = self._process_inner(segment, parent)
            self._process_leaf(segments[-1], item, parent, prefix, is_dir, item_inode, hlm)
        duration = time.perf_counter() - t0
        logger.debug("fuse: _process_archive completed in %.1f s for archive %s", duration, archive.name)

    def _process_leaf(self, name, item, parent, prefix, is_dir, item_inode, hlm):
        path = item.path
        del item.path  # save some space

        def file_version(item, path):
            if "chunks" in item:
                file_id = blake2b_128(path)
                current_version, previous_id = self.versions_index.get(file_id, (0, None))

                contents_id = blake2b_128(b"".join(chunk_id for chunk_id, _ in item.chunks))

                if contents_id != previous_id:
                    current_version += 1
                    self.versions_index[file_id] = current_version, contents_id

                return current_version

        def make_versioned_name(name, version, add_dir=False):
            if add_dir:
                # add intermediate directory with same name as filename
                path_fname = name.rsplit(b"/", 1)
                name += b"/" + path_fname[-1]
            # keep original extension at end to avoid confusing tools
            name, ext = os.path.splitext(name)
            version_enc = os.fsencode(".%05d" % version)
            return name + version_enc + ext

        if "hlid" in item:
            link_target = hlm.retrieve(id=item.hlid, default=None)
            if link_target is not None:
                # Hard link was extracted previously, just link
                link_target = os.fsencode(link_target)
                if self.versions:
                    # adjust link target name with version
                    version = self.file_versions[link_target]
                    link_target = make_versioned_name(link_target, version, add_dir=True)
                try:
                    inode = self.find_inode(link_target, prefix)
                except KeyError:
                    logger.warning("Skipping broken hard link: %s -> %s", path, link_target)
                    return
                item = self.get_item(inode)
                item.nlink = item.get("nlink", 1) + 1
                self._items[inode] = item
            else:
                inode = item_inode
                self._items[inode] = item
                # remember extracted item path, so that following hardlinks don't extract twice.
                hlm.remember(id=item.hlid, info=path)
        else:
            inode = item_inode

        if self.versions and not is_dir:
            parent = self._process_inner(name, parent)
            enc_path = os.fsencode(path)
            version = file_version(item, enc_path)
            if version is not None:
                # regular file, with contents
                name = make_versioned_name(name, version)
                self.file_versions[enc_path] = version

        self.parent[inode] = parent
        if name:
            self.contents[parent][name] = inode

    def _process_inner(self, name, parent_inode):
        dir = self.contents[parent_inode]
        if name in dir:
            inode = dir[name]
        else:
            inode = self._create_dir(parent_inode)
            if name:
                dir[name] = inode
        return inode


class FuseOperations(llfuse.Operations, FuseBackend):
    """Export archive as a FUSE filesystem"""

    def __init__(self, manifest, args, decrypted_repository):
        llfuse.Operations.__init__(self)
        FuseBackend.__init__(self, manifest, args, decrypted_repository)
        self.decrypted_repository = decrypted_repository
        data_cache_capacity = int(os.environ.get("BORG_MOUNT_DATA_CACHE_ENTRIES", os.cpu_count() or 1))
        logger.debug("mount data cache capacity: %d chunks", data_cache_capacity)
        self.data_cache = LRUCache(capacity=data_cache_capacity, dispose=lambda _: None)
        self._last_pos = LRUCache(capacity=FILES, dispose=lambda _: None)

    def sig_info_handler(self, sig_no, stack):
        logger.debug(
            "fuse: %d synth inodes, %d edges (%s)",
            self.inode_count,
            len(self.parent),
            # getsizeof is the size of the dict itself; key and value are two small-ish integers,
            # which are shared due to code structure (this has been verified).
            format_file_size(sys.getsizeof(self.parent) + len(self.parent) * sys.getsizeof(self.inode_count)),
        )
        logger.debug("fuse: %d pending archives", len(self.pending_archives))
        logger.debug(
            "fuse: ItemCache %d entries (%d direct, %d indirect), meta-array size %s, direct items size %s",
            self.cache.direct_items + self.cache.indirect_items,
            self.cache.direct_items,
            self.cache.indirect_items,
            format_file_size(sys.getsizeof(self.cache.meta)),
            format_file_size(os.stat(self.cache.fd.fileno()).st_size),
        )
        logger.debug(
            "fuse: data cache: %d/%d entries, %s",
            len(self.data_cache.items()),
            self.data_cache._capacity,
            format_file_size(sum(len(chunk) for key, chunk in self.data_cache.items())),
        )
        self.decrypted_repository.log_instrumentation()

    def mount(self, mountpoint, mount_options, foreground=False):
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

        # default_permissions enables permission checking by the kernel. Without
        # this, any umask (or uid/gid) would not have an effect and this could
        # cause security issues if used with allow_other mount option.
        # When not using allow_other or allow_root, access is limited to the
        # mounting user anyway.
        options = ["fsname=borgfs", "ro", "default_permissions"]
        if mount_options:
            options.extend(mount_options.split(","))
        ignore_permissions = pop_option(options, "ignore_permissions", True, False, bool)
        if ignore_permissions:
            # in case users have a use-case that requires NOT giving "default_permissions",
            # this is enabled by the custom "ignore_permissions" mount option which just
            # removes "default_permissions" again:
            pop_option(options, "default_permissions", True, False, bool)
        self.allow_damaged_files = pop_option(options, "allow_damaged_files", True, False, bool)
        self.versions = pop_option(options, "versions", True, False, bool)
        self.uid_forced = pop_option(options, "uid", None, None, int)
        self.gid_forced = pop_option(options, "gid", None, None, int)
        self.umask = pop_option(options, "umask", 0, 0, int, int_base=8)  # umask is octal, e.g. 222 or 0222
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
        llfuse.init(self, mountpoint, options)
        if not foreground:
            if isinstance(self.repository_uncached, RemoteRepository):
                daemonize()
            else:
                with daemonizing() as (old_id, new_id):
                    # local repo: the locking process' PID is changing, migrate it:
                    logger.debug("fuse: mount local repo, going to background: migrating lock.")
                    self.repository_uncached.migrate_lock(old_id, new_id)

        # If the file system crashes, we do not want to umount because in that
        # case the mountpoint suddenly appears to become empty. This can have
        # nasty consequences, imagine the user has e.g. an active rsync mirror
        # job - seeing the mountpoint empty, rsync would delete everything in the
        # mirror.
        umount = False
        try:
            with signal_handler("SIGUSR1", self.sig_info_handler), signal_handler("SIGINFO", self.sig_info_handler):
                signal = fuse_main()
            # no crash and no signal (or it's ^C and we're in the foreground) -> umount request
            umount = signal is None or (signal == SIGINT and foreground)
        finally:
            llfuse.close(umount)

    @async_wrapper
    def statfs(self, ctx=None):
        stat_ = llfuse.StatvfsData()
        stat_.f_bsize = 512
        stat_.f_frsize = 512
        stat_.f_blocks = 0
        stat_.f_bfree = 0
        stat_.f_bavail = 0
        stat_.f_files = 0
        stat_.f_ffree = 0
        stat_.f_favail = 0
        stat_.f_namemax = 255  # == NAME_MAX (depends on archive source OS / FS)
        return stat_

    def _getattr(self, inode, ctx=None):
        item = self.get_item(inode)
        entry = llfuse.EntryAttributes()
        entry.st_ino = inode
        entry.generation = 0
        entry.entry_timeout = 300
        entry.attr_timeout = 300
        entry.st_mode = item.mode & ~self.umask
        entry.st_nlink = item.get("nlink", 1)
        entry.st_uid, entry.st_gid = get_item_uid_gid(
            item,
            numeric=self.numeric_ids,
            uid_default=self.default_uid,
            gid_default=self.default_gid,
            uid_forced=self.uid_forced,
            gid_forced=self.gid_forced,
        )
        entry.st_rdev = item.get("rdev", 0)
        entry.st_size = item.get_size()
        entry.st_blksize = 512
        entry.st_blocks = (entry.st_size + entry.st_blksize - 1) // entry.st_blksize
        # note: older archives only have mtime (not atime nor ctime)
        entry.st_mtime_ns = mtime_ns = item.mtime
        entry.st_atime_ns = item.get("atime", mtime_ns)
        entry.st_ctime_ns = item.get("ctime", mtime_ns)
        entry.st_birthtime_ns = item.get("birthtime", mtime_ns)
        return entry

    @async_wrapper
    def getattr(self, inode, ctx=None):
        return self._getattr(inode, ctx=ctx)

    @async_wrapper
    def listxattr(self, inode, ctx=None):
        item = self.get_item(inode)
        return item.get("xattrs", {}).keys()

    @async_wrapper
    def getxattr(self, inode, name, ctx=None):
        item = self.get_item(inode)
        try:
            return item.get("xattrs", {})[name] or b""
        except KeyError:
            raise llfuse.FUSEError(llfuse.ENOATTR) from None

    @async_wrapper
    def lookup(self, parent_inode, name, ctx=None):
        self.check_pending_archive(parent_inode)
        if name == b".":
            inode = parent_inode
        elif name == b"..":
            inode = self.parent[parent_inode]
        else:
            inode = self.contents[parent_inode].get(name)
            if not inode:
                raise llfuse.FUSEError(errno.ENOENT)
        return self._getattr(inode)

    @async_wrapper
    def open(self, inode, flags, ctx=None):
        if not self.allow_damaged_files:
            item = self.get_item(inode)
            if "chunks_healthy" in item:
                # Processed archive items don't carry the path anymore; for converting the inode
                # to the path we'd either have to store the inverse of the current structure,
                # or search the entire archive. So we just don't print it. It's easy to correlate anyway.
                logger.warning(
                    "File has damaged (all-zero) chunks. Try running borg check --repair. "
                    "Mount with allow_damaged_files to read damaged files."
                )
                raise llfuse.FUSEError(errno.EIO)
        return llfuse.FileInfo(fh=inode) if has_pyfuse3 else inode

    @async_wrapper
    def opendir(self, inode, ctx=None):
        self.check_pending_archive(inode)
        return inode

    @async_wrapper
    def read(self, fh, offset, size):
        parts = []
        item = self.get_item(fh)

        # optimize for linear reads:
        # we cache the chunk number and the in-file offset of the chunk in _last_pos[fh]
        chunk_no, chunk_offset = self._last_pos.get(fh, (0, 0))
        if chunk_offset > offset:
            # this is not a linear read, so we lost track and need to start from beginning again...
            chunk_no, chunk_offset = (0, 0)

        offset -= chunk_offset
        chunks = item.chunks
        # note: using index iteration to avoid frequently copying big (sub)lists by slicing
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
                    # evict fully read chunk from cache
                    del self.data_cache[id]
            else:
                _, data = self.repo_objs.parse(id, self.repository_uncached.get(id))
                if offset + n < len(data):
                    # chunk was only partially read, cache it
                    self.data_cache[id] = data
            parts.append(data[offset : offset + n])
            offset = 0
            size -= n
            if not size:
                if fh in self._last_pos:
                    self._last_pos.upd(fh, (chunk_no, chunk_offset))
                else:
                    self._last_pos[fh] = (chunk_no, chunk_offset)
                break
        return b"".join(parts)

    # note: we can't have a generator (with yield) and not a generator (async) in the same method
    if has_pyfuse3:

        async def readdir(self, fh, off, token):  # type: ignore[misc]
            entries = [(b".", fh), (b"..", self.parent[fh])]
            entries.extend(self.contents[fh].items())
            for i, (name, inode) in enumerate(entries[off:], off):
                attrs = self._getattr(inode)
                if not llfuse.readdir_reply(token, name, attrs, i + 1):
                    break

    else:

        def readdir(self, fh, off):  # type: ignore[misc]
            entries = [(b".", fh), (b"..", self.parent[fh])]
            entries.extend(self.contents[fh].items())
            for i, (name, inode) in enumerate(entries[off:], off):
                attrs = self._getattr(inode)
                yield name, attrs, i + 1

    @async_wrapper
    def readlink(self, inode, ctx=None):
        item = self.get_item(inode)
        return os.fsencode(item.source)

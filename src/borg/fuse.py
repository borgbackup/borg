import errno
import io
import os
import stat
import struct
import sys
import tempfile
import time
from collections import defaultdict
from signal import SIGINT
from distutils.version import LooseVersion
from zlib import adler32

import llfuse
import msgpack

from .logger import create_logger
logger = create_logger()

from .archive import Archive
from .helpers import daemonize, hardlinkable, signal_handler, format_file_size
from .item import Item
from .lrucache import LRUCache

# Does this version of llfuse support ns precision?
have_fuse_xtime_ns = hasattr(llfuse.EntryAttributes, 'st_mtime_ns')

fuse_version = LooseVersion(getattr(llfuse, '__version__', '0.1'))
if fuse_version >= '0.42':
    def fuse_main():
        return llfuse.main(workers=1)
else:
    def fuse_main():
        llfuse.main(single=True)
        return None


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

    indirect_entry_struct = struct.Struct('=cII')
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
        self.fd = tempfile.TemporaryFile(prefix='borg-tmp')

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
            raise ValueError('ItemCache.get() called with an invalid inode number')
        if self.meta[offset] == ord(b'I'):
            _, chunk_id_relative_offset, chunk_offset = self.indirect_entry_struct.unpack_from(self.meta, offset)
            chunk_id_offset = offset - chunk_id_relative_offset
            # bytearray slices are bytearrays as well, explicitly convert to bytes()
            chunk_id = bytes(self.meta[chunk_id_offset:chunk_id_offset + 32])
            chunk = self.chunks.get(chunk_id)
            if not chunk:
                csize, chunk = next(self.decrypted_repository.get_many([chunk_id]))
                self.chunks[chunk_id] = chunk
            data = memoryview(chunk)[chunk_offset:]
            unpacker = msgpack.Unpacker()
            unpacker.feed(data)
            return Item(internal_dict=next(unpacker))
        elif self.meta[offset] == ord(b'S'):
            fd_offset = int.from_bytes(self.meta[offset + 1:offset + 9], 'little')
            self.fd.seek(fd_offset, io.SEEK_SET)
            return Item(internal_dict=next(msgpack.Unpacker(self.fd, read_size=1024)))
        else:
            raise ValueError('Invalid entry type in self.meta')

    def iter_archive_items(self, archive_item_ids):
        unpacker = msgpack.Unpacker()

        # Current offset in the metadata stream, which consists of all metadata chunks glued together
        stream_offset = 0
        # Offset of the current chunk in the metadata stream
        chunk_begin = 0
        # Length of the chunk preciding the current chunk
        last_chunk_length = 0
        msgpacked_bytes = b''

        write_offset = self.write_offset
        meta = self.meta
        pack_indirect_into = self.indirect_entry_struct.pack_into

        def write_bytes(append_msgpacked_bytes):
            # XXX: Future versions of msgpack include an Unpacker.tell() method that provides this for free.
            nonlocal msgpacked_bytes
            nonlocal stream_offset
            msgpacked_bytes += append_msgpacked_bytes
            stream_offset += len(append_msgpacked_bytes)

        for key, (csize, data) in zip(archive_item_ids, self.decrypted_repository.get_many(archive_item_ids)):
            # Store the chunk ID in the meta-array
            if write_offset + 32 >= len(meta):
                self.meta = meta = meta + bytes(self.GROW_META_BY)
            meta[write_offset:write_offset + 32] = key
            current_id_offset = write_offset
            write_offset += 32

            # The chunk boundaries cannot be tracked through write_bytes, because the unpack state machine
            # *can* and *will* consume partial items, so calls to write_bytes are unrelated to chunk boundaries.
            chunk_begin += last_chunk_length
            last_chunk_length = len(data)

            unpacker.feed(data)
            while True:
                try:
                    item = unpacker.unpack(write_bytes)
                except msgpack.OutOfData:
                    # Need more data, feed the next chunk
                    break

                current_item = msgpacked_bytes
                current_item_length = len(current_item)
                current_spans_chunks = stream_offset - current_item_length < chunk_begin
                msgpacked_bytes = b''

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
                    meta[write_offset:write_offset + 9] = b'S' + pos.to_bytes(8, 'little')
                    self.direct_items += 1
                else:
                    item_offset = stream_offset - current_item_length - chunk_begin
                    pack_indirect_into(meta, write_offset, b'I', write_offset - current_id_offset, item_offset)
                    self.indirect_items += 1
                inode = write_offset + self.offset
                write_offset += 9

                yield inode, Item(internal_dict=item)

        self.write_offset = write_offset


class FuseOperations(llfuse.Operations):
    """Export archive as a fuse filesystem
    """
    # mount options
    allow_damaged_files = False
    versions = False

    def __init__(self, key, repository, manifest, args, decrypted_repository):
        super().__init__()
        self.repository_uncached = repository
        self.decrypted_repository = decrypted_repository
        self.args = args
        self.manifest = manifest
        self.key = key
        # Maps inode numbers to Item instances. This is used for synthetic inodes,
        # i.e. file-system objects that are made up by FuseOperations and are not contained
        # in the archives. For example archive directories or intermediate directories
        # not contained in archives.
        self.items = {}
        # _inode_count is the current count of synthetic inodes, i.e. those in self.items
        self._inode_count = 0
        # Maps inode numbers to the inode number of the parent
        self.parent = {}
        # Maps inode numbers to a dictionary mapping byte directory entry names to their inode numbers,
        # i.e. this contains all dirents of everything that is mounted. (It becomes really big).
        self.contents = defaultdict(dict)
        self.default_uid = os.getuid()
        self.default_gid = os.getgid()
        self.default_dir = Item(mode=0o40755, mtime=int(time.time() * 1e9), uid=self.default_uid, gid=self.default_gid)
        self.pending_archives = {}
        self.cache = ItemCache(decrypted_repository)
        data_cache_capacity = int(os.environ.get('BORG_MOUNT_DATA_CACHE_ENTRIES', os.cpu_count() or 1))
        logger.debug('mount data cache capacity: %d chunks', data_cache_capacity)
        self.data_cache = LRUCache(capacity=data_cache_capacity, dispose=lambda _: None)

    def _create_filesystem(self):
        self._create_dir(parent=1)  # first call, create root dir (inode == 1)
        if self.args.location.archive:
            self.process_archive(self.args.location.archive)
        else:
            archive_names = (x.name for x in self.manifest.archives.list_considering(self.args))
            for archive_name in archive_names:
                if self.versions:
                    # process archives immediately
                    self.process_archive(archive_name)
                else:
                    # lazy load archives, create archive placeholder inode
                    archive_inode = self._create_dir(parent=1)
                    self.contents[1][os.fsencode(archive_name)] = archive_inode
                    self.pending_archives[archive_inode] = archive_name

    def sig_info_handler(self, sig_no, stack):
        logger.debug('fuse: %d synth inodes, %d edges (%s)',
                     self._inode_count, len(self.parent),
                     # getsizeof is the size of the dict itself; key and value are two small-ish integers,
                     # which are shared due to code structure (this has been verified).
                     format_file_size(sys.getsizeof(self.parent) + len(self.parent) * sys.getsizeof(self._inode_count)))
        logger.debug('fuse: %d pending archives', len(self.pending_archives))
        logger.debug('fuse: ItemCache %d entries (%d direct, %d indirect), meta-array size %s, direct items size %s',
                     self.cache.direct_items + self.cache.indirect_items, self.cache.direct_items, self.cache.indirect_items,
                     format_file_size(sys.getsizeof(self.cache.meta)),
                     format_file_size(os.stat(self.cache.fd.fileno()).st_size))
        logger.debug('fuse: data cache: %d/%d entries, %s', len(self.data_cache.items()), self.data_cache._capacity,
                     format_file_size(sum(len(chunk) for key, chunk in self.data_cache.items())))
        self.decrypted_repository.log_instrumentation()

    def mount(self, mountpoint, mount_options, foreground=False):
        """Mount filesystem on *mountpoint* with *mount_options*."""
        options = ['fsname=borgfs', 'ro']
        if mount_options:
            options.extend(mount_options.split(','))
        try:
            options.remove('allow_damaged_files')
            self.allow_damaged_files = True
        except ValueError:
            pass
        try:
            options.remove('versions')
            self.versions = True
        except ValueError:
            pass
        self._create_filesystem()
        llfuse.init(self, mountpoint, options)
        if not foreground:
            daemonize()

        # If the file system crashes, we do not want to umount because in that
        # case the mountpoint suddenly appears to become empty. This can have
        # nasty consequences, imagine the user has e.g. an active rsync mirror
        # job - seeing the mountpoint empty, rsync would delete everything in the
        # mirror.
        umount = False
        try:
            with signal_handler('SIGUSR1', self.sig_info_handler), \
                 signal_handler('SIGINFO', self.sig_info_handler):
                signal = fuse_main()
            # no crash and no signal (or it's ^C and we're in the foreground) -> umount request
            umount = (signal is None or (signal == SIGINT and foreground))
        finally:
            llfuse.close(umount)

    def _create_dir(self, parent):
        """Create directory
        """
        ino = self.allocate_inode()
        self.items[ino] = self.default_dir
        self.parent[ino] = parent
        return ino

    def process_archive(self, archive_name, prefix=[]):
        """Build fuse inode hierarchy from archive metadata
        """
        self.file_versions = {}  # for versions mode: original path -> version
        t0 = time.perf_counter()
        archive = Archive(self.repository_uncached, self.key, self.manifest, archive_name,
                          consider_part_files=self.args.consider_part_files)
        for item_inode, item in self.cache.iter_archive_items(archive.metadata.items):
            path = os.fsencode(item.path)
            is_dir = stat.S_ISDIR(item.mode)
            if is_dir:
                try:
                    # This can happen if an archive was created with a command line like
                    # $ borg create ... dir1/file dir1
                    # In this case the code below will have created a default_dir inode for dir1 already.
                    inode = self._find_inode(path, prefix)
                except KeyError:
                    pass
                else:
                    self.items[inode] = item
                    continue
            segments = prefix + path.split(b'/')
            parent = 1
            for segment in segments[:-1]:
                parent = self.process_inner(segment, parent)
            self.process_leaf(segments[-1], item, parent, prefix, is_dir, item_inode)
        duration = time.perf_counter() - t0
        logger.debug('fuse: process_archive completed in %.1f s for archive %s', duration, archive.name)

    def process_leaf(self, name, item, parent, prefix, is_dir, item_inode):
        def file_version(item):
            if 'chunks' in item:
                ident = 0
                for chunkid, _, _ in item.chunks:
                    ident = adler32(chunkid, ident)
                return ident

        def make_versioned_name(name, version, add_dir=False):
            if add_dir:
                # add intermediate directory with same name as filename
                path_fname = name.rsplit(b'/', 1)
                name += b'/' + path_fname[-1]
            return name + os.fsencode('.%08x' % version)

        if self.versions and not is_dir:
            parent = self.process_inner(name, parent)
            version = file_version(item)
            if version is not None:
                # regular file, with contents - maybe a hardlink master
                name = make_versioned_name(name, version)
                path = os.fsencode(item.path)
                self.file_versions[path] = version

        path = item.path
        del item.path  # safe some space
        if 'source' in item and hardlinkable(item.mode):
            # a hardlink, no contents, <source> is the hardlink master
            source = os.fsencode(item.source)
            if self.versions:
                # adjust source name with version
                version = self.file_versions[source]
                source = make_versioned_name(source, version, add_dir=True)
                name = make_versioned_name(name, version)
            try:
                inode = self._find_inode(source, prefix)
            except KeyError:
                logger.warning('Skipping broken hard link: %s -> %s', path, item.source)
                return
            item = self.cache.get(inode)
            item.nlink = item.get('nlink', 1) + 1
            self.items[inode] = item
        else:
            inode = item_inode
        self.parent[inode] = parent
        if name:
            self.contents[parent][name] = inode

    def process_inner(self, name, parent_inode):
        dir = self.contents[parent_inode]
        if name in dir:
            inode = dir[name]
        else:
            inode = self._create_dir(parent_inode)
            if name:
                dir[name] = inode
        return inode

    def allocate_inode(self):
        self._inode_count += 1
        return self._inode_count

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
        return stat_

    def get_item(self, inode):
        try:
            return self.items[inode]
        except KeyError:
            return self.cache.get(inode)

    def _find_inode(self, path, prefix=[]):
        segments = prefix + path.split(b'/')
        inode = 1
        for segment in segments:
            inode = self.contents[inode][segment]
        return inode

    def getattr(self, inode, ctx=None):
        item = self.get_item(inode)
        entry = llfuse.EntryAttributes()
        entry.st_ino = inode
        entry.generation = 0
        entry.entry_timeout = 300
        entry.attr_timeout = 300
        entry.st_mode = item.mode
        entry.st_nlink = item.get('nlink', 1)
        entry.st_uid = item.uid if item.uid >= 0 else self.default_uid
        entry.st_gid = item.gid if item.gid >= 0 else self.default_gid
        entry.st_rdev = item.get('rdev', 0)
        entry.st_size = item.get_size()
        entry.st_blksize = 512
        entry.st_blocks = (entry.st_size + entry.st_blksize - 1) // entry.st_blksize
        # note: older archives only have mtime (not atime nor ctime)
        mtime_ns = item.mtime
        if have_fuse_xtime_ns:
            entry.st_mtime_ns = mtime_ns
            entry.st_atime_ns = item.get('atime', mtime_ns)
            entry.st_ctime_ns = item.get('ctime', mtime_ns)
        else:
            entry.st_mtime = mtime_ns / 1e9
            entry.st_atime = item.get('atime', mtime_ns) / 1e9
            entry.st_ctime = item.get('ctime', mtime_ns) / 1e9
        return entry

    def listxattr(self, inode, ctx=None):
        item = self.get_item(inode)
        return item.get('xattrs', {}).keys()

    def getxattr(self, inode, name, ctx=None):
        item = self.get_item(inode)
        try:
            return item.get('xattrs', {})[name] or b''
        except KeyError:
            raise llfuse.FUSEError(llfuse.ENOATTR) from None

    def _load_pending_archive(self, inode):
        # Check if this is an archive we need to load
        archive_name = self.pending_archives.pop(inode, None)
        if archive_name:
            self.process_archive(archive_name, [os.fsencode(archive_name)])

    def lookup(self, parent_inode, name, ctx=None):
        self._load_pending_archive(parent_inode)
        if name == b'.':
            inode = parent_inode
        elif name == b'..':
            inode = self.parent[parent_inode]
        else:
            inode = self.contents[parent_inode].get(name)
            if not inode:
                raise llfuse.FUSEError(errno.ENOENT)
        return self.getattr(inode)

    def open(self, inode, flags, ctx=None):
        if not self.allow_damaged_files:
            item = self.get_item(inode)
            if 'chunks_healthy' in item:
                # Processed archive items don't carry the path anymore; for converting the inode
                # to the path we'd either have to store the inverse of the current structure,
                # or search the entire archive. So we just don't print it. It's easy to correlate anyway.
                logger.warning('File has damaged (all-zero) chunks. Try running borg check --repair. '
                               'Mount with allow_damaged_files to read damaged files.')
                raise llfuse.FUSEError(errno.EIO)
        return inode

    def opendir(self, inode, ctx=None):
        self._load_pending_archive(inode)
        return inode

    def read(self, fh, offset, size):
        parts = []
        item = self.get_item(fh)
        for id, s, csize in item.chunks:
            if s < offset:
                offset -= s
                continue
            n = min(size, s - offset)
            if id in self.data_cache:
                data = self.data_cache[id]
                if offset + n == len(data):
                    # evict fully read chunk from cache
                    del self.data_cache[id]
            else:
                data = self.key.decrypt(id, self.repository_uncached.get(id))
                if offset + n < len(data):
                    # chunk was only partially read, cache it
                    self.data_cache[id] = data
            parts.append(data[offset:offset + n])
            offset = 0
            size -= n
            if not size:
                break
        return b''.join(parts)

    def readdir(self, fh, off):
        entries = [(b'.', fh), (b'..', self.parent[fh])]
        entries.extend(self.contents[fh].items())
        for i, (name, inode) in enumerate(entries[off:], off):
            yield name, self.getattr(inode), i + 1

    def readlink(self, inode, ctx=None):
        item = self.get_item(inode)
        return os.fsencode(item.source)

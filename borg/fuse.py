from collections import defaultdict
import errno
import io
import llfuse
import os
import stat
import tempfile
import time
from distutils.version import LooseVersion

import msgpack

from .archive import Archive
from .helpers import daemonize, bigint_to_int
from .logger import create_logger
from .lrucache import LRUCache
logger = create_logger()


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
    def __init__(self):
        self.fd = tempfile.TemporaryFile(prefix='borg-tmp')
        self.offset = 1000000

    def add(self, item):
        pos = self.fd.seek(0, io.SEEK_END)
        self.fd.write(msgpack.packb(item))
        return pos + self.offset

    def get(self, inode):
        self.fd.seek(inode - self.offset, io.SEEK_SET)
        return next(msgpack.Unpacker(self.fd, read_size=1024))


class FuseOperations(llfuse.Operations):
    """Export archive as a fuse filesystem
    """

    allow_damaged_files = False

    def __init__(self, key, repository, manifest, archive, cached_repo):
        super().__init__()
        self._inode_count = 0
        self.key = key
        self.repository = cached_repo
        self.items = {}
        self.parent = {}
        self.contents = defaultdict(dict)
        self.default_dir = {b'mode': 0o40755, b'mtime': int(time.time() * 1e9), b'uid': os.getuid(), b'gid': os.getgid()}
        self.pending_archives = {}
        self.accounted_chunks = {}
        self.cache = ItemCache()
        data_cache_capacity = int(os.environ.get('BORG_MOUNT_DATA_CACHE_ENTRIES', os.cpu_count() or 1))
        logger.debug('mount data cache capacity: %d chunks', data_cache_capacity)
        self.data_cache = LRUCache(capacity=data_cache_capacity, dispose=lambda _: None)
        self._create_dir(parent=1)  # first call, create root dir (inode == 1)
        if archive:
            self.process_archive(archive)
        else:
            for archive_name in manifest.archives:
                # Create archive placeholder inode
                archive_inode = self._create_dir(parent=1)
                self.contents[1][os.fsencode(archive_name)] = archive_inode
                self.pending_archives[archive_inode] = Archive(repository, key, manifest, archive_name)

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
            signal = fuse_main()
            umount = (signal is None)  # no crash and no signal -> umount request
        finally:
            llfuse.close(umount)

    def _create_dir(self, parent):
        """Create directory
        """
        ino = self.allocate_inode()
        self.items[ino] = self.default_dir
        self.parent[ino] = parent
        return ino

    def process_archive(self, archive, prefix=[]):
        """Build fuse inode hierarchy from archive metadata
        """
        unpacker = msgpack.Unpacker()
        for key, chunk in zip(archive.metadata[b'items'], self.repository.get_many(archive.metadata[b'items'])):
            data = self.key.decrypt(key, chunk)
            unpacker.feed(data)
            for item in unpacker:
                try:
                    # This can happen if an archive was created with a command line like
                    # $ borg create ... dir1/file dir1
                    # In this case the code below will have created a default_dir inode for dir1 already.
                    inode = self._find_inode(item[b'path'], prefix)
                except KeyError:
                    pass
                else:
                    self.items[inode] = item
                    continue
                segments = prefix + os.fsencode(os.path.normpath(item[b'path'])).split(b'/')
                del item[b'path']
                num_segments = len(segments)
                parent = 1
                for i, segment in enumerate(segments, 1):
                    # Leaf segment?
                    if i == num_segments:
                        if b'source' in item and stat.S_ISREG(item[b'mode']):
                            inode = self._find_inode(item[b'source'], prefix)
                            item = self.cache.get(inode)
                            item[b'nlink'] = item.get(b'nlink', 1) + 1
                            self.items[inode] = item
                        else:
                            inode = self.cache.add(item)
                        self.parent[inode] = parent
                        if segment:
                            self.contents[parent][segment] = inode
                    elif segment in self.contents[parent]:
                        parent = self.contents[parent][segment]
                    else:
                        inode = self._create_dir(parent)
                        if segment:
                            self.contents[parent][segment] = inode
                        parent = inode

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
        segments = prefix + os.fsencode(os.path.normpath(path)).split(b'/')
        inode = 1
        for segment in segments:
            inode = self.contents[inode][segment]
        return inode

    def getattr(self, inode, ctx=None):
        item = self.get_item(inode)
        size = 0
        dsize = 0
        try:
            for key, chunksize, _ in item[b'chunks']:
                size += chunksize
                if self.accounted_chunks.get(key, inode) == inode:
                    self.accounted_chunks[key] = inode
                    dsize += chunksize
        except KeyError:
            pass
        entry = llfuse.EntryAttributes()
        entry.st_ino = inode
        entry.generation = 0
        entry.entry_timeout = 300
        entry.attr_timeout = 300
        entry.st_mode = item[b'mode']
        entry.st_nlink = item.get(b'nlink', 1)
        entry.st_uid = item[b'uid']
        entry.st_gid = item[b'gid']
        entry.st_rdev = item.get(b'rdev', 0)
        entry.st_size = size
        entry.st_blksize = 512
        entry.st_blocks = dsize / 512
        # note: older archives only have mtime (not atime nor ctime)
        if have_fuse_xtime_ns:
            entry.st_mtime_ns = bigint_to_int(item[b'mtime'])
            if b'atime' in item:
                entry.st_atime_ns = bigint_to_int(item[b'atime'])
            else:
                entry.st_atime_ns = bigint_to_int(item[b'mtime'])
            if b'ctime' in item:
                entry.st_ctime_ns = bigint_to_int(item[b'ctime'])
            else:
                entry.st_ctime_ns = bigint_to_int(item[b'mtime'])
        else:
            entry.st_mtime = bigint_to_int(item[b'mtime']) / 1e9
            if b'atime' in item:
                entry.st_atime = bigint_to_int(item[b'atime']) / 1e9
            else:
                entry.st_atime = bigint_to_int(item[b'mtime']) / 1e9
            if b'ctime' in item:
                entry.st_ctime = bigint_to_int(item[b'ctime']) / 1e9
            else:
                entry.st_ctime = bigint_to_int(item[b'mtime']) / 1e9
        return entry

    def listxattr(self, inode, ctx=None):
        item = self.get_item(inode)
        return item.get(b'xattrs', {}).keys()

    def getxattr(self, inode, name, ctx=None):
        item = self.get_item(inode)
        try:
            return item.get(b'xattrs', {})[name]
        except KeyError:
            raise llfuse.FUSEError(llfuse.ENOATTR) from None

    def _load_pending_archive(self, inode):
        # Check if this is an archive we need to load
        archive = self.pending_archives.pop(inode, None)
        if archive:
            self.process_archive(archive, [os.fsencode(archive.name)])

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
            if b'chunks_healthy' in item:
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
        for id, s, csize in item[b'chunks']:
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
                data = self.key.decrypt(id, self.repository.get(id))
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
        return os.fsencode(item[b'source'])

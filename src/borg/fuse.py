import errno
import io
import os
import stat
import tempfile
import time
from collections import defaultdict
from distutils.version import LooseVersion

import llfuse
import msgpack

from .logger import create_logger
logger = create_logger()

from .archive import Archive
from .helpers import daemonize
from .item import Item
from .lrucache import LRUCache
from .helpers import Manifest
from .remote import cache_if_remote


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
        self.fd.write(msgpack.packb(item.as_dict()))
        return pos + self.offset

    def get(self, inode):
        self.fd.seek(inode - self.offset, io.SEEK_SET)
        item = next(msgpack.Unpacker(self.fd, read_size=1024))
        return Item(internal_dict=item)


class FuseOperations(llfuse.Operations):
    """Export archive as a fuse filesystem
    """
    def __init__(self, repository, archive_name):
      with repository:
        self.key, self.manifest = Manifest.load(repository)
        super().__init__()
        self._inode_count = 0
        self.repository = repository
        self.items = {}
        self.parent = {}
        self.contents = defaultdict(dict)
        self.default_dir = Item(mode=0o40755, mtime=int(time.time() * 1e9), uid=os.getuid(), gid=os.getgid())
        self.pending_archives = {}
        self.accounted_chunks = {}
        self.cache = ItemCache()
        data_cache_capacity = int(os.environ.get('BORG_MOUNT_DATA_CACHE_ENTRIES', os.cpu_count() or 1))
        logger.debug('mount data cache capacity: %d chunks', data_cache_capacity)
        self.data_cache = LRUCache(capacity=data_cache_capacity, dispose=lambda _: None)
        if archive_name:
            archive = Archive(repository, self.key, self.manifest, archive_name)
            self.process_archive(archive)
        else:
            # Create root inode
            self.parent[1] = self.allocate_inode()
            self.items[1] = self.default_dir
            for archive_name in self.manifest.archives:
                # Create archive placeholder inode
                archive_inode = self.allocate_inode()
                self.items[archive_inode] = self.default_dir
                self.parent[archive_inode] = 1
                self.contents[1][os.fsencode(archive_name)] = archive_inode
                self.pending_archives[archive_inode] = archive_name

    def process_archive(self, archive, prefix=[]):
      """Build fuse inode hierarchy from archive metadata
      """
      with self.repository:
       with cache_if_remote(self.repository) as cached_repo:
        unpacker = msgpack.Unpacker()
        for key, chunk in zip(archive.metadata[b'items'], cached_repo.get_many(archive.metadata[b'items'])):
            _, data = self.key.decrypt(key, chunk)
            unpacker.feed(data)
            for item in unpacker:
                item = Item(internal_dict=item)
                segments = prefix + os.fsencode(os.path.normpath(item.path)).split(b'/')
                del item.path
                num_segments = len(segments)
                parent = 1
                for i, segment in enumerate(segments, 1):
                    # Insert a default root inode if needed
                    if self._inode_count == 0 and segment:
                        archive_inode = self.allocate_inode()
                        self.items[archive_inode] = self.default_dir
                        self.parent[archive_inode] = parent
                    # Leaf segment?
                    if i == num_segments:
                        if 'source' in item and stat.S_ISREG(item.mode):
                            inode = self._find_inode(item.source, prefix)
                            item = self.cache.get(inode)
                            item.nlink = item.get('nlink', 1) + 1
                            self.items[inode] = item
                        else:
                            inode = self.cache.add(item)
                        self.parent[inode] = parent
                        if segment:
                            self.contents[parent][segment] = inode
                    elif segment in self.contents[parent]:
                        parent = self.contents[parent][segment]
                    else:
                        inode = self.allocate_inode()
                        self.items[inode] = self.default_dir
                        self.parent[inode] = parent
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
        if 'chunks' in item:
            for key, chunksize, _ in item.chunks:
                size += chunksize
                if self.accounted_chunks.get(key, inode) == inode:
                    self.accounted_chunks[key] = inode
                    dsize += chunksize
        entry = llfuse.EntryAttributes()
        entry.st_ino = inode
        entry.generation = 0
        entry.entry_timeout = 300
        entry.attr_timeout = 300
        entry.st_mode = item.mode
        entry.st_nlink = item.get('nlink', 1)
        entry.st_uid = item.uid
        entry.st_gid = item.gid
        entry.st_rdev = item.get('rdev', 0)
        entry.st_size = size
        entry.st_blksize = 512
        entry.st_blocks = dsize / 512
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
            return item.get('xattrs', {})[name]
        except KeyError:
            raise llfuse.FUSEError(errno.ENODATA) from None

    def _load_pending_archive(self, inode):
      with self.repository:
       with cache_if_remote(self.repository) as cached_repo:
        # Check if this is an archive we need to load
        archive_name = self.pending_archives.pop(inode, None)
        archive = Archive(cached_repo, self.key, self.manifest, archive_name)
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
        return inode

    def opendir(self, inode, ctx=None):
        self._load_pending_archive(inode)
        return inode

    def read(self, fh, offset, size):
      with self.repository:
       with cache_if_remote(self.repository) as cached_repo:
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
                _, data = self.key.decrypt(id, cached_repo.get(id))
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

    def mount(self, mountpoint, extra_options, foreground=False):
        options = ['fsname=borgfs', 'ro']
        if extra_options:
            options.extend(extra_options.split(','))
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

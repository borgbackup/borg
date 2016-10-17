import errno
import io
import os
import stat
import tempfile
import time
from collections import defaultdict
from distutils.version import LooseVersion
from zlib import adler32

import llfuse
import msgpack

from .logger import create_logger
logger = create_logger()

from .archive import Archive
from .helpers import daemonize
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
    def __init__(self):
        self.fd = tempfile.TemporaryFile(prefix='borg-tmp')
        self.offset = 1000000

    def add(self, item):
        pos = self.fd.seek(0, io.SEEK_END)
        self.fd.write(msgpack.packb(item.as_dict()))
        return pos + self.offset

    def get(self, inode):
        offset = inode - self.offset
        if offset < 0:
            raise ValueError('ItemCache.get() called with an invalid inode number')
        self.fd.seek(offset, io.SEEK_SET)
        item = next(msgpack.Unpacker(self.fd, read_size=1024))
        return Item(internal_dict=item)


class FuseOperations(llfuse.Operations):
    """Export archive as a fuse filesystem
    """
    # mount options
    allow_damaged_files = False
    versions = False

    def __init__(self, key, repository, manifest, args, cached_repo):
        super().__init__()
        self.repository_uncached = repository
        self.repository = cached_repo
        self.args = args
        self.manifest = manifest
        self.key = key
        self._inode_count = 0
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

    def _create_filesystem(self):
        self._create_dir(parent=1)  # first call, create root dir (inode == 1)
        if self.args.location.archive:
            archive = Archive(self.repository_uncached, self.key, self.manifest, self.args.location.archive,
                              consider_part_files=self.args.consider_part_files)
            self.process_archive(archive)
        else:
            archive_names = (x.name for x in self.manifest.archives.list_considering(self.args))
            for name in archive_names:
                archive = Archive(self.repository_uncached, self.key, self.manifest, name,
                                  consider_part_files=self.args.consider_part_files)
                if self.versions:
                    # process archives immediately
                    self.process_archive(archive)
                else:
                    # lazy load archives, create archive placeholder inode
                    archive_inode = self._create_dir(parent=1)
                    self.contents[1][os.fsencode(name)] = archive_inode
                    self.pending_archives[archive_inode] = archive

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
        self.file_versions = {}  # for versions mode: original path -> version
        unpacker = msgpack.Unpacker()
        for key, chunk in zip(archive.metadata.items, self.repository.get_many(archive.metadata.items)):
            _, data = self.key.decrypt(key, chunk)
            unpacker.feed(data)
            for item in unpacker:
                item = Item(internal_dict=item)
                path = os.fsencode(os.path.normpath(item.path))
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
                self.process_leaf(segments[-1], item, parent, prefix, is_dir)

    def process_leaf(self, name, item, parent, prefix, is_dir):
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
                path = os.fsencode(os.path.normpath(item.path))
                self.file_versions[path] = version

        del item.path  # safe some space
        if 'source' in item and stat.S_ISREG(item.mode):
            # a hardlink, no contents, <source> is the hardlink master
            source = os.fsencode(os.path.normpath(item.source))
            if self.versions:
                # adjust source name with version
                version = self.file_versions[source]
                source = make_versioned_name(source, version, add_dir=True)
                name = make_versioned_name(name, version)
            inode = self._find_inode(source, prefix)
            item = self.cache.get(inode)
            item.nlink = item.get('nlink', 1) + 1
            self.items[inode] = item
        else:
            inode = self.cache.add(item)
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
                _, data = self.key.decrypt(id, self.repository.get(id))
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

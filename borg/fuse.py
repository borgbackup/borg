from collections import defaultdict
import errno
import io
import llfuse
import msgpack
import os
import stat
import tempfile
import time
from .archive import Archive
from .helpers import daemonize
from .remote import cache_if_remote

# Does this version of llfuse support ns precision?
have_fuse_mtime_ns = hasattr(llfuse.EntryAttributes, 'st_mtime_ns')


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
        return next(msgpack.Unpacker(self.fd))


class FuseOperations(llfuse.Operations):
    """Export archive as a fuse filesystem
    """
    def __init__(self, key, repository, manifest, archive):
        super().__init__()
        self._inode_count = 0
        self.key = key
        self.repository = cache_if_remote(repository)
        self.items = {}
        self.parent = {}
        self.contents = defaultdict(dict)
        self.default_dir = {b'mode': 0o40755, b'mtime': int(time.time() * 1e9), b'uid': os.getuid(), b'gid': os.getgid()}
        self.pending_archives = {}
        self.accounted_chunks = {}
        self.cache = ItemCache()
        if archive:
            self.process_archive(archive)
        else:
            # Create root inode
            self.parent[1] = self.allocate_inode()
            self.items[1] = self.default_dir
            for archive_name in manifest.archives:
                # Create archive placeholder inode
                archive_inode = self.allocate_inode()
                self.items[archive_inode] = self.default_dir
                self.parent[archive_inode] = 1
                self.contents[1][os.fsencode(archive_name)] = archive_inode
                self.pending_archives[archive_inode] = Archive(repository, key, manifest, archive_name)

    def process_archive(self, archive, prefix=[]):
        """Build fuse inode hierarchy from archive metadata
        """
        unpacker = msgpack.Unpacker()
        for key, chunk in zip(archive.metadata[b'items'], self.repository.get_many(archive.metadata[b'items'])):
            data = self.key.decrypt(key, chunk)
            unpacker.feed(data)
            for item in unpacker:
                segments = prefix + os.fsencode(os.path.normpath(item[b'path'])).split(b'/')
                del item[b'path']
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
                        inode = self.allocate_inode()
                        self.items[inode] = self.default_dir
                        self.parent[inode] = parent
                        if segment:
                            self.contents[parent][segment] = inode
                        parent = inode

    def allocate_inode(self):
        self._inode_count += 1
        return self._inode_count

    def statfs(self):
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

    def getattr(self, inode):
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
        if have_fuse_mtime_ns:
            entry.st_atime_ns = item[b'mtime']
            entry.st_mtime_ns = item[b'mtime']
            entry.st_ctime_ns = item[b'mtime']
        else:
            entry.st_atime = item[b'mtime'] / 1e9
            entry.st_mtime = item[b'mtime'] / 1e9
            entry.st_ctime = item[b'mtime'] / 1e9
        return entry

    def listxattr(self, inode):
        item = self.get_item(inode)
        return item.get(b'xattrs', {}).keys()

    def getxattr(self, inode, name):
        item = self.get_item(inode)
        try:
            return item.get(b'xattrs', {})[name]
        except KeyError:
            raise llfuse.FUSEError(errno.ENODATA)

    def _load_pending_archive(self, inode):
        # Check if this is an archive we need to load
        archive = self.pending_archives.pop(inode, None)
        if archive:
            self.process_archive(archive, [os.fsencode(archive.name)])

    def lookup(self, parent_inode, name):
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

    def open(self, inode, flags):
        return inode

    def opendir(self, inode):
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
            chunk = self.key.decrypt(id, self.repository.get(id))
            parts.append(chunk[offset:offset+n])
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

    def readlink(self, inode):
        item = self.get_item(inode)
        return os.fsencode(item[b'source'])

    def mount(self, mountpoint, extra_options, foreground=False):
        options = ['fsname=borgfs', 'ro']
        if extra_options:
            options.extend(extra_options.split(','))
        llfuse.init(self, mountpoint, options)
        if not foreground:
            daemonize()
        try:
            llfuse.main(single=True)
        finally:
            llfuse.close()

from collections import defaultdict
import errno
import llfuse
import os
import stat
import time

from attic.helpers import daemonize
# Does this version of llfuse support ns precision?
have_fuse_mtime_ns = hasattr(llfuse.EntryAttributes, 'st_mtime_ns')


class AtticOperations(llfuse.Operations):
    """Export Attic archive as a fuse filesystem
    """
    def __init__(self, key, repository, archive):
        super(AtticOperations, self).__init__()
        self._inode_count = 0
        self.key = key
        self.repository = repository
        self.items = {}
        self.parent = {}
        self.contents = defaultdict(dict)
        default_dir = {b'mode': 0o40755, b'mtime': int(time.time() * 1e9), b'uid': os.getuid(), b'gid': os.getgid()}
        # Loop through all archive items and assign inode numbers and
        # extract hierarchy information
        for item in archive.iter_items():
            segments = os.fsencode(os.path.normpath(item[b'path'])).split(b'/')
            num_segments = len(segments)
            parent = 1
            for i, segment in enumerate(segments, 1):
                # Insert a default root inode if needed
                if self._inode_count == 0 and segment:
                    self.items[self.allocate_inode()] = default_dir
                    self.parent[1] = 1
                # Leaf segment?
                if i == num_segments:
                    if b'source' in item and stat.S_ISREG(item[b'mode']):
                        inode = self._find_inode(item[b'source'])
                        self.items[inode][b'nlink'] = self.items[inode].get(b'nlink', 1) + 1
                    else:
                        inode = self.allocate_inode()
                        self.items[inode] = item
                    self.parent[inode] = parent
                    if segment:
                        self.contents[parent][segment] = inode
                elif segment in self.contents[parent]:
                    parent = self.contents[parent][segment]
                else:
                    inode = self.allocate_inode()
                    self.items[inode] = default_dir
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

    def _find_inode(self, path):
        segments = os.fsencode(os.path.normpath(path)).split(b'/')
        inode = 1
        for segment in segments:
            inode = self.contents[inode][segment]
        return inode

    def getattr(self, inode):
        item = self.items[inode]
        size = 0
        try:
            size = sum(size for _, size, _ in item[b'chunks'])
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
        entry.st_blocks = 1
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
        item = self.items[inode]
        return item.get(b'xattrs', {}).keys()

    def getxattr(self, inode, name):
        item = self.items[inode]
        try:
            return item.get(b'xattrs', {})[name]
        except KeyError:
            raise llfuse.FUSEError(errno.ENODATA)

    def lookup(self, parent_inode, name):
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
        return inode

    def read(self, fh, offset, size):
        parts = []
        item = self.items[fh]
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
        return os.fsencode(self.items[inode][b'source'])

    def mount(self, mountpoint, extra_options, foreground=False):
        options = ['fsname=atticfs', 'ro']
        if extra_options:
            options.extend(extra_options.split(','))
        llfuse.init(self, mountpoint, options)
        if not foreground:
            daemonize()
        try:
            llfuse.main(single=True)
        except:
            llfuse.close()
            raise
        llfuse.close()

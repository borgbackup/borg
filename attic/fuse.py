from collections import defaultdict
import errno
import llfuse
import os
import time

# TODO
# - multi archive
# hard links

class AtticOperations(llfuse.Operations):
    """
    """
    def __init__(self, key, repository, archive):
        super(AtticOperations, self).__init__()
        print('__init__')
        self.key = key
        self.repository = repository
        self.items = {}
        self.inodes = {}
        self.inode_parent = {}
        self.inode_contents = defaultdict(dict)

        for item, _ in archive.iter_items():
            head, tail = os.path.split(os.path.normpath(os.fsencode(item[b'path'])))
            segments = head.split(b'/')
            parent = 1
            for segment in segments:
                if not segment:
                    continue
                if not segment in self.inode_contents[parent]:
                    node = self._make_directory_inode()
                    self.inodes[node.st_ino] = node
                    self.inode_parent[node.st_ino] = parent
                    self.inode_contents[parent][segment] = node.st_ino
                    parent = node.st_ino
                else:
                    parent = self.inode_contents[parent][segment]

            node = self._make_item_inode(item)
            node.st_nlink += 1
            self.inodes[node.st_ino] = node
            self.items[node.st_ino] = item
            self.inode_parent[node.st_ino] = parent
            if tail:
                self.inode_contents[parent][tail] = node.st_ino

    def _make_directory_inode(self):
        entry = llfuse.EntryAttributes()
        entry.st_ino = len(self.inodes) + 1
        entry.generation = 0
        entry.entry_timeout = 300
        entry.attr_timeout = 300
        entry.st_mode = 0o40755
        entry.st_nlink = 0
        entry.st_uid = os.getuid()
        entry.st_gid = os.getgid()
        entry.st_rdev = 0
        entry.st_size = 0
        entry.st_blksize = 512
        entry.st_blocks = 1
        entry.st_atime = time.time()
        entry.st_mtime = time.time()
        entry.st_ctime = time.time()
        return entry

    def _make_item_inode(self, item):
        size = 0
        try:
            size = sum(size for _, size, _ in item[b'chunks'])
        except KeyError:
            pass
        entry = llfuse.EntryAttributes()
        entry.st_ino = len(self.inodes) + 1
        entry.generation = 0
        entry.entry_timeout = 300
        entry.attr_timeout = 300
        entry.st_mode = item[b'mode']
        entry.st_nlink = 0
        entry.st_uid = item[b'uid']
        entry.st_gid = item[b'uid']
        entry.st_rdev = item.get(b'rdev', 0)
        entry.st_size = size
        entry.st_blksize = 512
        entry.st_blocks = 1
        entry.st_atime = item[b'mtime'] / 1e9
        entry.st_mtime = item[b'mtime'] / 1e9
        entry.st_ctime = item[b'mtime'] / 1e9
        return entry

    def run(self, dir):
        llfuse.init(self, dir, ['fsname=atticfs', 'nonempty'])
        try:
            llfuse.main(single=True)
        except:
            llfuse.close(unmount=False)
            raise
        llfuse.close()

    def getattr(self, inode):
        return self.inodes[inode]

    def listxattr(self, inode):
        item = self.items[inode]
        return [b'user.' + name for name in item.get(b'xattrs', {}).keys()]

    def getxattr(self, inode, name):
        item = self.items[inode]
        if name.startswith(b'user.'):
            name = name[5:]
        try:
            return item.get(b'xattrs', {})[name]
        except KeyError:
            raise llfuse.FUSEError(errno.ENODATA)

    def lookup(self, parent_inode, name):
        if name == b'.':
            inode = parent_inode
        elif name == b'..':
            inode = self.inode_parent[parent_inode]
        else:
            inode = self.inode_contents[parent_inode].get(name)
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
        entries = [(b'.', fh), (b'..', self.inode_parent[fh])]
        entries.extend(self.inode_contents[fh].items())
        for i, (name, inode) in enumerate(entries[off:], off):
            yield name, self.getattr(inode), i + 1

    def readlink(self, inode):
        return os.fsencode(self.items[inode][b'source'])

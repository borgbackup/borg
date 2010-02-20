import os
import sys
import hashlib
import zlib
from repository import Repository

CHUNKSIZE = 256 * 1024

class FileItem(object):
    
    def __init__(self):
        """"""

    def process_file(self, filename, cache):
        self.filename = filename
        fd = open(filename, 'rb')
        self.size = 0
        self.chunks = []
        while True:
            data = fd.read(CHUNKSIZE)
            if not data:
                break
            self.size += len(data)
            self.chunks.append(cache.add_chunk(zlib.compress(data)))
        print '%s: %d chunks' % (filename, len(self.chunks))


class Cache(object):
    """Client Side cache
    """
    def __init__(self, repo):
        self.repo = repo
        self.chunkmap = {}

    def chunk_filename(self, sha):
        hex = sha.encode('hex')
        return 'chunks/%s/%s/%s' % (hex[:2], hex[2:4], hex[4:])

    def add_chunk(self, data):
        sha = hashlib.sha1(data).digest()
        if not self.seen_chunk(sha):
            self.repo.put_file(self.chunk_filename(sha), data)
        else:
            print 'seen chunk', sha.encode('hex')
        self.chunk_incref(sha)
        return sha

    def seen_chunk(self, sha):
        return self.chunkmap.get(sha, 0) > 0

    def chunk_incref(self, sha):
        self.chunkmap.setdefault(sha, 0)
        self.chunkmap[sha] += 1

    def chunk_decref(self, sha):
        assert self.chunkmap.get(sha, 0) > 0
        self.chunkmap[sha] -= 1
        return self.chunkmap[sha]


class Archive(object):
    """
    """
    def __init__(self):
        self.items = []

    def add_item(self, item):
        self.items.append(item)


class Archiver(object):

    def __init__(self):
        self.cache = Cache(Repository('/tmp/repo'))
        self.archive = Archive()

    def run(self, path):
        for root, dirs, files in os.walk(path):
            for f in files:
                filename = os.path.join(root, f)
                item = FileItem()
                item.process_file(filename, self.cache)
                self.archive.add_item(item)
        self.cache.repo.commit()


def main():
    archiver = Archiver()
    archiver.run(sys.argv[1])

if __name__ == '__main__':
    main()
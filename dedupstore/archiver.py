import os
import sys
import hashlib
import zlib
import cPickle
from repository import Repository

CHUNKSIZE = 256 * 1024


class Cache(object):
    """Client Side cache
    """
    def __init__(self, path, repo):
        self.repo = repo
        self.chunkmap = {}
        self.archives = []
        self.open(path)

    def open(self, path):
        for archive in self.repo.listdir('archives'):
            self.archives.append(archive)
            data = self.repo.get_file(os.path.join('archives', archive))
            a = cPickle.loads(zlib.decompress(data))
            for item in a['items']:
                if item['type'] == 'FILE':
                    for c in item['chunks']:
                        print 'adding chunk', c.encode('hex')
                        self.chunk_incref(c)

    def save(self):
        assert self.repo.state == Repository.OPEN

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

class Archiver(object):

    def __init__(self):
        self.repo = Repository('/tmp/repo')
        self.cache = Cache('/tmp/cache', self.repo)

    def create_archive(self, archive_name, path):
        if archive_name in self.cache.archives:
            raise Exception('Archive "%s" already exists' % archive_name)
        items = []
        for root, dirs, files in os.walk(path):
            for d in dirs:
                name = os.path.join(root, d)
                items.append(self.process_dir(name, self.cache))
            for f in files:
                name = os.path.join(root, f)
                items.append(self.process_file(name, self.cache))
        archive = {'name': name, 'items': items}
        zdata = zlib.compress(cPickle.dumps(archive))
        self.repo.put_file(os.path.join('archives', archive_name), zdata)
        print 'Archive file size: %d' % len(zdata)
        self.repo.commit()
        self.cache.save()

    def process_dir(self, path, cache):
        print 'Directory: %s' % (path)
        return {'type': 'DIR', 'path': path}

    def process_file(self, path, cache):
        fd = open(path, 'rb')
        size = 0
        chunks = []
        while True:
            data = fd.read(CHUNKSIZE)
            if not data:
                break
            size += len(data)
            chunks.append(cache.add_chunk(zlib.compress(data)))
        print 'File: %s (%d chunks)' % (path, len(chunks))
        return {'type': 'FILE', 'path': path, 'size': size, 'chunks': chunks}


def main():
    archiver = Archiver()
    archiver.create_archive(sys.argv[1], sys.argv[2])

if __name__ == '__main__':
    main()
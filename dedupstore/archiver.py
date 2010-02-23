import os
import sys
import hashlib
import zlib
import cPickle
from store import Store

CHUNKSIZE = 256 * 1024


class Cache(object):
    """Client Side cache
    """
    def __init__(self, path, store):
        self.store = store
        self.path = path
        self.tid = 'unknown'
        self.open()
        if self.tid != self.store.tid:
            print self.tid.encode('hex'), self.store.tid.encode('hex')
            self.create()

    def open(self):
        if self.store.tid == '':
            return
        filename = os.path.join(self.path, '%s.cache' % self.store.uuid)
        if not os.path.exists(filename):
            return
        print 'Reading cache: ', filename, '...'
        data = cPickle.loads(zlib.decompress(open(filename, 'rb').read()))
        self.chunkmap = data['chunkmap']
        self.tid = data['tid']
        self.archives = data['archives']
        print 'done'

    def update_manifest(self):
        print 'old manifest', self.tid.encode('hex')
        if self.tid:
            self.chunk_decref(self.tid)
        manifest = {'archives': self.archives.values()}
        hash = self.add_chunk(zlib.compress(cPickle.dumps(manifest)))
        print 'new manifest', hash.encode('hex')
        self.store.commit(hash)

    def create(self):
        self.archives = {}
        self.chunkmap = {}
        self.tid = self.store.tid
        if self.store.tid == '':
            return
        print 'Recreating cache...'
        self.chunk_incref(self.store.tid)
        manifest = cPickle.loads(zlib.decompress(self.store.get(self.store.tid)))
        for hash in manifest['archives']:
            self.chunk_incref(hash)
            archive = cPickle.loads(zlib.decompress(self.store.get(hash)))
            self.archives[archive['name']] = hash
            for item in archive['items']:
                if item['type'] == 'FILE':
                    for c in item['chunks']:
                        self.chunk_incref(c)
        print 'done'

    def save(self):
        assert self.store.state == Store.OPEN
        print 'saving cache'
        data = {'chunkmap': self.chunkmap, 'tid': self.store.tid, 'archives': self.archives}
        filename = os.path.join(self.path, '%s.cache' % self.store.uuid)
        print 'Saving cache as:', filename
        with open(filename, 'wb') as fd:
            fd.write(zlib.compress(cPickle.dumps(data)))
        print 'done'

    def add_chunk(self, data):
        hash = hashlib.sha1(data).digest()
        if not self.seen_chunk(hash):
            self.store.put(data, hash)
        else:
            print 'seen chunk', hash.encode('hex')
        self.chunk_incref(hash)
        return hash

    def seen_chunk(self, hash):
        return self.chunkmap.get(hash, 0) > 0

    def chunk_incref(self, hash):
        self.chunkmap.setdefault(hash, 0)
        self.chunkmap[hash] += 1

    def chunk_decref(self, hash):
        count = self.chunkmap.get(hash, 0) - 1
        assert count >= 0
        self.chunkmap[hash] = count
        if not count:
            print 'deleting chunk: ', hash.encode('hex')
            self.store.delete(hash)
        return count


class Archiver(object):

    def __init__(self):
        self.store = Store('/tmp/store')
        self.cache = Cache('/tmp/cache', self.store)

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
        hash = self.cache.add_chunk(zlib.compress(cPickle.dumps(archive)))
        self.cache.archives[archive_name] = hash
        self.cache.update_manifest()
        self.cache.save()

    def delete_archive(self, archive_name):
        hash = self.cache.archives.get(archive_name)
        if not hash:
            raise Exception('Archive "%s" does not exist' % archive_name)
        archive = cPickle.loads(zlib.decompress(self.store.get(hash)))
        self.cache.chunk_decref(hash)
        for item in archive['items']:
            if item['type'] == 'FILE':
                for c in item['chunks']:
                    self.cache.chunk_decref(c)
        del self.cache.archives[archive_name]
        self.cache.update_manifest()
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
    if sys.argv[1] == 'delete':
        archiver.delete_archive(sys.argv[2])
    else:
        archiver.create_archive(sys.argv[1], sys.argv[2])

if __name__ == '__main__':
    main()
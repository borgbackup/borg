import os
import hashlib
import zlib
import cPickle
from optparse import OptionParser

from chunkifier import chunkify
from cache import Cache
from store import Store, NS_ARCHIVES, NS_CHUNKS, CHUNK_SIZE


class Archive(object):

    def __init__(self, store, name=None):
        self.store = store
        self.items = []
        self.chunks = []
        self.chunk_idx = {}
        if name:
            self.open(name)

    def add_chunk(self, id, sum, csize, osize):
        try:
            return self.chunk_idx[id]
        except KeyError:
            idx = len(self.chunks)
            self.chunks.append((id, sum, csize, osize))
            self.chunk_idx[id] = idx
            return idx
        
    def open(self, name):
        archive = cPickle.loads(zlib.decompress(self.store.get(NS_ARCHIVES, name)))
        self.items = archive['items']
        self.name = archive['name']
        for i, (id, sum, csize, osize) in enumerate(archive['chunks']):
            self.chunk_idx[i] = id

    def save(self, name):
        archive = {'name': name, 'items': self.items, 'chunks': self.chunks}
        self.store.put(NS_ARCHIVES, name, zlib.compress(cPickle.dumps(archive)))
        self.store.commit()

    def list(self):
        for item in self.items:
            print item['path']

    def extract(self):
        for item in self.items:
            assert item['path'][0] not in ('/', '\\', ':')
            print item['path']
            if item['type'] == 'DIR':
                if not os.path.exists(item['path']):
                    os.makedirs(item['path'])
            if item['type'] == 'FILE':
                path = item['path']
                if not os.path.exists(os.path.dirname(path)):
                    os.makedirs(os.path.dirname(path))
                with open(item['path'], 'wb') as fd:
                    for chunk in item['chunks']:
                        id = self.chunk_idx[chunk]
                        data = self.store.get(NS_CHUNKS, id)
                        if hashlib.sha1(data).digest() != id:
                            raise Exception('Invalid chunk checksum')
                        fd.write(zlib.decompress(data))

    def verify(self):
        for item in self.items:
            if item['type'] == 'FILE':
                print item['path'], '...',
                print self.chunk_idx[0].encode('hex')
                for chunk in item['chunks']:
                    id = self.chunk_idx[chunk]
                    data = self.store.get(NS_CHUNKS, id)
                    if hashlib.sha1(data).digest() != id:
                        print 'ERROR'
                        break
                else:
                    print 'OK'

    def delete(self, cache):
        self.store.delete(NS_ARCHIVES, self.name)
        for item in self.items:
            if item['type'] == 'FILE':
                for c in item['chunks']:
                    id = self.chunk_idx[c]
                    cache.chunk_decref(id)
        self.store.commit()
        cache.archives.remove(self.name)
        cache.save()

    def create(self, name, paths, cache):
        for path in paths:
            for root, dirs, files in os.walk(path):
                for d in dirs:
                    p = os.path.join(root, d)
                    self.items.append(self.process_dir(p, cache))
                for f in files:
                    p = os.path.join(root, f)
                    self.items.append(self.process_file(p, cache))
        self.save(name)
        cache.archives.append(name)
        cache.save()

    def process_dir(self, path, cache):
        path = path.lstrip('/\\:')
        print 'Directory: %s' % (path)
        return {'type': 'DIR', 'path': path}

    def process_file(self, path, cache):
        with open(path, 'rb') as fd:
            path = path.lstrip('/\\:')
            print 'Adding: %s...' % path
            chunks = []
            for chunk in chunkify(fd, CHUNK_SIZE, cache.summap):
                chunks.append(self.add_chunk(*cache.add_chunk(chunk)))
        return {'type': 'FILE', 'path': path, 'chunks': chunks}


class Archiver(object):

    def create_archive(self, name, paths):
        archive = Archive(self.store)
        archive.create(name, paths, self.cache)

    def delete_archive(self, archive_name):
        archive = Archive(self.store, archive_name)
        archive.delete(self.cache)

    def list_archives(self):
        print 'Archives:'
        for archive in sorted(self.cache.archives):
            print archive

    def list_archive(self, archive_name):
        archive = Archive(self.store, archive_name)
        archive.list()

    def verify_archive(self, archive_name):
        archive = Archive(self.store, archive_name)
        archive.verify()

    def extract_archive(self, archive_name):
        archive = Archive(self.store, archive_name)
        archive.extract()

    def run(self):
        parser = OptionParser()
        parser.add_option("-s", "--store", dest="store",
                          help="path to dedupe store", metavar="STORE")
        parser.add_option("-c", "--create", dest="create_archive",
                          help="create ARCHIVE", metavar="ARCHIVE")
        parser.add_option("-d", "--delete", dest="delete_archive",
                          help="delete ARCHIVE", metavar="ARCHIVE")
        parser.add_option("-l", "--list-archives", dest="list_archives",
                        action="store_true", default=False,
                        help="list archives")
        parser.add_option("-V", "--verify", dest="verify_archive",
                        help="verify archive consistency")
        parser.add_option("-e", "--extract", dest="extract_archive",
                        help="extract ARCHIVE")
        parser.add_option("-L", "--list-archive", dest="list_archive",
                        help="verify archive consistency", metavar="ARCHIVE")
        (options, args) = parser.parse_args()
        if options.store:
            self.store = Store(options.store)
        else:
            parser.error('No store path specified')
        self.cache = Cache(self.store)
        if options.list_archives:
            self.list_archives()
        elif options.list_archive:
            self.list_archive(options.list_archive)
        elif options.verify_archive:
            self.verify_archive(options.verify_archive)
        elif options.extract_archive:
            self.extract_archive(options.extract_archive)
        elif options.delete_archive:
            self.delete_archive(options.delete_archive)
        else:
            self.create_archive(options.create_archive, args)


def main():
    archiver = Archiver()
    archiver.run()

if __name__ == '__main__':
    main()

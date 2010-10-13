import os
import sys
import hashlib
import logging
import zlib
import cPickle
from optparse import OptionParser

from chunkifier import chunkify
from cache import Cache, NS_ARCHIVES, NS_CHUNKS
#from sqlitestore import SqliteStore
from bandstore import BandStore

CHUNK_SIZE = 55001


class Archive(object):

    def __init__(self, store, name=None):
        self.store = store
        self.items = []
        self.chunks = []
        self.chunk_idx = {}
        if name:
            self.open(name)

    def add_chunk(self, id, csize, osize):
        try:
            return self.chunk_idx[id]
        except KeyError:
            idx = len(self.chunks)
            self.chunks.append((id, csize, osize))
            self.chunk_idx[id] = idx
            return idx

    def open(self, name):
        archive = cPickle.loads(zlib.decompress(self.store.get(NS_ARCHIVES, name)))
        self.items = archive['items']
        self.name = archive['name']
        self.chunks = archive['chunks']
        for i, (id, csize, osize) in enumerate(archive['chunks']):
            self.chunk_idx[i] = id

    def save(self, name):
        archive = {'name': name, 'items': self.items, 'chunks': self.chunks}
        self.store.put(NS_ARCHIVES, name, zlib.compress(cPickle.dumps(archive)))
        self.store.commit()

    def stats(self, cache):
        total_osize = 0
        total_csize = 0
        total_usize = 0
        chunk_count = {}
        for item in self.items:
            if item['type'] == 'FILE':
                total_osize += item['size']
                for idx in item['chunks']:
                    id = self.chunk_idx[idx]
                    chunk_count.setdefault(id, 0)
                    chunk_count[id] += 1
        for id, c in chunk_count.items():
            count, csize, osize = cache.chunkmap[id]
            total_csize += csize
            if  c == count:
                total_usize += csize
        return dict(osize=total_osize, csize=total_csize, usize=total_usize)

    def list(self):
        for item in self.items:
            print item['path']

    def extract(self):
        for item in self.items:
            assert item['path'][0] not in ('/', '\\', ':')
            logging.info(item['path'])
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
                for chunk in item['chunks']:
                    id = self.chunk_idx[chunk]
                    data = self.store.get(NS_CHUNKS, id)
                    if hashlib.sha1(data).digest() != id:
                        logging.ERROR('%s ... ERROR', item['path'])
                        break
                else:
                    logging.info('%s ... OK', item['path'])

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
                    entry = self.process_file(p, cache)
                    if entry:
                        self.items.append(entry)
        self.save(name)
        cache.archives.append(name)
        cache.save()

    def process_dir(self, path, cache):
        path = path.lstrip('/\\:')
        logging.info(path)
        return {'type': 'DIR', 'path': path}

    def process_file(self, path, cache):
        try:
            fd = open(path, 'rb')
        except IOError, e:
            logging.error(e)
            return
        with fd:
            path = path.lstrip('/\\:')
            logging.info(path)
            chunks = []
            size = 0
            for chunk in chunkify(fd, CHUNK_SIZE, 30):
                size += len(chunk)
                chunks.append(self.add_chunk(*cache.add_chunk(chunk)))
        return {'type': 'FILE', 'path': path, 'chunks': chunks, 'size': size}


class Archiver(object):

    def pretty_size(self, v):
        if v > 1024 * 1024 * 1024:
            return '%.2f GB' % (v / 1024. / 1024. / 1024.)
        elif v > 1024 * 1024:
            return '%.2f MB' % (v / 1024. / 1024.)
        elif v > 1024:
            return '%.2f kB' % (v / 1024.)
        else:
            return str(v)

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

    def archive_stats(self, archive_name):
        archive = Archive(self.store, archive_name)
        stats = archive.stats(self.cache)
        print 'Original size:', self.pretty_size(stats['osize'])
        print 'Compressed size:', self.pretty_size(stats['csize'])
        print 'Unique data:', self.pretty_size(stats['usize'])

    def run(self):
        parser = OptionParser()
        parser.add_option("-v", "--verbose",
                          action="store_true", dest="verbose", default=False,
                          help="Print status messages to stdout")
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
        parser.add_option("-S", "--stats", dest="archive_stats",
                        help="Display archive statistics", metavar="ARCHIVE")
        (options, args) = parser.parse_args()
        if options.verbose:
            logging.basicConfig(level=logging.INFO, format='%(message)s')
        else:
            logging.basicConfig(level=logging.WARNING, format='%(message)s')
        if options.store:
            self.store = BandStore(options.store)
        else:
            parser.error('No store path specified')
        self.cache = Cache(self.store)
        if options.list_archives and not args:
            self.list_archives()
        elif options.list_archive and not args:
            self.list_archive(options.list_archive)
        elif options.verify_archive and not args:
            self.verify_archive(options.verify_archive)
        elif options.extract_archive and not args:
            self.extract_archive(options.extract_archive)
        elif options.delete_archive and not args:
            self.delete_archive(options.delete_archive)
        elif options.create_archive:
            self.create_archive(options.create_archive, args)
        elif options.archive_stats and not args:
            self.archive_stats(options.archive_stats)
        else:
            parser.error('Invalid usage')
            sys.exit(1)

def main():
    archiver = Archiver()
    archiver.run()

if __name__ == '__main__':
    main()

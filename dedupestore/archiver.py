import os
import hashlib
import logging
import zlib
import argparse
import sys
from cStringIO import StringIO
from datetime import datetime

from avro import io

from dedupestore import archive_schema
from chunkifier import chunkify
from cache import Cache, NS_ARCHIVES, NS_CHUNKS
from bandstore import BandStore
from helpers import location_validator, pretty_size

CHUNK_SIZE = 55001

class LevelFilter(logging.Filter):

    def __init__(self, *args, **kwargs):
        super(LevelFilter, self).__init__(args, **kwargs)
        self.count = {}

    def filter(self, record):
        self.count.setdefault(record.levelname, 0)
        self.count[record.levelname] += 1
        return record


class Archive(object):

    def __init__(self, store, cache, name=None):
        self.store = store
        self.cache = cache
        self.items = []
        self.chunks = []
        self.chunk_idx = {}
        if name:
            self.open(name)

    def open(self, name):
        id = self.cache.archives[name]
        data = self.store.get(NS_ARCHIVES, id)
        if hashlib.sha256(data).digest() != id:
            raise Exception('Archive hash did not match')
        buffer = StringIO(zlib.decompress(data))
        reader = io.DatumReader(archive_schema)
        decoder = io.BinaryDecoder(buffer)
        archive = reader.read(decoder)
        self.items = archive['items']
        self.name = archive['name']
        self.chunks = archive['chunks']
        for i, chunk in enumerate(archive['chunks']):
            self.chunk_idx[i] = chunk['id']

    def save(self, name):
        archive = {
            'name': name,
            'ts': datetime.utcnow().isoformat(),
            'items': self.items,
            'chunks': self.chunks
        }
        writer = StringIO()
        encoder = io.BinaryEncoder(writer)
        datum_writer = io.DatumWriter(archive_schema)
        datum_writer.write(archive, encoder)
        data = zlib.compress(writer.getvalue())
        print 'archive size: %d' % len(data)
        self.id = hashlib.sha256(data).digest()
        self.store.put(NS_ARCHIVES, self.id, data)
        self.store.commit()

    def add_chunk(self, id, size):
        try:
            return self.chunk_idx[id]
        except KeyError:
            idx = len(self.chunks)
            self.chunks.append(dict(id=id, size=size))
            self.chunk_idx[id] = idx
            return idx

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
            count, size = cache.chunkmap[id]
            total_csize += size
            if  c == count:
                total_usize += size
        return dict(osize=total_osize, csize=total_csize, usize=total_usize)

    def list(self):
        for item in self.items:
            print item['path']

    def extract(self, dest=None):
        dest = dest or os.getcwdu()
        for item in self.items:
            assert item['path'][0] not in ('/', '\\', ':')
            path = os.path.join(dest, item['path'])
            logging.info(path)
            if item['type'] == 'DIRECTORY':
                if not os.path.exists(path):
                    os.makedirs(path)
            if item['type'] == 'FILE':
                if not os.path.exists(os.path.dirname(path)):
                    os.makedirs(os.path.dirname(path))
                with open(path, 'wb') as fd:
                    for chunk in item['chunks']:
                        id = self.chunk_idx[chunk]
                        data = self.store.get(NS_CHUNKS, id)
                        cid = data[:32]
                        data = data[32:]
                        if hashlib.sha256(data).digest() != cid:
                            raise Exception('Invalid chunk checksum')
                        if hashlib.sha256(zlib.decompress(data)).digest() != id:
                            raise Exception('Invalid chunk checksum')
                        fd.write(zlib.decompress(data))

    def verify(self):
        for item in self.items:
            if item['type'] == 'FILE':
                for chunk in item['chunks']:
                    id = self.chunk_idx[chunk]
                    data = self.store.get(NS_CHUNKS, id)
                    data = self.store.get(NS_CHUNKS, id)
                    cid = data[:32]
                    data = data[32:]
                    if (hashlib.sha256(data).digest() != cid or
                        hashlib.sha256(zlib.decompress(data)).digest() != id):
                        logging.error('%s ... ERROR', item['path'])
                        break
                else:
                    logging.info('%s ... OK', item['path'])

    def delete(self, cache):
        self.store.delete(NS_ARCHIVES, self.cache.archives[self.name])
        for item in self.items:
            if item['type'] == 'FILE':
                for c in item['chunks']:
                    id = self.chunk_idx[c]
                    cache.chunk_decref(id)
        self.store.commit()
        del cache.archives[self.name]
        cache.save()

    def create(self, name, paths, cache):
        if name in cache.archives:
            raise NameError('Archive already exists')
        for path in paths:
            for root, dirs, files in os.walk(unicode(path)):
                for d in dirs:
                    p = os.path.join(root, d)
                    self.items.append(self.process_dir(p, cache))
                for f in files:
                    p = os.path.join(root, f)
                    entry = self.process_file(p, cache)
                    if entry:
                        self.items.append(entry)
        self.save(name)
        cache.archives[name] = self.id
        cache.save()

    def process_dir(self, path, cache):
        path = path.lstrip('/\\:')
        logging.info(path)
        return {'type': 'DIRECTORY', 'path': path}

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

    def open_store(self, location):
        store = BandStore(location.path)
        cache = Cache(store)
        return store, cache

    def exit_code_from_logger(self):
        if not self.level_filter.count.get('ERROR'):
            return 0
        else:
            return 1

    def do_create(self, args):
        store, cache = self.open_store(args.archive)
        archive = Archive(store, cache)
        archive.create(args.archive.archive, args.paths, cache)
        return self.exit_code_from_logger()

    def do_extract(self, args):
        store, cache = self.open_store(args.archive)
        archive = Archive(store, cache, args.archive.archive)
        archive.extract(args.dest)
        return self.exit_code_from_logger()

    def do_delete(self, args):
        store, cache = self.open_store(args.archive)
        archive = Archive(store, cache, args.archive.archive)
        archive.delete(cache)
        return self.exit_code_from_logger()

    def do_list(self, args):
        store, cache = self.open_store(args.src)
        if args.src.archive:
            archive = Archive(store, cache, args.src.archive)
            archive.list()
        else:
            for archive in sorted(cache.archives):
                print archive
        return self.exit_code_from_logger()

    def do_verify(self, args):
        store, cache = self.open_store(args.archive)
        archive = Archive(store, cache, args.archive.archive)
        archive.verify()
        return self.exit_code_from_logger()

    def do_info(self, args):
        store, cache = self.open_store(args.archive)
        archive = Archive(store, cache, args.archive.archive)
        stats = archive.stats(cache)
        print 'Original size:', pretty_size(stats['osize'])
        print 'Compressed size:', pretty_size(stats['csize'])
        print 'Unique data:', pretty_size(stats['usize'])
        return self.exit_code_from_logger()

    def run(self, args=None):
        parser = argparse.ArgumentParser(description='Dedupestore')
        parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                            default=False,
                            help='Verbose output')

        subparsers = parser.add_subparsers(title='Available subcommands')
        subparser = subparsers.add_parser('create')
        subparser.set_defaults(func=self.do_create)
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='Archive to create')
        subparser.add_argument('paths', metavar='PATH', nargs='+', type=str,
                               help='Paths to add to archive')

        subparser = subparsers.add_parser('extract')
        subparser.set_defaults(func=self.do_extract)
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='Archive to create')
        subparser.add_argument('dest', metavar='DEST', type=str, nargs='?',
                               help='Where to extract files')

        subparser = subparsers.add_parser('delete')
        subparser.set_defaults(func=self.do_delete)
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='Archive to delete')

        subparser = subparsers.add_parser('list')
        subparser.set_defaults(func=self.do_list)
        subparser.add_argument('src', metavar='SRC', type=location_validator(),
                               help='Store/Archive to list contents of')

        subparser= subparsers.add_parser('verify')
        subparser.set_defaults(func=self.do_verify)
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='Archive to verity integrity of')

        subparser= subparsers.add_parser('info')
        subparser.set_defaults(func=self.do_info)
        subparser.add_argument('archive', metavar='ARCHIVE',
                               type=location_validator(archive=True),
                               help='Archive to display information about')

        args = parser.parse_args(args)
        if args.verbose:
            logging.basicConfig(level=logging.INFO, format='%(message)s')
        else:
            logging.basicConfig(level=logging.WARNING, format='%(message)s')
        self.level_filter = LevelFilter()
        logging.getLogger('').addFilter(self.level_filter)
        return args.func(args)

def main():
    archiver = Archiver()
    sys.exit(archiver.run())

if __name__ == '__main__':
    main()

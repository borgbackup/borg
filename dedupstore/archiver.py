import os
import sys
import hashlib
import zlib
import struct
import cPickle
from optparse import OptionParser

from chunker import chunker, checksum
from store import Store


CHUNKSIZE = 64 * 1024
NS_ARCHIVES = 'ARCHIVES'
NS_CHUNKS  = 'CHUNKS'

class Cache(object):
    """Client Side cache
    """
    def __init__(self, path, store):
        self.store = store
        self.path = path
        self.tid = -1
        self.open()
        if self.tid != self.store.tid:
            print self.tid, self.store.tid
            self.create()

    def open(self):
        if self.store.tid == -1:
            return
        filename = os.path.join(self.path, '%s.cache' % self.store.uuid)
        if not os.path.exists(filename):
            return
        print 'Loading cache: ', filename, '...'
        data = cPickle.loads(zlib.decompress(open(filename, 'rb').read()))
        self.chunkmap = data['chunkmap']
        self.summap = data['summap']
        self.archives = data['archives']
        self.tid = data['tid']
        print 'done'

    def create(self):
        self.summap = {}
        self.chunkmap = {}
        self.archives = []
        self.tid = self.store.tid
        if self.store.tid == 0:
            return
        print 'Recreating cache...'
        for id in self.store.list(NS_ARCHIVES):
            archive = cPickle.loads(zlib.decompress(self.store.get(NS_ARCHIVES, id)))
            self.archives.append(archive['name'])
            for item in archive['items']:
                if item['type'] == 'FILE':
                    for c in item['chunks']:
                        self.chunk_incref(c)
        print 'done'

    def save(self):
        assert self.store.state == Store.OPEN
        print 'saving cache'
        data = {'chunkmap': self.chunkmap, 'summap': self.summap,
                'tid': self.store.tid, 'archives': self.archives}
        filename = os.path.join(self.path, '%s.cache' % self.store.uuid)
        print 'Saving cache as:', filename
        with open(filename, 'wb') as fd:
            fd.write(zlib.compress(cPickle.dumps(data)))
        print 'done'

    def add_chunk(self, data):
        sum = checksum(data)
        #print 'chunk %d: %d' % (len(data), sum)
        hash = struct.pack('I', sum) + hashlib.sha1(data).digest()
        if not self.seen_chunk(hash):
            zdata = zlib.compress(data)
            size = len(zdata)
            self.store.put(NS_CHUNKS, hash, zdata)
        else:
            size = 0
            #print 'seen chunk', hash.encode('hex')
        self.chunk_incref(hash)
        return hash, size

    def seen_chunk(self, hash):
        return self.chunkmap.get(hash, 0) > 0

    def chunk_incref(self, hash):
        sum = struct.unpack('I', hash[:4])[0]
        self.chunkmap.setdefault(hash, 0)
        self.summap.setdefault(sum, 0)
        self.chunkmap[hash] += 1
        self.summap[sum] += 1

    def chunk_decref(self, hash):
        self.summap[struct.unpack('I', hash[:4])[0]] -= 1
        count = self.chunkmap.get(hash, 0) - 1
        assert count >= 0
        self.chunkmap[hash] = count
        if not count:
            print 'deleting chunk: ', hash.encode('hex')
            self.store.delete(NS_CHUNKS, hash)
        return count


class Archiver(object):

    def create_archive(self, archive_name, paths):
        try:
            self.store.get(NS_ARCHIVES, archive_name)
        except Store.DoesNotExist:
            pass
        else:
            raise Exception('Archive "%s" already exists' % archive_name)
        items = []
        for path in paths:
            for root, dirs, files in os.walk(path):
                for d in dirs:
                    name = os.path.join(root, d)
                    items.append(self.process_dir(name, self.cache))
                for f in files:
                    name = os.path.join(root, f)
                    items.append(self.process_file(name, self.cache))
        archive = {'name': archive_name, 'items': items}
        hash = self.store.put(NS_ARCHIVES, archive_name, zlib.compress(cPickle.dumps(archive)))
        self.store.commit()
        self.cache.archives.append(archive_name)
        self.cache.save()

    def delete_archive(self, archive_name):
        try:
            archive = cPickle.loads(zlib.decompress(self.store.get(NS_ARCHIVES, archive_name)))
        except Store.DoesNotExist:
            raise Exception('Archive "%s" does not exist' % archive_name)
        self.store.delete(NS_ARCHIVES, archive_name)
        for item in archive['items']:
            if item['type'] == 'FILE':
                for c in item['chunks']:
                    self.cache.chunk_decref(c)
        self.store.commit()
        self.cache.archives.remove(archive_name)
        self.cache.save()

    def list_archives(self):
        print 'Archives:'
        for archive in sorted(self.cache.archives):
            print archive

    def list_archive(self, archive_name):
        try:
            archive = cPickle.loads(zlib.decompress(self.store.get(NS_ARCHIVES, archive_name)))
        except Store.DoesNotExist:
            raise Exception('Archive "%s" does not exist' % archive_name)
        for item in archive['items']:
            print item['path']

    def verify_archive(self, archive_name):
        try:
            archive = cPickle.loads(zlib.decompress(self.store.get(NS_ARCHIVES, archive_name)))
        except Store.DoesNotExist:
            raise Exception('Archive "%s" does not exist' % archive_name)
        for item in archive['items']:
            if item['type'] == 'FILE':
                print item['path'], '...',
                for chunk in item['chunks']:
                    data = self.store.get(NS_CHUNKS, chunk)
                    if hashlib.sha1(data).digest() != chunk:
                        print 'ERROR'
                        break
                else:
                    print 'OK'

    def extract_archive(self, archive_name):
        try:
            archive = cPickle.loads(zlib.decompress(self.store.get(NS_ARCHIVES, archive_name)))
        except Store.DoesNotExist:
            raise Exception('Archive "%s" does not exist' % archive_name)
        for item in archive['items']:
            assert item['path'][0] not in ('/', '\\', ':')
            print item['path']
            if item['type'] == 'DIR':
                if not os.path.exists(item['path']):
                    os.makedirs(item['path'])
            if item['type'] == 'FILE':
                with open(item['path'], 'wb') as fd:
                    for chunk in item['chunks']:
                        fd.write(zlib.decompress(self.store.get(NS_CHUNKS, chunk)))

    def process_dir(self, path, cache):
        path = path.lstrip('/\\:')
        print 'Directory: %s' % (path)
        return {'type': 'DIR', 'path': path}

    def process_file(self, path, cache):
        print 'Adding: %s...' % path,
        sys.stdout.flush()
        with open(path, 'rb') as fd:
            origsize = 0
            compsize = 0
            chunks = []
            for chunk in chunker(fd, CHUNKSIZE, self.cache.summap):
                origsize += len(chunk)
                id, size = cache.add_chunk(chunk)
                compsize += size
                chunks.append(id)
        path = path.lstrip('/\\:')
        ratio = origsize and compsize * 100 / origsize or 0
        print '(%d chunks: %d%%)' % (len(chunks), ratio)
        return {'type': 'FILE', 'path': path, 'size': size, 'chunks': chunks}

    def run(self):
        parser = OptionParser()
        parser.add_option("-C", "--cache", dest="cache",
                          help="cache directory to use", metavar="CACHE")
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
        if options.cache:
            self.cache = Cache(options.cache, self.store)
        else:
            parser.error('No cache path specified')
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
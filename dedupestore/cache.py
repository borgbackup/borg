import cPickle
import hashlib
import os
import sys
import zlib

from chunkifier import checksum
from store import Store, NS_ARCHIVES, NS_CHUNKS


class Cache(object):
    """Client Side cache
    """

    def __init__(self, store):
        self.store = store
        self.path = os.path.join(os.path.expanduser('~'), '.dedupestore', 'cache', 
                                 '%s.cache' % self.store.uuid)
        self.tid = -1
        self.open()
        if self.tid != self.store.tid:
            self.init()

    def open(self):
        if not os.path.exists(self.path):
            return
        print 'Loading cache: ', self.path, '...'
        data = cPickle.loads(zlib.decompress(open(self.path, 'rb').read()))
        if data['uuid'] != self.store.uuid:
            print >> sys.stderr, 'Cache UUID mismatch'
            return
        self.chunkmap = data['chunkmap']
        self.summap = data['summap']
        self.archives = data['archives']
        self.tid = data['tid']
        print 'done'

    def init(self):
        """Initializes cache by fetching and reading all archive indicies
        """
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
            for id, sum, csize, osize in archive['chunks']:
                if self.seen_chunk(id):
                    self.chunk_incref(id)
                else:
                    self.init_chunk(id, sum, csize, osize)
        print 'done'

    def save(self):
        assert self.store.state == Store.OPEN
        print 'saving cache'
        data = {'uuid': self.store.uuid, 
                'chunkmap': self.chunkmap, 'summap': self.summap,
                'tid': self.store.tid, 'archives': self.archives}
        print 'Saving cache as:', self.path
        cachedir = os.path.dirname(self.path)
        if not os.path.exists(cachedir):
            os.makedirs(cachedir)
        with open(self.path, 'wb') as fd:
            fd.write(zlib.compress(cPickle.dumps(data)))
        print 'done'

    def add_chunk(self, data):
        sum = checksum(data)
        osize = len(data)
        data = zlib.compress(data)
        id = hashlib.sha1(data).digest()
        if self.seen_chunk(id):
            return self.chunk_incref(id)
        csize = len(data)
        self.store.put(NS_CHUNKS, id, data)
        return self.init_chunk(id, sum, csize, osize)

    def init_chunk(self, id, sum, csize, osize):
        self.chunkmap[id] = (1, sum, osize, csize)
        self.summap.setdefault(sum, 1)
        return id, sum, csize, osize

    def seen_chunk(self, id):
        return id in self.chunkmap

    def chunk_incref(self, id):
        count, sum, csize, osize = self.chunkmap[id]
        self.chunkmap[id] = (count + 1, sum, osize, csize)
        self.summap[sum] += 1
        return id, sum, csize, osize

    def chunk_decref(self, id):
        count, sum, csize, osize = self.chunkmap[id]
        sumcount = self.summap[sum] 
        if sumcount == 1:
            del self.summap[sum]
        else:
            self.summap[sum] = sumcount - 1
        if count == 1:
            del self.chunkmap[id]
            print 'deleting chunk: ', id.encode('hex')
            self.store.delete(NS_CHUNKS, id)
        else:
            self.chunkmap[id] = (count - 1, sum, csize, osize)

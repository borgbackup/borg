import cPickle
import hashlib
import os
import sys
import struct
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
            for item in archive['items']:
                if item['type'] == 'FILE':
                    for c in item['chunks']:
                        self.chunk_incref(c)
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
        data = zlib.compress(data)
        #print 'chunk %d: %d' % (len(data), sum)
        id = struct.pack('I', sum) + hashlib.sha1(data).digest()
        if not self.seen_chunk(id):
            size = len(data)
            self.store.put(NS_CHUNKS, id, data)
        else:
            size = 0
            #print 'seen chunk', hash.encode('hex')
        self.chunk_incref(id)
        return id, size

    def seen_chunk(self, hash):
        return self.chunkmap.get(hash, 0) > 0

    def chunk_incref(self, id):
        sum = struct.unpack('I', id[:4])[0]
        self.chunkmap.setdefault(id, 0)
        self.summap.setdefault(sum, 0)
        self.chunkmap[id] += 1
        self.summap[sum] += 1

    def chunk_decref(self, id):
        sum = struct.unpack('I', id[:4])[0]
        sumcount = self.summap[sum] - 1
        count = self.chunkmap[id] - 1
        assert sumcount >= 0
        assert count >= 0
        if sumcount:
            self.summap[sum] = sumcount
        else:
            del self.summap[sum]
        if count:
            self.chunkmap[id] = count
        else:
            del self.chunkmap[id]
            print 'deleting chunk: ', id.encode('hex')
            self.store.delete(NS_CHUNKS, id)
        return count

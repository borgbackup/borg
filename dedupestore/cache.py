import hashlib
import logging
import msgpack
import os
import zlib

from .helpers import pack, unpack

NS_ARCHIVES = 'A'
NS_CHUNKS = 'C'
NS_CINDEX = 'I'


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
        data = open(self.path, 'rb').read()
        cache = unpack(data)
        version = cache.get('version')
        if version != 1:
            logging.error('Unsupported cache version %r' % version)
            return
        if cache['store'] != self.store.uuid:
            raise Exception('Cache UUID mismatch')
        self.chunkmap = cache['chunkmap']
        self.tid = cache['tid']

    def init(self):
        """Initializes cache by fetching and reading all archive indicies
        """
        logging.info('Initializing cache...')
        self.chunkmap = {}
        self.tid = self.store.tid
        if self.store.tid == 0:
            return
        for id in list(self.store.list(NS_CINDEX)):
            cindex = unpack(self.store.get(NS_CINDEX, id))
            for id, size in cindex['chunks']:
                try:
                    count, size = self.chunkmap[id]
                    self.chunkmap[id] = count + 1, size
                except KeyError:
                    self.chunkmap[id] = 1, size
        self.save()

    def save(self):
        assert self.store.state == self.store.OPEN
        cache = {'version': 1,
                'store': self.store.uuid,
                'chunkmap': self.chunkmap,
                'tid': self.store.tid,
        }
        _, data = pack(cache)
        cachedir = os.path.dirname(self.path)
        if not os.path.exists(cachedir):
            os.makedirs(cachedir)
        with open(self.path, 'wb') as fd:
            fd.write(data)

    def add_chunk(self, id, data):
        if self.seen_chunk(id):
            return self.chunk_incref(id)
        _, data = pack(data)
        csize = len(data)
        self.store.put(NS_CHUNKS, id, data)
        self.chunkmap[id] = (1, csize)
        return csize

    def seen_chunk(self, id):
        count, size = self.chunkmap.get(id, (0, 0))
        return count

    def chunk_incref(self, id):
        count, size = self.chunkmap[id]
        self.chunkmap[id] = (count + 1, size)
        return size

    def chunk_decref(self, id):
        count, size = self.chunkmap[id]
        if count == 1:
            del self.chunkmap[id]
            self.store.delete(NS_CHUNKS, id)
        else:
            self.chunkmap[id] = (count - 1, size)



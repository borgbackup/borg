import hashlib
import os
import msgpack
import zlib

NS_ARCHIVES = 'A'
NS_CHUNKS = 'C'


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
        id = data[:32]
        data = data[32:]
        if hashlib.sha256(data).digest() != id:
            raise Exception('Cache hash did not match')
        data = msgpack.unpackb(zlib.decompress(data))
        if data['uuid'] != self.store.uuid:
            raise Exception('Cache UUID mismatch')
        self.chunkmap = data['chunkmap']
        self.archives = data['archives']
        self.tid = data['tid']

    def init(self):
        """Initializes cache by fetching and reading all archive indicies
        """
        self.chunkmap = {}
        self.archives = {}
        self.tid = self.store.tid
        if self.store.tid == 0:
            return
        for id in list(self.store.list(NS_ARCHIVES)):
            data = self.store.get(NS_ARCHIVES, id)
            if hashlib.sha256(data).digest() != id:
                raise Exception('Archive hash did not match')
            archive = msgpack.unpackb(zlib.decompress(data))
            self.archives[archive['name']] = id
            for id, size in archive['chunks']:
                try:
                    count, size = self.chunkmap[id]
                    self.chunkmap[id] = count + 1, size
                except KeyError:
                    self.chunkmap[id] = 1, size
        self.save()

    def save(self):
        assert self.store.state == self.store.OPEN
        data = {'uuid': self.store.uuid,
                'chunkmap': self.chunkmap,
                'tid': self.store.tid, 'archives': self.archives}
        cachedir = os.path.dirname(self.path)
        if not os.path.exists(cachedir):
            os.makedirs(cachedir)
        with open(self.path, 'wb') as fd:
            data = zlib.compress(msgpack.packb(data))
            id = hashlib.sha256(data).digest()
            fd.write(id + data)

    def add_chunk(self, id, data):
        if self.seen_chunk(id):
            return self.chunk_incref(id)
        data = zlib.compress(data)
        data = hashlib.sha256(data).digest() + data
        csize = len(data)
        self.store.put(NS_CHUNKS, id, data)
        return self.init_chunk(id, csize)[1]

    def init_chunk(self, id, size):
        self.chunkmap[id] = (1, size)
        return id, size

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



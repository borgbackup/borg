from itertools import ifilter
import logging
import msgpack
import os

from . import NS_ARCHIVE_CHUNKS, NS_CHUNK


class Cache(object):
    """Client Side cache
    """

    def __init__(self, store, crypto):
        self.store = store
        self.path = os.path.join(os.path.expanduser('~'), '.dedupestore', 'cache',
                                 '%s.cache' % self.store.id.encode('hex'))
        self.tid = -1
        self.open()
        if self.tid != self.store.tid:
            self.init(crypto)

    def open(self):
        if not os.path.exists(self.path):
            return
        cache = msgpack.unpackb(open(self.path, 'rb').read())
        assert cache['version'] == 1
        self.chunk_counts = cache['chunk_counts']
        # Discard old file_chunks entries
        self.file_chunks = cache['file_chunks']
        self.tid = cache['tid']

    def init(self, crypto):
        """Initializes cache by fetching and reading all archive indicies
        """
        logging.info('Initializing cache...')
        self.chunk_counts = {}
        self.file_chunks = {}
        self.tid = self.store.tid
        if self.store.tid == 0:
            return
        for id in list(self.store.list(NS_ARCHIVE_CHUNKS)):
            data, hash = crypto.decrypt(self.store.get(NS_ARCHIVE_CHUNKS, id))
            cindex = msgpack.unpackb(data)
            for id, size in cindex['chunks']:
                try:
                    count, size = self.chunk_counts[id]
                    self.chunk_counts[id] = count + 1, size
                except KeyError:
                    self.chunk_counts[id] = 1, size
        self.save()

    def save(self):
        assert self.store.state == self.store.OPEN
        cache = {'version': 1,
                'tid': self.store.tid,
                'chunk_counts': self.chunk_counts,
                'file_chunks': dict(ifilter(lambda i: i[1][0] < 8,
                                            self.file_chunks.iteritems())),
        }
        data = msgpack.packb(cache)
        cachedir = os.path.dirname(self.path)
        if not os.path.exists(cachedir):
            os.makedirs(cachedir)
        with open(self.path, 'wb') as fd:
            fd.write(data)

    def add_chunk(self, id, data, crypto):
        if self.seen_chunk(id):
            return self.chunk_incref(id)
        data, hash = crypto.encrypt_read(data)
        csize = len(data)
        self.store.put(NS_CHUNK, id, data)
        self.chunk_counts[id] = (1, csize)
        return csize

    def seen_chunk(self, id):
        return self.chunk_counts.get(id, (0, 0))[0]

    def chunk_incref(self, id):
        count, size = self.chunk_counts[id]
        self.chunk_counts[id] = (count + 1, size)
        return size

    def chunk_decref(self, id):
        count, size = self.chunk_counts[id]
        if count == 1:
            del self.chunk_counts[id]
            self.store.delete(NS_CHUNK, id)
        else:
            self.chunk_counts[id] = (count - 1, size)

    def file_known_and_unchanged(self, path_hash, st):
        entry = self.file_chunks.get(path_hash)
        if (entry and entry[3] == st.st_mtime
            and entry[2] == st.st_size and entry[1] == st.st_ino):
            # reset entry age
            self.file_chunks[path_hash] = (0,) + entry[1:]
            return entry[4], entry[2]
        else:
            return None, 0

    def memorize_file_chunks(self, path_hash, st, ids):
        # Entry: Age, inode, size, mtime, chunk ids
        self.file_chunks[path_hash] = 0, st.st_ino, st.st_size, st.st_mtime, ids


from ConfigParser import RawConfigParser
import fcntl
import msgpack
import os
import shutil

from . import NS_ARCHIVE_CHUNKS, NS_CHUNK, PACKET_ARCHIVE_CHUNKS, PACKET_CHUNK
from .hashindex import NSIndex


class Cache(object):
    """Client Side cache
    """

    def __init__(self, store, keychain):
        self.txn_active = False
        self.store = store
        self.keychain = keychain
        self.path = os.path.join(Cache.cache_dir_path(), self.store.id.encode('hex'))
        if not os.path.exists(self.path):
            self.create()
        self.open()
        assert self.id == store.id
        if self.tid != store.tid:
            self.sync()

    @staticmethod
    def cache_dir_path():
        """Return path to directory used for storing users cache files"""
        return os.path.join(os.path.expanduser('~'), '.darc', 'cache')

    def create(self):
        """Create a new empty store at `path`
        """
        os.makedirs(self.path)
        with open(os.path.join(self.path, 'README'), 'wb') as fd:
            fd.write('This is a DARC cache')
        config = RawConfigParser()
        config.add_section('cache')
        config.set('cache', 'version', '1')
        config.set('cache', 'store_id', self.store.id.encode('hex'))
        config.set('cache', 'tid', '0')
        with open(os.path.join(self.path, 'config'), 'wb') as fd:
            config.write(fd)
        NSIndex.create(os.path.join(self.path, 'chunks'))
        with open(os.path.join(self.path, 'files'), 'wb') as fd:
            pass # empty file

    def open(self):
        if not os.path.isdir(self.path):
            raise Exception('%s Does not look like a darc cache' % self.path)
        self.lock_fd = open(os.path.join(self.path, 'README'), 'r+')
        fcntl.flock(self.lock_fd, fcntl.LOCK_EX)
        self.rollback()
        self.config = RawConfigParser()
        self.config.read(os.path.join(self.path, 'config'))
        if self.config.getint('cache', 'version') != 1:
            raise Exception('%s Does not look like a darc cache')
        self.id = self.config.get('cache', 'store_id').decode('hex')
        self.tid = self.config.getint('cache', 'tid')
        self.chunks = NSIndex(os.path.join(self.path, 'chunks'))
        with open(os.path.join(self.path, 'files'), 'rb') as fd:
            self.files = {}
            u = msgpack.Unpacker()
            while True:
                data = fd.read(64 * 1024)
                if not data:
                    break
                u.feed(data)
                for hash, item in u:
                    if item[0] < 8:
                        self.files[hash] = (item[0] + 1,) + item[1:]

    def begin_txn(self):
        # Initialize transaction snapshot
        txn_dir = os.path.join(self.path, 'txn.tmp')
        os.mkdir(txn_dir)
        shutil.copy(os.path.join(self.path, 'config'), txn_dir)
        shutil.copy(os.path.join(self.path, 'chunks'), txn_dir)
        shutil.copy(os.path.join(self.path, 'files'), txn_dir)
        os.rename(os.path.join(self.path, 'txn.tmp'),
                  os.path.join(self.path, 'txn.active'))
        self.txn_active = True

    def commit(self):
        """Commit transaction
        """
        if not self.txn_active:
            return
        with open(os.path.join(self.path, 'files'), 'wb') as fd:
            for item in self.files.iteritems():
                msgpack.pack(item, fd)
        for id, (count, size) in self.chunks.iteritems():
            if count > 1000000:
                self.chunks[id] = count - 1000000, size
        self.config.set('cache', 'tid', self.store.tid)
        with open(os.path.join(self.path, 'config'), 'w') as fd:
            self.config.write(fd)
        self.chunks.flush()
        os.rename(os.path.join(self.path, 'txn.active'),
                  os.path.join(self.path, 'txn.tmp'))
        shutil.rmtree(os.path.join(self.path, 'txn.tmp'))
        self.txn_active = False

    def rollback(self):
        """Roll back partial and aborted transactions
        """
        # Remove partial transaction
        if os.path.exists(os.path.join(self.path, 'txn.tmp')):
            shutil.rmtree(os.path.join(self.path, 'txn.tmp'))
        # Roll back active transaction
        txn_dir = os.path.join(self.path, 'txn.active')
        if os.path.exists(txn_dir):
            shutil.copy(os.path.join(txn_dir, 'config'), self.path)
            shutil.copy(os.path.join(txn_dir, 'chunks'), self.path)
            shutil.copy(os.path.join(txn_dir, 'files'), self.path)
            shutil.rmtree(txn_dir)
        self.txn_active = False

    def sync(self):
        """Initializes cache by fetching and reading all archive indicies
        """
        self.begin_txn()
        print 'Initializing cache...'
        for id in self.store.list(NS_ARCHIVE_CHUNKS):
            magic, data, hash = self.keychain.decrypt(self.store.get(NS_ARCHIVE_CHUNKS, id))
            assert magic == PACKET_ARCHIVE_CHUNKS
            chunks = msgpack.unpackb(data)
            for id, size in chunks:
                try:
                    count, size = self.chunks[id]
                    self.chunks[id] = count + 1, size
                except KeyError:
                    self.chunks[id] = 1, size

    def add_chunk(self, id, data):
        if not self.txn_active:
            self.begin_txn()
        if self.seen_chunk(id):
            return self.chunk_incref(id)
        data, hash = self.keychain.encrypt(PACKET_CHUNK, data)
        csize = len(data)
        self.store.put(NS_CHUNK, id, data)
        self.chunks[id] = (1000001, csize)
        return id

    def seen_chunk(self, id):
        return self.chunks.get(id, (0, 0))[0]

    def chunk_incref(self, id):
        if not self.txn_active:
            self.begin_txn()
        count, size = self.chunks[id]
        if count < 1000000:
            self.chunks[id] = (count + 1000001, size)
        return id

    def chunk_decref(self, id):
        if not self.txn_active:
            self.begin_txn()
        count, size = self.chunks[id]
        if count == 1:
            del self.chunks[id]
            self.store.delete(NS_CHUNK, id)
        else:
            self.chunks[id] = (count - 1, size)

    def file_known_and_unchanged(self, path_hash, st):
        entry = self.files.get(path_hash)
        if (entry and entry[3] == st.st_mtime
            and entry[2] == st.st_size and entry[1] == st.st_ino):
            # reset entry age
            self.files[path_hash] = (0,) + entry[1:]
            return entry[4], entry[2]
        else:
            return None, 0

    def memorize_file(self, path_hash, st, ids):
        # Entry: Age, inode, size, mtime, chunk ids
        self.files[path_hash] = 0, st.st_ino, st.st_size, st.st_mtime, ids


from __future__ import with_statement
from ConfigParser import RawConfigParser
import fcntl
from itertools import izip_longest
import msgpack
import os
import shutil

from .helpers import get_cache_dir
from .hashindex import ChunkIndex


class Cache(object):
    """Client Side cache
    """

    def __init__(self, store, key, manifest):
        self.txn_active = False
        self.store = store
        self.key = key
        self.manifest = manifest
        self.path = os.path.join(get_cache_dir(), store.id.encode('hex'))
        if not os.path.exists(self.path):
            self.create()
        self.open()
        if self.manifest.id != self.manifest_id:
            self.sync()
            self.commit()

    def create(self):
        """Create a new empty store at `path`
        """
        os.makedirs(self.path)
        with open(os.path.join(self.path, 'README'), 'wb') as fd:
            fd.write('This is a DARC cache')
        config = RawConfigParser()
        config.add_section('cache')
        config.set('cache', 'version', '1')
        config.set('cache', 'store', self.store.id.encode('hex'))
        config.set('cache', 'manifest', '')
        with open(os.path.join(self.path, 'config'), 'wb') as fd:
            config.write(fd)
        ChunkIndex.create(os.path.join(self.path, 'chunks'))
        with open(os.path.join(self.path, 'files'), 'wb') as fd:
            pass  # empty file

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
        self.id = self.config.get('cache', 'store')
        self.manifest_id = self.config.get('cache', 'manifest').decode('hex')
        self.chunks = ChunkIndex(os.path.join(self.path, 'chunks'))
        self.files = None

    def _read_files(self):
        self.files = {}
        self._newest_mtime = 0
        with open(os.path.join(self.path, 'files'), 'rb') as fd:
            u = msgpack.Unpacker()
            while True:
                data = fd.read(64 * 1024)
                if not data:
                    break
                u.feed(data)
                for hash, item in u:
                    if item[0] < 10:
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
        if self.files is not None:
            with open(os.path.join(self.path, 'files'), 'wb') as fd:
                for item in self.files.iteritems():
                    # Discard cached files with the newest mtime to avoid
                    # issues with filesystem snapshots and mtime precision
                    if item[1][3] < self._newest_mtime:
                        msgpack.pack(item, fd)
        self.config.set('cache', 'manifest', self.manifest.id.encode('hex'))
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
        # Roll back active transaction
        txn_dir = os.path.join(self.path, 'txn.active')
        if os.path.exists(txn_dir):
            shutil.copy(os.path.join(txn_dir, 'config'), self.path)
            shutil.copy(os.path.join(txn_dir, 'chunks'), self.path)
            shutil.copy(os.path.join(txn_dir, 'files'), self.path)
            os.rename(txn_dir, os.path.join(self.path, 'txn.tmp'))
        # Remove partial transaction
        if os.path.exists(os.path.join(self.path, 'txn.tmp')):
            shutil.rmtree(os.path.join(self.path, 'txn.tmp'))
        self.txn_active = False

    def sync(self):
        """Initializes cache by fetching and reading all archive indicies
        """
        def add(id, size, csize):
            try:
                count, size, csize = self.chunks[id]
                self.chunks[id] = count + 1, size, csize
            except KeyError:
                self.chunks[id] = 1, size, csize
        self.begin_txn()
        print 'Initializing cache...'
        self.chunks.clear()
        unpacker = msgpack.Unpacker()
        for name, info in self.manifest.archives.items():
            id = info['id']
            cdata = self.store.get(id)
            data = self.key.decrypt(id, cdata)
            add(id, len(data), len(cdata))
            archive = msgpack.unpackb(data)
            print 'Analyzing archive:', archive['name']
            for id, chunk in izip_longest(archive['items'], self.store.get_many(archive['items'])):
                data = self.key.decrypt(id, chunk)
                add(id, len(data), len(chunk))
                unpacker.feed(data)
                for item in unpacker:
                    try:
                        for id, size, csize in item['chunks']:
                            add(id, size, csize)
                    except KeyError:
                        pass

    def add_chunk(self, id, data, stats):
        if not self.txn_active:
            self.begin_txn()
        if self.seen_chunk(id):
            return self.chunk_incref(id, stats)
        size = len(data)
        data = self.key.encrypt(data)
        csize = len(data)
        self.store.put(id, data, wait=False)
        self.chunks[id] = (1, size, csize)
        stats.update(size, csize, True)
        return id, size, csize

    def seen_chunk(self, id):
        return self.chunks.get(id, (0, 0, 0))[0]

    def chunk_incref(self, id, stats):
        if not self.txn_active:
            self.begin_txn()
        count, size, csize = self.chunks[id]
        self.chunks[id] = (count + 1, size, csize)
        stats.update(size, csize, False)
        return id, size, csize

    def chunk_decref(self, id):
        if not self.txn_active:
            self.begin_txn()
        count, size, csize = self.chunks[id]
        if count == 1:
            del self.chunks[id]
            self.store.delete(id, wait=False)
        else:
            self.chunks[id] = (count - 1, size, csize)

    def file_known_and_unchanged(self, path_hash, st):
        if self.files is None:
            self._read_files()
        entry = self.files.get(path_hash)
        if (entry and entry[3] == st.st_mtime
            and entry[2] == st.st_size and entry[1] == st.st_ino):
            # reset entry age
            self.files[path_hash] = (0,) + entry[1:]
            return entry[4]
        else:
            return None

    def memorize_file(self, path_hash, st, ids):
        # Entry: Age, inode, size, mtime, chunk ids
        self.files[path_hash] = 0, st.st_ino, st.st_size, st.st_mtime, ids
        self._newest_mtime = max(self._newest_mtime, st.st_mtime)


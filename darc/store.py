from ConfigParser import RawConfigParser
import fcntl
import numpy
import os
import shutil
import struct
import tempfile
import unittest
from UserDict import DictMixin

from .lrucache import LRUCache


class Store(object):
    """Filesystem based transactional key value store

    On disk layout:
    dir/README
    dir/config
    dir/bands/<X / BANDS_PER_DIR>/<X>
    dir/indexes/<NS>
    """
    DEFAULT_MAX_BAND_SIZE = 10 * 1024 * 1024
    DEFAULT_BANDS_PER_DIR = 10000

    class DoesNotExist(KeyError):
        """Requested key does not exist"""


    def __init__(self, path, create=False):
        self.txn_active = False
        if create:
            self.create(path)
        self.open(path)

    def create(self, path):
        """Create a new empty store at `path`
        """
        if os.path.exists(path) and (not os.path.isdir(path) or os.listdir(path)):
            raise Exception('Path "%s" already exists' % path)
        if not os.path.exists(path):
            os.mkdir(path)
        with open(os.path.join(path, 'README'), 'wb') as fd:
            fd.write('This is a DARC store')
        os.mkdir(os.path.join(path, 'bands'))
        os.mkdir(os.path.join(path, 'indexes'))
        config = RawConfigParser()
        config.add_section('store')
        config.set('store', 'version', '1')
        config.set('store', 'id', os.urandom(32).encode('hex'))
        config.set('store', 'bands_per_dir', self.DEFAULT_BANDS_PER_DIR)
        config.set('store', 'max_band_size', self.DEFAULT_MAX_BAND_SIZE)
        config.add_section('state')
        config.set('state', 'next_band', '0')
        config.set('state', 'tid', '0')
        with open(os.path.join(path, 'config'), 'w') as fd:
            config.write(fd)

    def open(self, path):
        self.path = path
        if not os.path.isdir(path):
            raise Exception('%s Does not look like a darc store' % path)
        self.lock_fd = open(os.path.join(path, 'README'), 'r+')
        fcntl.flock(self.lock_fd, fcntl.LOCK_EX)
        self.config = RawConfigParser()
        self.config.read(os.path.join(path, 'config'))
        if self.config.getint('store', 'version') != 1:
            raise Exception('%s Does not look like a darc store')
        self.id = self.config.get('store', 'id').decode('hex')
        self.tid = self.config.getint('state', 'tid')
        next_band = self.config.getint('state', 'next_band')
        max_band_size = self.config.getint('store', 'max_band_size')
        bands_per_dir = self.config.getint('store', 'bands_per_dir')
        self.rollback()
        self.io = BandIO(self.path, next_band, max_band_size, bands_per_dir)

    def begin_txn(self):
        txn_dir = os.path.join(self.path, 'txn.tmp')
        # Initialize transaction snapshot
        os.mkdir(txn_dir)
        shutil.copytree(os.path.join(self.path, 'indexes'),
                        os.path.join(txn_dir, 'indexes'))
        shutil.copy(os.path.join(self.path, 'config'), txn_dir)
        os.rename(os.path.join(self.path, 'txn.tmp'),
                  os.path.join(self.path, 'txn.active'))
        self.compact = set()
        self.txn_active = True

    def close(self):
        self.rollback()
        self.lock_fd.close()

    def commit(self):
        """Commit transaction, `tid` will be increased by 1
        """
        self.compact_bands()
        self.io.close()
        self.tid += 1
        self.config.set('state', 'tid', self.tid)
        self.config.set('state', 'next_band', self.io.band + 1)
        with open(os.path.join(self.path, 'config'), 'w') as fd:
            self.config.write(fd)
        for i in self.indexes.values():
            i.flush()
        os.rename(os.path.join(self.path, 'txn.active'),
                  os.path.join(self.path, 'txn.tmp'))
        shutil.rmtree(os.path.join(self.path, 'txn.tmp'))
        self.indexes = {}
        self.txn_active = False

    def compact_bands(self):
        if not self.compact:
            return
        self.io.close_band()
        for band in self.compact:
            for ns, key, offset, size in self.io.iter_objects(band):
                if key in self.indexes[ns]:
                    del self.indexes[ns][key]
                    data = self.io.read(band, offset)
                    self.indexes[ns][key] = self.io.write(ns, key, data)
        for band in self.compact:
            self.io.delete_band(band)

    def rollback(self):
        """
        """
        # Remove partial transaction
        if os.path.exists(os.path.join(self.path, 'txn.tmp')):
            shutil.rmtree(os.path.join(self.path, 'txn.tmp'))
        # Roll back active transaction
        txn_dir = os.path.join(self.path, 'txn.active')
        if os.path.exists(txn_dir):
            shutil.rmtree(os.path.join(self.path, 'indexes'))
            shutil.copytree(os.path.join(txn_dir, 'indexes'),
                            os.path.join(self.path, 'indexes'))
            shutil.copy(os.path.join(txn_dir, 'config'), self.path)
            shutil.rmtree(txn_dir)
        self.indexes = {}
        self.txn_active = False

    def get_index(self, ns):
        try:
            return self.indexes[ns]
        except KeyError:
            filename = os.path.join(self.path, 'indexes', str(ns))
            if os.path.exists(filename):
                self.indexes[ns] = HashIndex(filename)
            else:
                self.indexes[ns] = HashIndex.create(filename)
            return self.indexes[ns]

    def get(self, ns, id):
        try:
            band, offset = self.get_index(ns)[id]
            return self.io.read(band, offset)
        except KeyError:
            raise self.DoesNotExist

    def put(self, ns, id, data):
        if not self.txn_active:
            self.begin_txn()
        band, offset = self.io.write(ns, id, data)
        self.get_index(ns)[id] = band, offset

    def delete(self, ns, id):
        if not self.txn_active:
            self.begin_txn()
        try:
            band, offset = self.get_index(ns).pop(id)
            self.compact.add(band)
        except KeyError:
            raise self.DoesNotExist

    def list(self, ns, marker=None, limit=1000000):
        return [key for (key, value) in
                self.get_index(ns).iteritems(marker=marker, limit=limit)]


class HashIndex(DictMixin):
    """Hash Table with open addressing and lazy deletes
    """
    EMPTY, DELETED = -1, -2
    FREE = (EMPTY, DELETED)

    i_fmt    = struct.Struct('<i')
    assert i_fmt.size == 4
    idx_type = numpy.dtype('V32,<i,<i')
    assert idx_type.itemsize == 40

    def __init__(self, path):
        self.path = path
        self.fd = open(path, 'r+')
        assert self.fd.read(8) == 'DARCHASH'
        self.num_entries = self.i_fmt.unpack(self.fd.read(4))[0]
        self.buckets = numpy.memmap(self.fd, self.idx_type, offset=12)
        self.limit = 3 * self.buckets.size / 4  # 75% fill rate

    def flush(self):
        self.fd.seek(8)
        self.fd.write(self.i_fmt.pack(self.num_entries))
        self.fd.flush()
        self.buckets.flush()

    @classmethod
    def create(cls, path, capacity=1024):
        with open(path, 'wb') as fd:
            fd.write('DARCHASH\0\0\0\0')
            a = numpy.zeros(capacity, cls.idx_type)
            for i in xrange(capacity):
                a[i][1] = cls.EMPTY
            a.tofile(fd)
        return cls(path)

    def index(self, key):
        hash = self.i_fmt.unpack(key[:4])[0]
        return hash % self.buckets.size

    def lookup(self, key):
        didx = -1
        idx = self.index(key)
        while True:
            while self.buckets[idx][1] == self.DELETED:
                if didx == -1:
                    didx = idx
                idx = (idx + 1) % self.buckets.size
            if self.buckets[idx][1] == self.EMPTY:
                raise KeyError
            if str(self.buckets[idx][0]) == key:
                if didx != -1:
                    self.buckets[didx] = self.buckets[idx]
                    self.buckets[idx][1] = self.DELETED
                    idx = didx
                return idx
            idx = (idx + 1) % self.buckets.size

    def __contains__(self, key):
        try:
            self[key]
            return True
        except KeyError:
            return False

    def pop(self, key):
        idx = self.lookup(key)
        band = self.buckets[idx][1]
        self.buckets[idx][1] = self.DELETED
        self.num_entries -= 1
        return band, self.buckets[idx][2]

    def __getitem__(self, key):
        idx = self.lookup(key)
        return self.buckets[idx][1], self.buckets[idx][2]

    def __delitem__(self, key):
        self.buckets[self.lookup(key)][1] = self.DELETED
        self.num_entries -= 1

    def __setitem__(self, key, value):
        if self.num_entries >= self.limit:
            self.resize()
        try:
            idx = self.lookup(key)
            self.buckets[idx][1], self.buckets[idx][2] = value
            return
        except KeyError:
            idx = self.index(key)
            while self.buckets[idx][1] not in self.FREE:
                idx = (idx + 1) % self.buckets.size
            self.buckets[idx][1], self.buckets[idx][2] = value
            self.buckets[idx][0] = key
            self.num_entries += 1

    def iteritems(self, limit=0, marker=None):
        n = 0
        for idx in xrange(self.buckets.size):
            if self.buckets[idx][1] in self.FREE:
                continue
            key = str(self.buckets[idx][0])
            if marker and key != marker:
                continue
            elif marker:
                marker = None
            yield key, (self.buckets[idx][1], self.buckets[idx][2])
            n += 1
            if n == limit:
                return

    def resize(self, capacity=0):
        capacity = capacity or self.buckets.size * 2
        if capacity < self.num_entries:
            raise ValueError('HashIndex full')
        new = HashIndex.create(self.path + '.tmp', capacity)
        for key, value in self.iteritems():
            new[key] = value
        new.flush()
        os.unlink(self.path)
        os.rename(self.path + '.tmp', self.path)
        self.fd = new.fd
        self.buckets = new.buckets
        self.limit = 3 * self.buckets.size / 4


class BandIO(object):

    header_fmt = struct.Struct('<iBB32s')
    assert header_fmt.size == 38

    def __init__(self, path, nextband, limit, bands_per_dir, capacity=100):
        self.path = path
        self.fds = LRUCache(capacity)
        self.band = nextband
        self.limit = limit
        self.bands_per_dir = bands_per_dir
        self.offset = 0

    def close(self):
        for band in self.fds.keys():
            self.fds.pop(band).close()

    def band_filename(self, band):
        return os.path.join(self.path, 'bands', str(band / self.bands_per_dir), str(band))

    def get_fd(self, band, write=False):
        try:
            return self.fds[band]
        except KeyError:
            if write and band % 1000 == 0:
                dirname = os.path.join(self.path, 'bands', str(band / self.bands_per_dir))
                if not os.path.exists(dirname):
                    os.mkdir(dirname)
            fd = open(self.band_filename(band), write and 'w+' or 'rb')
            self.fds[band] = fd
            return fd

    def delete_band(self, band):
        os.unlink(self.band_filename(band))

    def read(self, band, offset):
        fd = self.get_fd(band)
        fd.seek(offset)
        data = fd.read(self.header_fmt.size)
        size, magic, ns, id = self.header_fmt.unpack(data)
        assert magic == 0
        return fd.read(size - self.header_fmt.size)

    def iter_objects(self, band):
        fd = self.get_fd(band)
        fd.seek(0)
        assert fd.read(8) == 'DARCBAND'
        offset = 8
        data = fd.read(self.header_fmt.size)
        while data:
            size, magic, ns, key = self.header_fmt.unpack(data)
            size -= self.header_fmt.size
            yield ns, key, offset, size
            offset += size + self.header_fmt.size
            fd.seek(offset)
            data = fd.read(self.header_fmt.size)

    def write(self, ns, id, data):
        size = len(data) + self.header_fmt.size
        if self.offset and self.offset + size > self.limit:
            self.close_band()
        fd = self.get_fd(self.band, write=True)
        fd.seek(self.offset)
        if self.offset == 0:
            fd.write('DARCBAND')
            self.offset = 8
        offset = self.offset
        fd.write(self.header_fmt.pack(size, 0, ns, id))
        fd.write(data)
        self.offset += size
        return self.band, offset

    def close_band(self):
        self.band += 1
        self.offset = 0


class StoreTestCase(unittest.TestCase):

    def setUp(self):
        self.tmppath = tempfile.mkdtemp()
        self.store = Store(os.path.join(self.tmppath, 'store'), create=True)

    def tearDown(self):
        shutil.rmtree(self.tmppath)

    def test1(self):
        self.assertEqual(self.store.tid, 0)
        for x in range(100):
            self.store.put(0, '%-32d' % x, 'SOMEDATA')
        key50 = '%-32d' % 50
        self.assertEqual(self.store.get(0, key50), 'SOMEDATA')
        self.store.delete(0, key50)
        self.assertRaises(self.store.DoesNotExist, lambda: self.store.get(0, key50))
        self.store.commit()
        self.assertEqual(self.store.tid, 1)
        self.store.close()
        store2 = Store(os.path.join(self.tmppath, 'store'))
        self.assertEqual(store2.tid, 1)
        keys = store2.list(0)
        for x in range(50):
            key = '%-32d' % x
            self.assertEqual(store2.get(0, key), 'SOMEDATA')
        self.assertRaises(store2.DoesNotExist, lambda: store2.get(0, key50))
        assert key50 not in keys
        for x in range(51, 100):
            key = '%-32d' % x
            assert key in keys
            self.assertEqual(store2.get(0, key), 'SOMEDATA')
        self.assertEqual(len(keys), 99)
        for x in range(50):
            key = '%-32d' % x
            store2.delete(0, key)
        self.assertEqual(len(store2.list(0)), 49)
        for x in range(51, 100):
            key = '%-32d' % x
            store2.delete(0, key)
        self.assertEqual(len(store2.list(0)), 0)


def suite():
    return unittest.TestLoader().loadTestsFromTestCase(StoreTestCase)

if __name__ == '__main__':
    unittest.main()

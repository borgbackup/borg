from ConfigParser import RawConfigParser
import fcntl
import os
import shutil
import struct
import tempfile
import unittest
from zlib import crc32

from .hashindex import NSIndex, BandIndex
from .helpers import IntegrityError, read_set, write_set
from .lrucache import LRUCache


class Store(object):
    """Filesystem based transactional key value store

    On disk layout:
    dir/README
    dir/config
    dir/bands/<X / BANDS_PER_DIR>/<X>
    dir/indexes/<NS>
    """
    DEFAULT_MAX_BAND_SIZE = 5 * 1024 * 1024
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
        BandIndex.create(os.path.join(path, 'indexes', 'bands'))
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
        self.rollback()
        self.config = RawConfigParser()
        self.config.read(os.path.join(path, 'config'))
        if self.config.getint('store', 'version') != 1:
            raise Exception('%s Does not look like a darc store')
        self.id = self.config.get('store', 'id').decode('hex')
        self.tid = self.config.getint('state', 'tid')
        next_band = self.config.getint('state', 'next_band')
        max_band_size = self.config.getint('store', 'max_band_size')
        bands_per_dir = self.config.getint('store', 'bands_per_dir')
        self.io = BandIO(self.path, next_band, max_band_size, bands_per_dir)

    def delete_bands(self):
        delete_path = os.path.join(self.path, 'indexes', 'delete')
        if os.path.exists(delete_path):
            for band in read_set(delete_path):
                assert self.bands.pop(band) == 0
                self.io.delete_band(band)
            os.unlink(delete_path)

    def begin_txn(self):
        self.io.cleanup()
        self.delete_bands()
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
        self.bands = BandIndex(os.path.join(self.path, 'indexes', 'bands'))

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
        self.bands.flush()
        os.rename(os.path.join(self.path, 'txn.active'),
                  os.path.join(self.path, 'txn.tmp'))
        shutil.rmtree(os.path.join(self.path, 'txn.tmp'))
        self.indexes = {}
        self.txn_active = False
        self.delete_bands()

    def compact_bands(self):
        """Compact sparse bands by copying data into new bands
        """
        if not self.compact:
            return
        self.io.close_band()
        def lookup(ns, key):
            return key in self.get_index(ns)
        for band in self.compact:
            if self.bands[band] > 0:
                for ns, key, data in self.io.iter_objects(band, lookup):
                    new_band, offset = self.io.write(ns, key, data)
                    self.indexes[ns][key] = new_band, offset
                    self.bands[band] -= 1
                    self.bands.setdefault(new_band, 0)
                    self.bands[new_band] += 1
        write_set(self.compact, os.path.join(self.path, 'indexes', 'delete'))

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
            filename = os.path.join(self.path, 'indexes', 'ns%d' % ns)
            if os.path.exists(filename):
                self.indexes[ns] = NSIndex(filename)
            else:
                self.indexes[ns] = NSIndex.create(filename)
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
        self.bands.setdefault(band, 0)
        self.bands[band] += 1
        self.get_index(ns)[id] = band, offset

    def delete(self, ns, id):
        if not self.txn_active:
            self.begin_txn()
        try:
            band, offset = self.get_index(ns).pop(id)
            self.bands[band] -= 1
            self.compact.add(band)
        except KeyError:
            raise self.DoesNotExist

    def list(self, ns, marker=None, limit=1000000):
        return [key for (key, value) in
                self.get_index(ns).iteritems(marker=marker, limit=limit)]


class BandIO(object):

    header_fmt = struct.Struct('<iBiB32s')
    assert header_fmt.size == 42

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

    def cleanup(self):
        """Delete band files left by aborted transactions
        """
        band = self.band
        while True:
            filename = self.band_filename(band)
            if not os.path.exists(filename):
                break
            os.unlink(filename)
            band += 1

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
        size, magic, hash, ns, id = self.header_fmt.unpack(data)
        assert magic == 0
        data = fd.read(size - self.header_fmt.size)
        if crc32(data) != hash:
            raise IntegrityError('Band checksum mismatch')
        return data

    def iter_objects(self, band, lookup):
        fd = self.get_fd(band)
        fd.seek(0)
        assert fd.read(8) == 'DARCBAND'
        offset = 8
        data = fd.read(self.header_fmt.size)
        while data:
            size, magic, hash, ns, key = self.header_fmt.unpack(data)
            assert magic == 0
            offset += size
            if lookup(ns, key):
                data = fd.read(size - self.header_fmt.size)
                if crc32(data) != hash:
                    raise IntegrityError('Band checksum mismatch')
                yield ns, key, data
            else:
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
        hash = crc32(data)
        fd.write(self.header_fmt.pack(size, 0, hash, ns, id))
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

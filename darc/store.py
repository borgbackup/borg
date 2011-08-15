from __future__ import with_statement
from ConfigParser import RawConfigParser
import errno
import fcntl
import os
import msgpack
import shutil
import struct
import tempfile
import unittest
from zlib import crc32

from .hashindex import NSIndex
from .helpers import IntegrityError, deferrable
from .lrucache import LRUCache


class Store(object):
    """Filesystem based transactional key value store

    On disk layout:
    dir/README
    dir/config
    dir/bands/<X / BANDS_PER_DIR>/<X>
    dir/band
    dir/index
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
        config = RawConfigParser()
        config.add_section('store')
        config.set('store', 'version', '1')
        config.set('store', 'bands_per_dir', self.DEFAULT_BANDS_PER_DIR)
        config.set('store', 'max_band_size', self.DEFAULT_MAX_BAND_SIZE)
        config.set('store', 'next_band', '0')
        config.add_section('meta')
        config.set('meta', 'manifest', '')
        config.set('meta', 'id', os.urandom(32).encode('hex'))
        NSIndex.create(os.path.join(path, 'index'))
        self.write_dict(os.path.join(path, 'band'), {})
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
        next_band = self.config.getint('store', 'next_band')
        max_band_size = self.config.getint('store', 'max_band_size')
        bands_per_dir = self.config.getint('store', 'bands_per_dir')
        self.meta = dict(self.config.items('meta'))
        self.io = BandIO(self.path, next_band, max_band_size, bands_per_dir)
        self.io.cleanup()

    def read_dict(self, filename):
        with open(filename, 'rb') as fd:
            return msgpack.unpackb(fd.read())

    def write_dict(self, filename, d):
        with open(filename, 'wb') as fd:
            fd.write(msgpack.packb(d))

    def delete_bands(self):
        delete_path = os.path.join(self.path, 'delete')
        if os.path.exists(delete_path):
            bands = self.read_dict(os.path.join(self.path, 'band'))
            for band in self.read_dict(delete_path):
                assert bands.pop(band, 0) == 0
                self.io.delete_band(band, missing_ok=True)
            os.unlink(delete_path)
            self.write_dict(os.path.join(self.path, 'band'), bands)

    def begin_txn(self):
        txn_dir = os.path.join(self.path, 'txn.tmp')
        # Initialize transaction snapshot
        os.mkdir(txn_dir)
        shutil.copy(os.path.join(self.path, 'config'), txn_dir)
        shutil.copy(os.path.join(self.path, 'index'), txn_dir)
        shutil.copy(os.path.join(self.path, 'band'), txn_dir)
        os.rename(os.path.join(self.path, 'txn.tmp'),
                  os.path.join(self.path, 'txn.active'))
        self.compact = set()
        self.txn_active = True

    def close(self):
        self.rollback()
        self.lock_fd.close()

    def commit(self, meta=None):
        """Commit transaction
        """
        meta = meta or self.meta
        self.compact_bands()
        self.io.close()
        self.config.set('store', 'next_band', self.io.band + 1)
        self.config.remove_section('meta')
        self.config.add_section('meta')
        for k, v in meta.items():
            self.config.set('meta', k, v)
        with open(os.path.join(self.path, 'config'), 'w') as fd:
            self.config.write(fd)
        self.index.flush()
        self.write_dict(os.path.join(self.path, 'band'), self.bands)
        # If we crash before this line, the transaction will be
        # rolled back by open()
        os.rename(os.path.join(self.path, 'txn.active'),
                  os.path.join(self.path, 'txn.commit'))
        self.rollback()

    def compact_bands(self):
        """Compact sparse bands by copying data into new bands
        """
        if not self.compact:
            return
        self.io.close_band()
        def lookup(key):
            return key in self.index
        bands = self.bands
        for band in self.compact:
            if bands[band] > 0:
                for key, data in self.io.iter_objects(band, lookup):
                    new_band, offset = self.io.write(key, data)
                    self.index[key] = new_band, offset
                    bands[band] -= 1
                    bands.setdefault(new_band, 0)
                    bands[new_band] += 1
        self.write_dict(os.path.join(self.path, 'delete'), tuple(self.compact))

    def rollback(self):
        """
        """
        # Commit any half committed transaction
        if os.path.exists(os.path.join(self.path, 'txn.commit')):
            self.delete_bands()
            os.rename(os.path.join(self.path, 'txn.commit'),
                      os.path.join(self.path, 'txn.tmp'))
        # Roll back active transaction
        txn_dir = os.path.join(self.path, 'txn.active')
        if os.path.exists(txn_dir):
            shutil.copy(os.path.join(txn_dir, 'config'), self.path)
            shutil.copy(os.path.join(txn_dir, 'index'), self.path)
            shutil.copy(os.path.join(txn_dir, 'band'), self.path)
            os.rename(txn_dir, os.path.join(self.path, 'txn.tmp'))
        # Remove partially removed transaction
        if os.path.exists(os.path.join(self.path, 'txn.tmp')):
            shutil.rmtree(os.path.join(self.path, 'txn.tmp'))
        self.index = NSIndex(os.path.join(self.path, 'index'))
        self.bands = self.read_dict(os.path.join(self.path, 'band'))
        self.txn_active = False

    @deferrable
    def get(self, id):
        try:
            band, offset = self.index[id]
            return self.io.read(band, offset, id)
        except KeyError:
            raise self.DoesNotExist

    @deferrable
    def put(self, id, data):
        if not self.txn_active:
            self.begin_txn()
        band, offset = self.io.write(id, data)
        self.bands.setdefault(band, 0)
        self.bands[band] += 1
        self.index[id] = band, offset

    @deferrable
    def delete(self, id):
        if not self.txn_active:
            self.begin_txn()
        try:
            band, offset = self.index.pop(id)
            self.bands[band] -= 1
            self.compact.add(band)
        except KeyError:
            raise self.DoesNotExist

    def flush_rpc(self, *args):
        pass


class BandIO(object):

    header_fmt = struct.Struct('<IBI32s')
    assert header_fmt.size == 41

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

    def delete_band(self, band, missing_ok=False):
        try:
            os.unlink(self.band_filename(band))
        except OSError, e:
            if not missing_ok or e.errno != errno.ENOENT:
                raise

    def read(self, band, offset, id):
        fd = self.get_fd(band)
        fd.seek(offset)
        data = fd.read(self.header_fmt.size)
        size, magic, hash, id_ = self.header_fmt.unpack(data)
        if magic != 0 or id != id_:
            raise IntegrityError('Invalid band entry header')
        data = fd.read(size - self.header_fmt.size)
        if crc32(data) & 0xffffffff != hash:
            raise IntegrityError('Band checksum mismatch')
        return data

    def iter_objects(self, band, lookup):
        fd = self.get_fd(band)
        fd.seek(0)
        if fd.read(8) != 'DARCBAND':
            raise IntegrityError('Invalid band header')
        offset = 8
        data = fd.read(self.header_fmt.size)
        while data:
            size, magic, hash, key = self.header_fmt.unpack(data)
            if magic != 0:
                raise IntegrityError('Unknown band entry header')
            offset += size
            if lookup(key):
                data = fd.read(size - self.header_fmt.size)
                if crc32(data) & 0xffffffff != hash:
                    raise IntegrityError('Band checksum mismatch')
                yield key, data
            else:
                fd.seek(offset)
            data = fd.read(self.header_fmt.size)

    def write(self, id, data):
        size = len(data) + self.header_fmt.size
        if self.offset and self.offset + size > self.limit:
            self.close_band()
        fd = self.get_fd(self.band, write=True)
        fd.seek(self.offset)
        if self.offset == 0:
            fd.write('DARCBAND')
            self.offset = 8
        offset = self.offset
        hash = crc32(data) & 0xffffffff
        fd.write(self.header_fmt.pack(size, 0, hash, id))
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
        for x in range(100):
            self.store.put('%-32d' % x, 'SOMEDATA')
        key50 = '%-32d' % 50
        self.assertEqual(self.store.get(key50), 'SOMEDATA')
        self.store.delete(key50)
        self.assertRaises(self.store.DoesNotExist, lambda: self.store.get(key50))
        self.store.commit()
        self.store.close()
        store2 = Store(os.path.join(self.tmppath, 'store'))


def suite():
    return unittest.TestLoader().loadTestsFromTestCase(StoreTestCase)

if __name__ == '__main__':
    unittest.main()

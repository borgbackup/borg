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
    dir/data/<X / SEGMENTS_PER_DIR>/<X>
    dir/segments
    dir/index
    """
    DEFAULT_MAX_SEGMENT_SIZE = 5 * 1024 * 1024
    DEFAULT_SEGMENTS_PER_DIR = 10000

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
        os.mkdir(os.path.join(path, 'data'))
        config = RawConfigParser()
        config.add_section('store')
        config.set('store', 'version', '1')
        config.set('store', 'segments_per_dir', self.DEFAULT_SEGMENTS_PER_DIR)
        config.set('store', 'max_segment_size', self.DEFAULT_MAX_SEGMENT_SIZE)
        config.set('store', 'next_segment', '0')
        config.add_section('meta')
        config.set('meta', 'manifest', '')
        config.set('meta', 'id', os.urandom(32).encode('hex'))
        NSIndex.create(os.path.join(path, 'index'))
        self.write_dict(os.path.join(path, 'segments'), {})
        with open(os.path.join(path, 'config'), 'w') as fd:
            config.write(fd)

    def open(self, path):
        self.path = path
        if not os.path.isdir(path):
            raise Exception('%s Does not look like a darc store' % path)
        self.lock_fd = open(os.path.join(path, 'README'), 'r+')
        fcntl.flock(self.lock_fd, fcntl.LOCK_EX)
        self.rollback()

    def read_dict(self, filename):
        with open(filename, 'rb') as fd:
            return msgpack.unpackb(fd.read())

    def write_dict(self, filename, d):
        with open(filename+'.tmp', 'wb') as fd:
            fd.write(msgpack.packb(d))
        os.rename(filename+'.tmp', filename)

    def delete_segments(self):
        delete_path = os.path.join(self.path, 'delete')
        if os.path.exists(delete_path):
            segments = self.read_dict(os.path.join(self.path, 'segments'))
            for segment in self.read_dict(delete_path):
                assert segments.pop(segment, 0) == 0
                self.io.delete_segment(segment, missing_ok=True)
            self.write_dict(os.path.join(self.path, 'segments'), segments)

    def begin_txn(self):
        txn_dir = os.path.join(self.path, 'txn.tmp')
        # Initialize transaction snapshot
        os.mkdir(txn_dir)
        shutil.copy(os.path.join(self.path, 'config'), txn_dir)
        shutil.copy(os.path.join(self.path, 'index'), txn_dir)
        shutil.copy(os.path.join(self.path, 'segments'), txn_dir)
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
        self.compact_segments()
        self.io.close()
        self.config.set('store', 'next_segment', self.io.segment + 1)
        self.config.remove_section('meta')
        self.config.add_section('meta')
        for k, v in meta.items():
            self.config.set('meta', k, v)
        with open(os.path.join(self.path, 'config'), 'w') as fd:
            self.config.write(fd)
        self.index.flush()
        self.write_dict(os.path.join(self.path, 'segments'), self.segments)
        # If we crash before this line, the transaction will be
        # rolled back by open()
        os.rename(os.path.join(self.path, 'txn.active'),
                  os.path.join(self.path, 'txn.commit'))
        self.rollback()

    def compact_segments(self):
        """Compact sparse segments by copying data into new segments
        """
        if not self.compact:
            return
        self.io.close_segment()
        def lookup(key):
            return self.index.get(key, (-1, -1))[0] == segment
        segments = self.segments
        for segment in self.compact:
            if segments[segment] > 0:
                for key, data in self.io.iter_objects(segment, lookup):
                    new_segment, offset = self.io.write(key, data)
                    self.index[key] = new_segment, offset
                    segments.setdefault(new_segment, 0)
                    segments[new_segment] += 1
                    segments[segment] -= 1
        self.write_dict(os.path.join(self.path, 'delete'), tuple(self.compact))

    def rollback(self):
        """
        """
        # Commit any half committed transaction
        if os.path.exists(os.path.join(self.path, 'txn.commit')):
            self.delete_segments()
            os.rename(os.path.join(self.path, 'txn.commit'),
                      os.path.join(self.path, 'txn.tmp'))

        delete_path = os.path.join(self.path, 'delete')
        if os.path.exists(delete_path):
            os.unlink(delete_path)
        # Roll back active transaction
        txn_dir = os.path.join(self.path, 'txn.active')
        if os.path.exists(txn_dir):
            shutil.copy(os.path.join(txn_dir, 'config'), self.path)
            shutil.copy(os.path.join(txn_dir, 'index'), self.path)
            shutil.copy(os.path.join(txn_dir, 'segments'), self.path)
            os.rename(txn_dir, os.path.join(self.path, 'txn.tmp'))
        # Remove partially removed transaction
        if os.path.exists(os.path.join(self.path, 'txn.tmp')):
            shutil.rmtree(os.path.join(self.path, 'txn.tmp'))
        self.index = NSIndex(os.path.join(self.path, 'index'))
        self.segments = self.read_dict(os.path.join(self.path, 'segments'))
        self.config = RawConfigParser()
        self.config.read(os.path.join(self.path, 'config'))
        if self.config.getint('store', 'version') != 1:
            raise Exception('%s Does not look like a darc store')
        next_segment = self.config.getint('store', 'next_segment')
        max_segment_size = self.config.getint('store', 'max_segment_size')
        segments_per_dir = self.config.getint('store', 'segments_per_dir')
        self.meta = dict(self.config.items('meta'))
        self.io = SegmentIO(self.path, next_segment, max_segment_size, segments_per_dir)
        self.io.cleanup()
        self.txn_active = False

    @deferrable
    def get(self, id):
        try:
            segment, offset = self.index[id]
            return self.io.read(segment, offset, id)
        except KeyError:
            raise self.DoesNotExist

    @deferrable
    def put(self, id, data):
        if not self.txn_active:
            self.begin_txn()
        try:
            segment, _ = self.index[id]
            self.segments[segment] -= 1
            self.compact.add(segment)
        except KeyError:
            pass
        segment, offset = self.io.write(id, data)
        self.segments.setdefault(segment, 0)
        self.segments[segment] += 1
        self.index[id] = segment, offset

    @deferrable
    def delete(self, id):
        if not self.txn_active:
            self.begin_txn()
        try:
            segment, offset = self.index.pop(id)
            self.segments[segment] -= 1
            self.compact.add(segment)
        except KeyError:
            raise self.DoesNotExist

    def flush_rpc(self, *args):
        pass


class SegmentIO(object):

    header_fmt = struct.Struct('<IBI32s')
    assert header_fmt.size == 41

    def __init__(self, path, next_segment, limit, segments_per_dir, capacity=100):
        self.path = path
        self.fds = LRUCache(capacity)
        self.segment = next_segment
        self.limit = limit
        self.segments_per_dir = segments_per_dir
        self.offset = 0

    def close(self):
        for segment in self.fds.keys():
            self.fds.pop(segment).close()
	self.fds = None # Just to make sure we're disabled

    def cleanup(self):
        """Delete segment files left by aborted transactions
        """
        segment = self.segment
        while True:
            filename = self.segment_filename(segment)
            if not os.path.exists(filename):
                break
            os.unlink(filename)
            segment += 1

    def segment_filename(self, segment):
        return os.path.join(self.path, 'data', str(segment / self.segments_per_dir), str(segment))

    def get_fd(self, segment, write=False):
        try:
            return self.fds[segment]
        except KeyError:
            if write and segment % self.segments_per_dir == 0:
                dirname = os.path.join(self.path, 'data', str(segment / self.segments_per_dir))
                if not os.path.exists(dirname):
                    os.mkdir(dirname)
            fd = open(self.segment_filename(segment), write and 'w+' or 'rb')
            self.fds[segment] = fd
            return fd

    def delete_segment(self, segment, missing_ok=False):
        try:
            os.unlink(self.segment_filename(segment))
        except OSError, e:
            if not missing_ok or e.errno != errno.ENOENT:
                raise

    def read(self, segment, offset, id):
        fd = self.get_fd(segment)
        fd.seek(offset)
        data = fd.read(self.header_fmt.size)
        size, magic, hash, id_ = self.header_fmt.unpack(data)
        if magic != 0 or id != id_:
            raise IntegrityError('Invalid segment entry header')
        data = fd.read(size - self.header_fmt.size)
        if crc32(data) & 0xffffffff != hash:
            raise IntegrityError('Segment checksum mismatch')
        return data

    def iter_objects(self, segment, lookup):
        fd = self.get_fd(segment)
        fd.seek(0)
        if fd.read(8) != 'DSEGMENT':
            raise IntegrityError('Invalid segment header')
        offset = 8
        data = fd.read(self.header_fmt.size)
        while data:
            size, magic, hash, key = self.header_fmt.unpack(data)
            if magic != 0:
                raise IntegrityError('Unknown segment entry header')
            offset += size
            if lookup(key):
                data = fd.read(size - self.header_fmt.size)
                if crc32(data) & 0xffffffff != hash:
                    raise IntegrityError('Segment checksum mismatch')
                yield key, data
            else:
                fd.seek(offset)
            data = fd.read(self.header_fmt.size)

    def write(self, id, data):
        size = len(data) + self.header_fmt.size
        if self.offset and self.offset + size > self.limit:
            self.close_segment()
        fd = self.get_fd(self.segment, write=True)
        fd.seek(self.offset)
        if self.offset == 0:
            fd.write('DSEGMENT')
            self.offset = 8
        offset = self.offset
        hash = crc32(data) & 0xffffffff
        fd.write(self.header_fmt.pack(size, 0, hash, id))
        fd.write(data)
        self.offset += size
        return self.segment, offset

    def close_segment(self):
        self.segment += 1
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

    def test2(self):
        """Test multiple sequential transactions
        """
        self.store.put('00000000000000000000000000000000', 'foo')
        self.store.put('00000000000000000000000000000001', 'foo')
        self.store.commit()
        self.store.delete('00000000000000000000000000000000')
        self.store.put('00000000000000000000000000000001', 'bar')
        self.store.commit()
        self.assertEqual(self.store.get('00000000000000000000000000000001'), 'bar')


def suite():
    return unittest.TestLoader().loadTestsFromTestCase(StoreTestCase)

if __name__ == '__main__':
    unittest.main()

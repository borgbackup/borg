from __future__ import with_statement
from ConfigParser import RawConfigParser
import fcntl
import os
import re
import shutil
import struct
import tempfile
import unittest
from zlib import crc32

from .hashindex import NSIndex
from .helpers import IntegrityError, read_msgpack, write_msgpack
from .lrucache import LRUCache

MAX_OBJECT_SIZE = 20 * 1024 * 1024

TAG_PUT = 0
TAG_DELETE = 1
TAG_COMMIT = 2


class Store(object):
    """Filesystem based transactional key value store

    On disk layout:
    dir/README
    dir/config
    dir/data/<X / SEGMENTS_PER_DIR>/<X>
    dir/index.X
    dir/hints.X
    """
    DEFAULT_MAX_SEGMENT_SIZE = 5 * 1024 * 1024
    DEFAULT_SEGMENTS_PER_DIR = 10000

    class DoesNotExist(KeyError):
        """Requested key does not exist"""

    def __init__(self, path, create=False):
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
        config.set('store', 'id', os.urandom(32).encode('hex'))
        with open(os.path.join(path, 'config'), 'w') as fd:
            config.write(fd)

    def open(self, path):
        self.head = None
        self.path = path
        if not os.path.isdir(path):
            raise Exception('%s Does not look like a darc store' % path)
        self.lock_fd = open(os.path.join(path, 'README'), 'r+')
        fcntl.flock(self.lock_fd, fcntl.LOCK_EX)
        self.config = RawConfigParser()
        self.config.read(os.path.join(self.path, 'config'))
        if self.config.getint('store', 'version') != 1:
            raise Exception('%s Does not look like a darc store')
        self.max_segment_size = self.config.getint('store', 'max_segment_size')
        self.segments_per_dir = self.config.getint('store', 'segments_per_dir')
        self.id = self.config.get('store', 'id').decode('hex')
        self.rollback()

    def close(self):
        self.lock_fd.close()

    def commit(self, rollback=True):
        """Commit transaction
        """
        self.io.write_commit()
        self.compact_segments()
        self.write_index()
        self.rollback()

    def _available_indices(self, reverse=False):
        names = [int(name[6:]) for name in os.listdir(self.path) if re.match('index\.\d+', name)]
        names.sort(reverse=reverse)
        return names

    def open_index(self, head, read_only=False):
        if head is None:
            self.index = NSIndex.create(os.path.join(self.path, 'index.tmp'))
            self.segments = {}
            self.compact = set()
        else:
            if read_only:
                self.index = NSIndex(os.path.join(self.path, 'index.%d') % head)
            else:
                shutil.copy(os.path.join(self.path, 'index.%d' % head),
                            os.path.join(self.path, 'index.tmp'))
                self.index = NSIndex(os.path.join(self.path, 'index.tmp'))
            hints = read_msgpack(os.path.join(self.path, 'hints.%d' % head))
            if hints['version'] != 1:
                raise ValueError('Unknown hints file version: %d' % hints['version'])
            self.segments = hints['segments']
            self.compact = set(hints['compact'])

    def write_index(self):
        hints = {'version': 1,
                 'segments': self.segments,
                 'compact': list(self.compact)}
        write_msgpack(os.path.join(self.path, 'hints.%d' % self.io.head), hints)
        self.index.flush()
        os.rename(os.path.join(self.path, 'index.tmp'),
                  os.path.join(self.path, 'index.%d' % self.io.head))
        # Remove old indices
        current = '.%d' % self.io.head
        for name in os.listdir(self.path):
            if not name.startswith('index.') and not name.startswith('hints.'):
                continue
            if name.endswith(current):
                continue
            os.unlink(os.path.join(self.path, name))

    def compact_segments(self):
        """Compact sparse segments by copying data into new segments
        """
        if not self.compact:
            return

        def lookup(tag, key):
            return tag == TAG_PUT and self.index.get(key, (-1, -1))[0] == segment
        segments = self.segments
        for segment in sorted(self.compact):
            if segments[segment] > 0:
                for tag, key, data in self.io.iter_objects(segment, lookup, include_data=True):
                    new_segment, offset = self.io.write_put(key, data)
                    self.index[key] = new_segment, offset
                    segments.setdefault(new_segment, 0)
                    segments[new_segment] += 1
                    segments[segment] -= 1
                assert segments[segment] == 0
        self.io.write_commit()
        for segment in self.compact:
            assert self.segments.pop(segment) == 0
            self.io.delete_segment(segment)
        self.compact = set()

    def recover(self, path):
        """Recover missing index by replaying logs"""
        start = None
        available = self._available_indices()
        if available:
            start = available[-1]
        self.open_index(start)
        for segment, filename in self.io._segment_names():
            if start is not None and segment <= start:
                continue
            self.segments[segment] = 0
            for tag, key, offset in self.io.iter_objects(segment):
                if tag == TAG_PUT:
                    try:
                        s, _ = self.index[key]
                        self.compact.add(s)
                        self.segments[s] -= 1
                    except KeyError:
                        pass
                    self.index[key] = segment, offset
                    self.segments[segment] += 1
                elif tag == TAG_DELETE:
                    try:
                        s, _ = self.index.pop(key)
                        self.segments[s] -= 1
                        self.compact.add(s)
                        self.compact.add(segment)
                    except KeyError:
                        pass
            if self.segments[segment] == 0:
                self.compact.add(segment)
        if self.io.head is not None:
            self.write_index()

    def rollback(self):
        """
        """
        self._active_txn = False
        self.io = LoggedIO(self.path, self.max_segment_size, self.segments_per_dir)
        if self.io.head is not None and not os.path.exists(os.path.join(self.path, 'index.%d' % self.io.head)):
            self.recover(self.path)
        self.open_index(self.io.head, read_only=True)

    def _len(self):
        return len(self.index)

    def get(self, id):
        try:
            segment, offset = self.index[id]
            return self.io.read(segment, offset, id)
        except KeyError:
            raise self.DoesNotExist

    def get_many(self, ids, peek=None):
        for id in ids:
            yield self.get(id)

    def put(self, id, data, wait=True):
        if not self._active_txn:
            self._active_txn = True
            self.open_index(self.io.head)
        try:
            segment, _ = self.index[id]
            self.segments[segment] -= 1
            self.compact.add(segment)
            segment = self.io.write_delete(id)
            self.segments.setdefault(segment, 0)
            self.compact.add(segment)
        except KeyError:
            pass
        segment, offset = self.io.write_put(id, data)
        self.segments.setdefault(segment, 0)
        self.segments[segment] += 1
        self.index[id] = segment, offset

    def delete(self, id, wait=True):
        if not self._active_txn:
            self._active_txn = True
            self.open_index(self.io.head)
        try:
            segment, offset = self.index.pop(id)
            self.segments[segment] -= 1
            self.compact.add(segment)
            segment = self.io.write_delete(id)
            self.compact.add(segment)
            self.segments.setdefault(segment, 0)
        except KeyError:
            raise self.DoesNotExist

    def add_callback(self, cb, data):
        cb(None, None, data)


class LoggedIO(object):

    header_fmt = struct.Struct('<IIB')
    assert header_fmt.size == 9
    put_header_fmt = struct.Struct('<IIB32s')
    assert put_header_fmt.size == 41
    header_no_crc_fmt = struct.Struct('<IB')
    assert header_no_crc_fmt.size == 5
    crc_fmt = struct.Struct('<I')
    assert crc_fmt.size == 4

    _commit = header_no_crc_fmt.pack(9, TAG_COMMIT)
    COMMIT = crc_fmt.pack(crc32(_commit)) + _commit

    def __init__(self, path, limit, segments_per_dir, capacity=100):
        self.path = path
        self.fds = LRUCache(capacity)
        self.segment = None
        self.limit = limit
        self.segments_per_dir = segments_per_dir
        self.offset = 0
        self._write_fd = None
        self.head = None
        self.cleanup()

    def close(self):
        for segment in self.fds.keys():
            self.fds.pop(segment).close()
        self.close_segment()
        self.fds = None  # Just to make sure we're disabled

    def _segment_names(self, reverse=False):
        for dirpath, dirs, filenames in os.walk(os.path.join(self.path, 'data')):
            dirs.sort(lambda a, b: cmp(int(a), int(b)), reverse=reverse)
            filenames.sort(lambda a, b: cmp(int(a), int(b)), reverse=reverse)
            for filename in filenames:
                yield int(filename), os.path.join(dirpath, filename)

    def cleanup(self):
        """Delete segment files left by aborted transactions
        """
        self.head = None
        self.segment = 0
        for segment, filename in self._segment_names(reverse=True):
            if self.is_complete_segment(filename):
                self.head = segment
                self.segment = self.head + 1
                return
            else:
                os.unlink(filename)

    def is_complete_segment(self, filename):
        with open(filename, 'rb') as fd:
            fd.seek(-self.header_fmt.size, 2)
            return fd.read(self.header_fmt.size) == self.COMMIT

    def segment_filename(self, segment):
        return os.path.join(self.path, 'data', str(segment / self.segments_per_dir), str(segment))

    def get_write_fd(self, no_new=False):
        if not no_new and self.offset and self.offset > self.limit:
            self.close_segment()
        if not self._write_fd:
            if self.segment % self.segments_per_dir == 0:
                dirname = os.path.join(self.path, 'data', str(self.segment / self.segments_per_dir))
                if not os.path.exists(dirname):
                    os.mkdir(dirname)
            self._write_fd = open(self.segment_filename(self.segment), 'ab')
            self._write_fd.write('DSEGMENT')
            self.offset = 8
        return self._write_fd

    def get_fd(self, segment):
        try:
            return self.fds[segment]
        except KeyError:
            fd = open(self.segment_filename(segment), 'rb')
            self.fds[segment] = fd
            return fd

    def delete_segment(self, segment):
        try:
            os.unlink(self.segment_filename(segment))
        except OSError:
            pass

    def iter_objects(self, segment, lookup=None, include_data=False):
        fd = self.get_fd(segment)
        fd.seek(0)
        if fd.read(8) != 'DSEGMENT':
            raise IntegrityError('Invalid segment header')
        offset = 8
        header = fd.read(self.header_fmt.size)
        while header:
            crc, size, tag = self.header_fmt.unpack(header)
            if size > MAX_OBJECT_SIZE:
                raise IntegrityError('Invalid segment object size')
            rest = fd.read(size - self.header_fmt.size)
            if crc32(rest, crc32(buffer(header, 4))) & 0xffffffff != crc:
                raise IntegrityError('Segment checksum mismatch')
            if tag not in (TAG_PUT, TAG_DELETE, TAG_COMMIT):
                raise IntegrityError('Invalid segment entry header')
            key = None
            if tag in (TAG_PUT, TAG_DELETE):
                key = rest[:32]
            if not lookup or lookup(tag, key):
                if include_data:
                    yield tag, key, rest[32:]
                else:
                    yield tag, key, offset
            offset += size
            header = fd.read(self.header_fmt.size)

    def read(self, segment, offset, id):
        if segment == self.segment:
            self._write_fd.flush()
        fd = self.get_fd(segment)
        fd.seek(offset)
        header = fd.read(self.put_header_fmt.size)
        crc, size, tag, key = self.put_header_fmt.unpack(header)
        if size > MAX_OBJECT_SIZE:
            raise IntegrityError('Invalid segment object size')
        data = fd.read(size - self.put_header_fmt.size)
        if crc32(data, crc32(buffer(header, 4))) & 0xffffffff != crc:
            raise IntegrityError('Segment checksum mismatch')
        if tag != TAG_PUT or id != key:
            raise IntegrityError('Invalid segment entry header')
        return data

    def write_put(self, id, data):
        size = len(data) + self.put_header_fmt.size
        fd = self.get_write_fd()
        offset = self.offset
        header = self.header_no_crc_fmt.pack(size, TAG_PUT)
        crc = self.crc_fmt.pack(crc32(data, crc32(id, crc32(header))) & 0xffffffff)
        fd.write(''.join((crc, header, id, data)))
        self.offset += size
        return self.segment, offset

    def write_delete(self, id):
        fd = self.get_write_fd()
        header = self.header_no_crc_fmt.pack(self.put_header_fmt.size, TAG_DELETE)
        crc = self.crc_fmt.pack(crc32(id, crc32(header)) & 0xffffffff)
        fd.write(''.join((crc, header, id)))
        self.offset += self.put_header_fmt.size
        return self.segment

    def write_commit(self):
        fd = self.get_write_fd(no_new=True)
        header = self.header_no_crc_fmt.pack(self.header_fmt.size, TAG_COMMIT)
        crc = self.crc_fmt.pack(crc32(header) & 0xffffffff)
        fd.write(''.join((crc, header)))
        self.head = self.segment
        self.close_segment()

    def close_segment(self):
        if self._write_fd:
            self.segment += 1
            self.offset = 0
            os.fsync(self._write_fd)
            self._write_fd.close()
            self._write_fd = None


class StoreTestCase(unittest.TestCase):

    def open(self, create=False):
        return Store(os.path.join(self.tmppath, 'store'), create=create)

    def setUp(self):
        self.tmppath = tempfile.mkdtemp()
        self.store = self.open(create=True)

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
        store2 = self.open()
        self.assertRaises(store2.DoesNotExist, lambda: store2.get(key50))
        for x in range(100):
            if x == 50:
                continue
            self.assertEqual(store2.get('%-32d' % x), 'SOMEDATA')

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

    def test_consistency(self):
        """Test cache consistency
        """
        self.store.put('00000000000000000000000000000000', 'foo')
        self.assertEqual(self.store.get('00000000000000000000000000000000'), 'foo')
        self.store.put('00000000000000000000000000000000', 'foo2')
        self.assertEqual(self.store.get('00000000000000000000000000000000'), 'foo2')
        self.store.put('00000000000000000000000000000000', 'bar')
        self.assertEqual(self.store.get('00000000000000000000000000000000'), 'bar')
        self.store.delete('00000000000000000000000000000000')
        self.assertRaises(self.store.DoesNotExist, lambda: self.store.get('00000000000000000000000000000000'))

    def test_consistency2(self):
        """Test cache consistency2
        """
        self.store.put('00000000000000000000000000000000', 'foo')
        self.assertEqual(self.store.get('00000000000000000000000000000000'), 'foo')
        self.store.commit()
        self.store.put('00000000000000000000000000000000', 'foo2')
        self.assertEqual(self.store.get('00000000000000000000000000000000'), 'foo2')
        self.store.rollback()
        self.assertEqual(self.store.get('00000000000000000000000000000000'), 'foo')

    def test_single_kind_transactions(self):
        # put
        self.store.put('00000000000000000000000000000000', 'foo')
        self.store.commit()
        self.store.close()
        # replace
        self.store = self.open()
        self.store.put('00000000000000000000000000000000', 'bar')
        self.store.commit()
        self.store.close()
        # delete
        self.store = self.open()
        self.store.delete('00000000000000000000000000000000')
        self.store.commit()



def suite():
    return unittest.TestLoader().loadTestsFromTestCase(StoreTestCase)

if __name__ == '__main__':
    unittest.main()

from collections import OrderedDict
from datetime import datetime, timezone
from io import StringIO
from unittest.mock import Mock

import pytest

from . import BaseTestCase
from ..crypto.key import PlaintextKey
from ..archive import Archive, CacheChunkBuffer, RobustUnpacker, valid_msgpacked_dict, ITEM_KEYS, Statistics
from ..archive import BackupOSError, backup_io, backup_io_iter
from ..helpers import Manifest
from ..helpers import msgpack
from ..item import Item, ArchiveItem


@pytest.fixture()
def stats():
    stats = Statistics()
    stats.update(20, 10, unique=True)
    return stats


def test_stats_basic(stats):
    assert stats.osize == 20
    assert stats.csize == stats.usize == 10
    stats.update(20, 10, unique=False)
    assert stats.osize == 40
    assert stats.csize == 20
    assert stats.usize == 10


def tests_stats_progress(stats, monkeypatch, columns=80):
    monkeypatch.setenv('COLUMNS', str(columns))
    out = StringIO()
    stats.show_progress(stream=out)
    s = '20 B O 10 B C 10 B D 0 N '
    buf = ' ' * (columns - len(s))
    assert out.getvalue() == s + buf + "\r"

    out = StringIO()
    stats.update(10**3, 0, unique=False)
    stats.show_progress(item=Item(path='foo'), final=False, stream=out)
    s = '1.02 kB O 10 B C 10 B D 0 N foo'
    buf = ' ' * (columns - len(s))
    assert out.getvalue() == s + buf + "\r"
    out = StringIO()
    stats.show_progress(item=Item(path='foo'*40), final=False, stream=out)
    s = '1.02 kB O 10 B C 10 B D 0 N foofoofoofoofoofoofoofo...oofoofoofoofoofoofoofoofoo'
    buf = ' ' * (columns - len(s))
    assert out.getvalue() == s + buf + "\r"


def test_stats_format(stats):
    assert str(stats) == """\
This archive:                   20 B                 10 B                 10 B"""
    s = "{0.osize_fmt}".format(stats)
    assert s == "20 B"
    # kind of redundant, but id is variable so we can't match reliably
    assert repr(stats) == '<Statistics object at {:#x} (20, 10, 10)>'.format(id(stats))


class MockCache:

    class MockRepo:
        def async_response(self, wait=True):
            pass

    def __init__(self):
        self.objects = {}
        self.repository = self.MockRepo()

    def add_chunk(self, id, chunk, stats=None, wait=True):
        self.objects[id] = chunk
        return id, len(chunk), len(chunk)


class ArchiveTimestampTestCase(BaseTestCase):

    def _test_timestamp_parsing(self, isoformat, expected):
        repository = Mock()
        key = PlaintextKey(repository)
        manifest = Manifest(repository, key)
        a = Archive(repository, key, manifest, 'test', create=True)
        a.metadata = ArchiveItem(time=isoformat)
        self.assert_equal(a.ts, expected)

    def test_with_microseconds(self):
        self._test_timestamp_parsing(
            '1970-01-01T00:00:01.000001',
            datetime(1970, 1, 1, 0, 0, 1, 1, timezone.utc))

    def test_without_microseconds(self):
        self._test_timestamp_parsing(
            '1970-01-01T00:00:01',
            datetime(1970, 1, 1, 0, 0, 1, 0, timezone.utc))


class ChunkBufferTestCase(BaseTestCase):

    def test(self):
        data = [Item(path='p1'), Item(path='p2')]
        cache = MockCache()
        key = PlaintextKey(None)
        chunks = CacheChunkBuffer(cache, key, None)
        for d in data:
            chunks.add(d)
            chunks.flush()
        chunks.flush(flush=True)
        self.assert_equal(len(chunks.chunks), 2)
        unpacker = msgpack.Unpacker()
        for id in chunks.chunks:
            unpacker.feed(cache.objects[id])
        self.assert_equal(data, [Item(internal_dict=d) for d in unpacker])

    def test_partial(self):
        big = "0123456789abcdefghijklmnopqrstuvwxyz" * 25000
        data = [Item(path='full', source=big), Item(path='partial', source=big)]
        cache = MockCache()
        key = PlaintextKey(None)
        chunks = CacheChunkBuffer(cache, key, None)
        for d in data:
            chunks.add(d)
        chunks.flush(flush=False)
        # the code is expected to leave the last partial chunk in the buffer
        self.assert_equal(len(chunks.chunks), 3)
        self.assert_true(chunks.buffer.tell() > 0)
        # now really flush
        chunks.flush(flush=True)
        self.assert_equal(len(chunks.chunks), 4)
        self.assert_true(chunks.buffer.tell() == 0)
        unpacker = msgpack.Unpacker()
        for id in chunks.chunks:
            unpacker.feed(cache.objects[id])
        self.assert_equal(data, [Item(internal_dict=d) for d in unpacker])


class RobustUnpackerTestCase(BaseTestCase):

    def make_chunks(self, items):
        return b''.join(msgpack.packb({'path': item}) for item in items)

    def _validator(self, value):
        return isinstance(value, dict) and value.get(b'path') in (b'foo', b'bar', b'boo', b'baz')

    def process(self, input):
        unpacker = RobustUnpacker(validator=self._validator, item_keys=ITEM_KEYS)
        result = []
        for should_sync, chunks in input:
            if should_sync:
                unpacker.resync()
            for data in chunks:
                unpacker.feed(data)
                for item in unpacker:
                    result.append(item)
        return result

    def test_extra_garbage_no_sync(self):
        chunks = [(False, [self.make_chunks([b'foo', b'bar'])]),
                  (False, [b'garbage'] + [self.make_chunks([b'boo', b'baz'])])]
        result = self.process(chunks)
        self.assert_equal(result, [
            {b'path': b'foo'}, {b'path': b'bar'},
            103, 97, 114, 98, 97, 103, 101,
            {b'path': b'boo'},
            {b'path': b'baz'}])

    def split(self, left, length):
        parts = []
        while left:
            parts.append(left[:length])
            left = left[length:]
        return parts

    def test_correct_stream(self):
        chunks = self.split(self.make_chunks([b'foo', b'bar', b'boo', b'baz']), 2)
        input = [(False, chunks)]
        result = self.process(input)
        self.assert_equal(result, [{b'path': b'foo'}, {b'path': b'bar'}, {b'path': b'boo'}, {b'path': b'baz'}])

    def test_missing_chunk(self):
        chunks = self.split(self.make_chunks([b'foo', b'bar', b'boo', b'baz']), 4)
        input = [(False, chunks[:3]), (True, chunks[4:])]
        result = self.process(input)
        self.assert_equal(result, [{b'path': b'foo'}, {b'path': b'boo'}, {b'path': b'baz'}])

    def test_corrupt_chunk(self):
        chunks = self.split(self.make_chunks([b'foo', b'bar', b'boo', b'baz']), 4)
        input = [(False, chunks[:3]), (True, [b'gar', b'bage'] + chunks[3:])]
        result = self.process(input)
        self.assert_equal(result, [{b'path': b'foo'}, {b'path': b'boo'}, {b'path': b'baz'}])


@pytest.fixture
def item_keys_serialized():
    return [msgpack.packb(name) for name in ITEM_KEYS]


@pytest.mark.parametrize('packed',
    [b'', b'x', b'foobar', ] +
    [msgpack.packb(o) for o in (
        [None, 0, 0.0, False, '', {}, [], ()] +
        [42, 23.42, True, b'foobar', {b'foo': b'bar'}, [b'foo', b'bar'], (b'foo', b'bar')]
    )])
def test_invalid_msgpacked_item(packed, item_keys_serialized):
    assert not valid_msgpacked_dict(packed, item_keys_serialized)


# pytest-xdist requires always same order for the keys and dicts:
IK = sorted(list(ITEM_KEYS))


@pytest.mark.parametrize('packed',
    [msgpack.packb(o) for o in [
        {b'path': b'/a/b/c'},  # small (different msgpack mapping type!)
        OrderedDict((k, b'') for k in IK),  # as big (key count) as it gets
        OrderedDict((k, b'x' * 1000) for k in IK),  # as big (key count and volume) as it gets
    ]])
def test_valid_msgpacked_items(packed, item_keys_serialized):
    assert valid_msgpacked_dict(packed, item_keys_serialized)


def test_key_length_msgpacked_items():
    key = b'x' * 32  # 31 bytes is the limit for fixstr msgpack type
    data = {key: b''}
    item_keys_serialized = [msgpack.packb(key), ]
    assert valid_msgpacked_dict(msgpack.packb(data), item_keys_serialized)


def test_backup_io():
    with pytest.raises(BackupOSError):
        with backup_io:
            raise OSError(123)


def test_backup_io_iter():
    class Iterator:
        def __init__(self, exc):
            self.exc = exc

        def __next__(self):
            raise self.exc()

    oserror_iterator = Iterator(OSError)
    with pytest.raises(BackupOSError):
        for _ in backup_io_iter(oserror_iterator):
            pass

    normal_iterator = Iterator(StopIteration)
    for _ in backup_io_iter(normal_iterator):
        assert False, 'StopIteration handled incorrectly'

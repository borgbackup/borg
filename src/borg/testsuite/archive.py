import os
from datetime import datetime, timezone
from io import StringIO
from unittest.mock import Mock

import pytest
import msgpack

from ..archive import Archive, CacheChunkBuffer, RobustUnpacker, Statistics
from ..item import Item
from ..key import PlaintextKey
from ..helpers import Manifest
from . import BaseTestCase


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


def tests_stats_progress(stats, columns=80):
    os.environ['COLUMNS'] = str(columns)
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
                       Original size      Compressed size    Deduplicated size
This archive:                   20 B                 10 B                 10 B"""
    s = "{0.osize_fmt}".format(stats)
    assert s == "20 B"
    # kind of redundant, but id is variable so we can't match reliably
    assert repr(stats) == '<Statistics object at {:#x} (20, 10, 10)>'.format(id(stats))


class MockCache:

    def __init__(self):
        self.objects = {}

    def add_chunk(self, id, chunk, stats=None):
        self.objects[id] = chunk.data
        return id, len(chunk.data), len(chunk.data)


class ArchiveTimestampTestCase(BaseTestCase):

    def _test_timestamp_parsing(self, isoformat, expected):
        repository = Mock()
        key = PlaintextKey(repository)
        manifest = Manifest(repository, key)
        a = Archive(repository, key, manifest, 'test', create=True)
        a.metadata = {b'time': isoformat}
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
        big = "0123456789" * 10000
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
        unpacker = RobustUnpacker(validator=self._validator)
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

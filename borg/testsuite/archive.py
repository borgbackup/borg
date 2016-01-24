from datetime import datetime, timezone
from unittest.mock import Mock

import msgpack

from ..archive import Archive, CacheChunkBuffer, RobustUnpacker
from ..key import PlaintextKey
from ..helpers import Manifest
from . import BaseTestCase


class MockCache:

    def __init__(self):
        self.objects = {}

    def add_chunk(self, id, data, stats=None):
        self.objects[id] = data
        return id, len(data), len(data)


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
        data = [{b'foo': 1}, {b'bar': 2}]
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
        self.assert_equal(data, list(unpacker))


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

import msgpack
from attic.testsuite import AtticTestCase
from attic.archive import ChunkBuffer
from attic.key import PlaintextKey


class MockCache:

    def __init__(self):
        self.objects = {}

    def add_chunk(self, id, data, stats=None):
        self.objects[id] = data
        return id, len(data), len(data)


class ChunkBufferTestCase(AtticTestCase):

    def test(self):
        data = [{b'foo': 1}, {b'bar': 2}]
        cache = MockCache()
        key = PlaintextKey()
        chunks = ChunkBuffer(cache, key, None)
        for d in data:
            chunks.add(d)
            chunks.flush()
        chunks.flush(flush=True)
        self.assert_equal(len(chunks.chunks), 2)
        unpacker = msgpack.Unpacker()
        for id in chunks.chunks:
            unpacker.feed(cache.objects[id])
        self.assert_equal(data, list(unpacker))

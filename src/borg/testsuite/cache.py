import io

from msgpack import packb

import pytest

from ..hashindex import ChunkIndex, CacheSynchronizer
from .hashindex import H


class TestCacheSynchronizer:
    @pytest.fixture
    def index(self):
        return ChunkIndex()

    @pytest.fixture
    def sync(self, index):
        return CacheSynchronizer(index)

    def test_no_chunks(self, index, sync):
        data = packb({
            'foo': 'bar',
            'baz': 1234,
            'bar': 5678,
            'user': 'chunks',
            'chunks': []
        })
        sync.feed(data)
        assert not len(index)

    def test_simple(self, index, sync):
        data = packb({
            'foo': 'bar',
            'baz': 1234,
            'bar': 5678,
            'user': 'chunks',
            'chunks': [
                (H(1), 1, 2),
                (H(2), 2, 3),
            ]
        })
        sync.feed(data)
        assert len(index) == 2
        assert index[H(1)] == (1, 1, 2)
        assert index[H(2)] == (1, 2, 3)

    def test_multiple(self, index, sync):
        data = packb({
            'foo': 'bar',
            'baz': 1234,
            'bar': 5678,
            'user': 'chunks',
            'chunks': [
                (H(1), 1, 2),
                (H(2), 2, 3),
            ]
        })
        data += packb({
            'xattrs': {
                'security.foo': 'bar',
                'chunks': '123456',
            },
            'stuff': [
                (1, 2, 3),
            ]
        })
        data += packb({
            'xattrs': {
                'security.foo': 'bar',
                'chunks': '123456',
            },
            'chunks': [
                (H(1), 1, 2),
                (H(2), 2, 3),
            ],
            'stuff': [
                (1, 2, 3),
            ]
        })
        data += packb({
            'chunks': [
                (H(3), 1, 2),
            ],
        })
        data += packb({
            'chunks': [
                (H(1), 1, 2),
            ],
        })

        part1 = data[:70]
        part2 = data[70:120]
        part3 = data[120:]
        sync.feed(part1)
        sync.feed(part2)
        sync.feed(part3)
        assert len(index) == 3
        assert index[H(1)] == (3, 1, 2)
        assert index[H(2)] == (2, 2, 3)
        assert index[H(3)] == (1, 1, 2)

    @pytest.mark.parametrize('elem,error', (
        ({1: 2}, 'Unexpected object: map'),
        (bytes(213), [
            'Unexpected bytes in chunks structure',  # structure 2/3
            'Incorrect key length']),                # structure 3/3
        (1, 'Unexpected object: integer'),
        (1.0, 'Unexpected object: double'),
        (True, 'Unexpected object: true'),
        (False, 'Unexpected object: false'),
        (None, 'Unexpected object: nil'),
    ))
    @pytest.mark.parametrize('structure', (
        lambda elem: {'chunks': elem},
        lambda elem: {'chunks': [elem]},
        lambda elem: {'chunks': [(elem, 1, 2)]},
    ))
    def test_corrupted(self, sync, structure, elem, error):
        packed = packb(structure(elem))
        with pytest.raises(ValueError) as excinfo:
            sync.feed(packed)
        if isinstance(error, str):
            error = [error]
        possible_errors = ['cache_sync_feed failed: ' + error for error in error]
        assert str(excinfo.value) in possible_errors

    @pytest.mark.parametrize('data,error', (
        # Incorrect tuple length
        ({'chunks': [(bytes(32), 2, 3, 4)]}, 'Invalid chunk list entry length'),
        ({'chunks': [(bytes(32), 2)]}, 'Invalid chunk list entry length'),
        # Incorrect types
        ({'chunks': [(1, 2, 3)]}, 'Unexpected object: integer'),
        ({'chunks': [(1, bytes(32), 2)]}, 'Unexpected object: integer'),
        ({'chunks': [(bytes(32), 1.0, 2)]}, 'Unexpected object: double'),
    ))
    def test_corrupted_ancillary(self, index, sync, data, error):
        packed = packb(data)
        with pytest.raises(ValueError) as excinfo:
            sync.feed(packed)
        assert str(excinfo.value) == 'cache_sync_feed failed: ' + error

    def make_index_with_refcount(self, refcount):
        index_data = io.BytesIO()
        index_data.write(b'BORG_IDX')
        # num_entries
        index_data.write((1).to_bytes(4, 'little'))
        # num_buckets
        index_data.write((1).to_bytes(4, 'little'))
        # key_size
        index_data.write((32).to_bytes(1, 'little'))
        # value_size
        index_data.write((3 * 4).to_bytes(1, 'little'))

        index_data.write(H(0))
        index_data.write(refcount.to_bytes(4, 'little'))
        index_data.write((1234).to_bytes(4, 'little'))
        index_data.write((5678).to_bytes(4, 'little'))

        index_data.seek(0)
        index = ChunkIndex.read(index_data)
        return index

    def test_corrupted_refcount(self):
        index = self.make_index_with_refcount(ChunkIndex.MAX_VALUE + 1)
        sync = CacheSynchronizer(index)
        data = packb({
            'chunks': [
                (H(0), 1, 2),
            ]
        })
        with pytest.raises(ValueError) as excinfo:
            sync.feed(data)
        assert str(excinfo.value) == 'cache_sync_feed failed: invalid reference count'

    def test_refcount_max_value(self):
        index = self.make_index_with_refcount(ChunkIndex.MAX_VALUE)
        sync = CacheSynchronizer(index)
        data = packb({
            'chunks': [
                (H(0), 1, 2),
            ]
        })
        sync.feed(data)
        assert index[H(0)] == (ChunkIndex.MAX_VALUE, 1234, 5678)

    def test_refcount_one_below_max_value(self):
        index = self.make_index_with_refcount(ChunkIndex.MAX_VALUE - 1)
        sync = CacheSynchronizer(index)
        data = packb({
            'chunks': [
                (H(0), 1, 2),
            ]
        })
        sync.feed(data)
        # Incremented to maximum
        assert index[H(0)] == (ChunkIndex.MAX_VALUE, 1234, 5678)
        sync.feed(data)
        assert index[H(0)] == (ChunkIndex.MAX_VALUE, 1234, 5678)

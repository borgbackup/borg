import pytest
from borg.hashindex import NSIndex, ChunkIndex

def test_nsindex_iteritems_marker():
    nsindex = NSIndex()
    nsindex[b'\xbb'*32] = (123, 456)
    nsindex[b'\xaa'*32] = (234, 567)

    # marker exists
    items = list(nsindex.iteritems(marker=b'\xbb'*32))
    assert len(items) == 1
    assert items[0][0] == b'\xaa'*32

    # marker does not exist
    with pytest.raises(KeyError, match="marker not found"):
        list(nsindex.iteritems(marker=b'\xcc'*32))

def test_chunkindex_iteritems_marker():
    chunkindex = ChunkIndex()
    chunkindex[b'\xbb'*32] = (1, 100, 50)
    chunkindex[b'\xaa'*32] = (1, 200, 100)

    # marker exists
    items = list(chunkindex.iteritems(marker=b'\xbb'*32))
    assert len(items) == 1
    assert items[0][0] == b'\xaa'*32

    # marker does not exist
    with pytest.raises(KeyError, match="marker not found"):
        list(chunkindex.iteritems(marker=b'\xcc'*32))

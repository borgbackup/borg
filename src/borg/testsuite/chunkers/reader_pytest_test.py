import os
from io import BytesIO

import pytest

from . import make_sparsefile, fs_supports_sparse
from . import BS, map_sparse1, map_sparse2, map_onlysparse, map_notsparse
from ...chunkers import sparsemap, FileReader, FileFMAPReader, Chunk
from ...constants import *  # NOQA


@pytest.mark.skipif(not fs_supports_sparse(), reason="fs does not support sparse files")
@pytest.mark.parametrize(
    "fname, sparse_map",
    [("sparse1", map_sparse1), ("sparse2", map_sparse2), ("onlysparse", map_onlysparse), ("notsparse", map_notsparse)],
)
def test_sparsemap(tmpdir, fname, sparse_map):
    def get_sparsemap_fh(fname):
        fh = os.open(fname, flags=os.O_RDONLY)
        try:
            return list(sparsemap(fh=fh))
        finally:
            os.close(fh)

    def get_sparsemap_fd(fname):
        with open(fname, "rb") as fd:
            return list(sparsemap(fd=fd))

    fn = str(tmpdir / fname)
    make_sparsefile(fn, sparse_map)
    assert get_sparsemap_fh(fn) == sparse_map
    assert get_sparsemap_fd(fn) == sparse_map


@pytest.mark.parametrize(
    "file_content, read_size, expected_data, expected_allocation, expected_size",
    [
        # Empty file
        (b"", 1024, b"", CH_DATA, 0),
        # Small data
        (b"data", 1024, b"data", CH_DATA, 4),
        # More data than read_size
        (b"data", 2, b"da", CH_DATA, 2),
    ],
)
def test_filereader_read_simple(file_content, read_size, expected_data, expected_allocation, expected_size):
    """Test read with different file contents."""
    reader = FileReader(fd=BytesIO(file_content), fh=-1, read_size=1024, sparse=False, fmap=None)
    chunk = reader.read(read_size)
    assert chunk.data == expected_data
    assert chunk.meta["allocation"] == expected_allocation
    assert chunk.meta["size"] == expected_size


@pytest.mark.parametrize(
    "file_content, read_sizes, expected_results",
    [
        # Partial data read
        (
            b"data1234",
            [4, 4],
            [{"data": b"data", "allocation": CH_DATA, "size": 4}, {"data": b"1234", "allocation": CH_DATA, "size": 4}],
        ),
        # Multiple calls with EOF
        (
            b"0123456789",
            [4, 4, 4, 4],
            [
                {"data": b"0123", "allocation": CH_DATA, "size": 4},
                {"data": b"4567", "allocation": CH_DATA, "size": 4},
                {"data": b"89", "allocation": CH_DATA, "size": 2},
                {"data": b"", "allocation": CH_DATA, "size": 0},
            ],
        ),
    ],
)
def test_filereader_read_multiple(file_content, read_sizes, expected_results):
    """Test multiple read calls with different file contents."""
    reader = FileReader(fd=BytesIO(file_content), fh=-1, read_size=1024, sparse=False, fmap=None)

    for i, read_size in enumerate(read_sizes):
        chunk = reader.read(read_size)
        assert chunk.data == expected_results[i]["data"]
        assert chunk.meta["allocation"] == expected_results[i]["allocation"]
        assert chunk.meta["size"] == expected_results[i]["size"]


@pytest.mark.parametrize(
    "mock_chunks, read_size, expected_data, expected_allocation, expected_size",
    [
        # Multiple chunks with mixed types
        (
            [
                Chunk(b"chunk1", size=6, allocation=CH_DATA),
                Chunk(None, size=4, allocation=CH_HOLE),
                Chunk(b"chunk2", size=6, allocation=CH_DATA),
            ],
            16,
            b"chunk1" + b"\0" * 4 + b"chunk2",
            CH_DATA,
            16,
        ),
        # Mixed allocation types (hole and alloc)
        ([Chunk(None, size=4, allocation=CH_HOLE), Chunk(None, size=4, allocation=CH_ALLOC)], 8, None, CH_HOLE, 8),
        # All alloc chunks
        ([Chunk(None, size=4, allocation=CH_ALLOC), Chunk(None, size=4, allocation=CH_ALLOC)], 8, None, CH_ALLOC, 8),
        # All hole chunks
        ([Chunk(None, size=4, allocation=CH_HOLE), Chunk(None, size=4, allocation=CH_HOLE)], 8, None, CH_HOLE, 8),
    ],
)
def test_filereader_read_with_mock(mock_chunks, read_size, expected_data, expected_allocation, expected_size):
    """Test read with a mock FileFMAPReader."""

    # Create a mock FileFMAPReader that yields specific chunks
    class MockFileFMAPReader:
        def __init__(self, chunks):
            self.chunks = chunks
            self.index = 0
            # Add required attributes to satisfy FileReader
            self.reading_time = 0.0

        def blockify(self):
            for chunk in self.chunks:
                yield chunk

    # Create a FileReader with a dummy BytesIO to satisfy the assertion
    reader = FileReader(fd=BytesIO(b""), fh=-1, read_size=1024, sparse=False, fmap=None)
    # Replace the reader with our mock
    reader.reader = MockFileFMAPReader(mock_chunks)
    reader.blockify_gen = reader.reader.blockify()

    # Read all chunks at once
    chunk = reader.read(read_size)

    # Check the result
    assert chunk.data == expected_data
    assert chunk.meta["allocation"] == expected_allocation
    assert chunk.meta["size"] == expected_size


@pytest.mark.parametrize(
    "file_content, read_size, expected_chunks",
    [
        # Empty file
        (b"", 1024, []),
        # Small data
        (b"data", 1024, [{"data": b"data", "allocation": CH_DATA, "size": 4}]),
        # Data larger than read_size
        (
            b"0123456789",
            4,
            [
                {"data": b"0123", "allocation": CH_DATA, "size": 4},
                {"data": b"4567", "allocation": CH_DATA, "size": 4},
                {"data": b"89", "allocation": CH_DATA, "size": 2},
            ],
        ),
        # Data with zeros (should be detected as allocated zeros)
        (
            b"data" + b"\0" * 8 + b"more",
            4,
            [
                {"data": b"data", "allocation": CH_DATA, "size": 4},
                {"data": None, "allocation": CH_ALLOC, "size": 4},
                {"data": None, "allocation": CH_ALLOC, "size": 4},
                {"data": b"more", "allocation": CH_DATA, "size": 4},
            ],
        ),
    ],
)
def test_filefmapreader_basic(file_content, read_size, expected_chunks):
    """Test basic functionality of FileFMAPReader with different file contents."""
    reader = FileFMAPReader(fd=BytesIO(file_content), fh=-1, read_size=read_size, sparse=False, fmap=None)

    # Collect all chunks from blockify
    chunks = list(reader.blockify())

    # Check the number of chunks
    assert len(chunks) == len(expected_chunks)

    # Check each chunk
    for i, chunk in enumerate(chunks):
        assert chunk.data == expected_chunks[i]["data"]
        assert chunk.meta["allocation"] == expected_chunks[i]["allocation"]
        assert chunk.meta["size"] == expected_chunks[i]["size"]


@pytest.mark.parametrize(
    "file_content, fmap, read_size, expected_chunks",
    [
        # Custom fmap with data and holes
        (
            b"dataXXXXmore",
            [(0, 4, True), (4, 4, False), (8, 4, True)],
            4,
            [
                {"data": b"data", "allocation": CH_DATA, "size": 4},
                {"data": None, "allocation": CH_HOLE, "size": 4},
                {"data": b"more", "allocation": CH_DATA, "size": 4},
            ],
        ),
        # Custom fmap with only holes
        (
            b"\0\0\0\0\0\0\0\0",
            [(0, 8, False)],
            4,
            [{"data": None, "allocation": CH_HOLE, "size": 4}, {"data": None, "allocation": CH_HOLE, "size": 4}],
        ),
        # Custom fmap with only data
        (
            b"datadata",
            [(0, 8, True)],
            4,
            [{"data": b"data", "allocation": CH_DATA, "size": 4}, {"data": b"data", "allocation": CH_DATA, "size": 4}],
        ),
        # Custom fmap with partial coverage (should seek to the right position)
        (
            b"skipthispartreadthispart",
            [(12, 12, True)],
            4,
            [
                {"data": b"read", "allocation": CH_DATA, "size": 4},
                {"data": b"this", "allocation": CH_DATA, "size": 4},
                {"data": b"part", "allocation": CH_DATA, "size": 4},
            ],
        ),
    ],
)
def test_filefmapreader_with_fmap(file_content, fmap, read_size, expected_chunks):
    """Test FileFMAPReader with an externally provided file map."""
    reader = FileFMAPReader(fd=BytesIO(file_content), fh=-1, read_size=read_size, sparse=False, fmap=fmap)

    # Collect all chunks from blockify
    chunks = list(reader.blockify())

    # Check the number of chunks
    assert len(chunks) == len(expected_chunks)

    # Check each chunk
    for i, chunk in enumerate(chunks):
        assert chunk.data == expected_chunks[i]["data"]
        assert chunk.meta["allocation"] == expected_chunks[i]["allocation"]
        assert chunk.meta["size"] == expected_chunks[i]["size"]


@pytest.mark.parametrize(
    "zeros_length, read_size, expected_allocation",
    [(4, 4, CH_ALLOC), (8192, 4096, CH_ALLOC)],  # Small block of zeros  # Large block of zeros
)
def test_filefmapreader_allocation_types(zeros_length, read_size, expected_allocation):
    """Test FileFMAPReader's handling of different allocation types."""
    # Create a file with all zeros
    file_content = b"\0" * zeros_length

    reader = FileFMAPReader(fd=BytesIO(file_content), fh=-1, read_size=read_size, sparse=False, fmap=None)

    # Collect all chunks from blockify
    chunks = list(reader.blockify())

    # Check that all chunks are of the expected allocation type
    for chunk in chunks:
        assert chunk.meta["allocation"] == expected_allocation
        assert chunk.data is None  # All-zero data should be None


@pytest.mark.skipif(not fs_supports_sparse(), reason="fs does not support sparse files")
def test_filefmapreader_with_real_sparse_file(tmpdir):
    """Test FileFMAPReader with a real sparse file."""
    # Create a sparse file
    fn = str(tmpdir / "sparse_file")
    sparse_map = [(0, BS, True), (BS, 2 * BS, False), (3 * BS, BS, True)]
    make_sparsefile(fn, sparse_map)

    # Expected chunks when reading with sparse=True
    expected_chunks_sparse = [
        {"data_type": bytes, "allocation": CH_DATA, "size": BS},
        {"data_type": type(None), "allocation": CH_HOLE, "size": BS},
        {"data_type": type(None), "allocation": CH_HOLE, "size": BS},
        {"data_type": bytes, "allocation": CH_DATA, "size": BS},
    ]

    # Expected chunks when reading with sparse=False.
    # Even though it is not differentiating data vs hole ranges, it still
    # transforms detected all-zero blocks to CH_ALLOC chunks.
    expected_chunks_non_sparse = [
        {"data_type": bytes, "allocation": CH_DATA, "size": BS},
        {"data_type": type(None), "allocation": CH_ALLOC, "size": BS},
        {"data_type": type(None), "allocation": CH_ALLOC, "size": BS},
        {"data_type": bytes, "allocation": CH_DATA, "size": BS},
    ]

    # Test with sparse=True
    with open(fn, "rb") as fd:
        reader = FileFMAPReader(fd=fd, fh=-1, read_size=BS, sparse=True, fmap=None)
        chunks = list(reader.blockify())

        assert len(chunks) == len(expected_chunks_sparse)
        for i, chunk in enumerate(chunks):
            assert isinstance(chunk.data, expected_chunks_sparse[i]["data_type"])
            assert chunk.meta["allocation"] == expected_chunks_sparse[i]["allocation"]
            assert chunk.meta["size"] == expected_chunks_sparse[i]["size"]

    # Test with sparse=False
    with open(fn, "rb") as fd:
        reader = FileFMAPReader(fd=fd, fh=-1, read_size=BS, sparse=False, fmap=None)
        chunks = list(reader.blockify())

        assert len(chunks) == len(expected_chunks_non_sparse)
        for i, chunk in enumerate(chunks):
            assert isinstance(chunk.data, expected_chunks_non_sparse[i]["data_type"])
            assert chunk.meta["allocation"] == expected_chunks_non_sparse[i]["allocation"]
            assert chunk.meta["size"] == expected_chunks_non_sparse[i]["size"]


def test_filefmapreader_build_fmap():
    """Test FileFMAPReader's _build_fmap method."""
    # Create a reader with sparse=False
    reader = FileFMAPReader(fd=BytesIO(b"data"), fh=-1, read_size=4, sparse=False, fmap=None)

    # Call _build_fmap
    fmap = reader._build_fmap()

    # Check that a default fmap is created
    assert len(fmap) == 1
    assert fmap[0][0] == 0  # start
    assert fmap[0][1] == 2**62  # size
    assert fmap[0][2] is True  # is_data

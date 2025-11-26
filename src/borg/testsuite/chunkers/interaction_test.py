import os
import pytest
from io import BytesIO

from ...chunkers import get_chunker
from ...constants import *  # NOQA


@pytest.mark.parametrize(
    "chunker_params",
    [
        (CH_FIXED, 1048576, 0),  # == reader_block_size
        (CH_FIXED, 1048576 // 2, 0),  # reader_block_size / N
        (CH_FIXED, 1048576 * 2, 0),  # N * reader_block_size
        (CH_FIXED, 1234567, 0),  # does not fit well, larger than reader_block_size
        (CH_FIXED, 123456, 0),  # does not fit well, smaller than reader_block_size
        (CH_BUZHASH, CHUNK_MIN_EXP, CHUNK_MAX_EXP, HASH_MASK_BITS, HASH_WINDOW_SIZE),
        (CH_BUZHASH64, CHUNK_MIN_EXP, CHUNK_MAX_EXP, HASH_MASK_BITS, HASH_WINDOW_SIZE),
    ],
)
def test_reader_chunker_interaction(chunker_params):
    """
    Test that chunking random/zero data produces chunks that can be reassembled to match the original data.

    If one of these fails, there is likely a problem with buffer management.
    """
    # Generate some data
    data_size = 6 * 12341234
    random_data = os.urandom(data_size // 3) + b"\0" * (data_size // 3) + os.urandom(data_size // 3)

    # Chunk the data
    chunker = get_chunker(*chunker_params)
    data_file = BytesIO(random_data)
    chunks = list(chunker.chunkify(data_file))

    data_chunks = 0
    hole_chunks = 0
    alloc_chunks = 0
    for chunk in chunks:
        if chunk.meta["allocation"] == CH_DATA:
            data_chunks += 1
        elif chunk.meta["allocation"] == CH_HOLE:
            hole_chunks += 1
        elif chunk.meta["allocation"] == CH_ALLOC:
            alloc_chunks += 1

    assert data_chunks > 0, "No data chunks found"
    assert alloc_chunks > 0, "No alloc chunks found"
    assert hole_chunks == 0, "Hole chunks found, this is not expected!"

    # Reassemble the chunks
    reassembled = BytesIO()
    for i, chunk in enumerate(chunks):
        if chunk.meta["allocation"] == CH_DATA:
            # For data chunks, write the actual data
            reassembled.write(bytes(chunk.data))
        elif chunk.meta["allocation"] in (CH_HOLE, CH_ALLOC):
            # For hole or alloc chunks, write zeros
            reassembled.write(b"\0" * chunk.meta["size"])

    # Check that the reassembled data has the correct size
    reassembled_size = reassembled.tell()
    assert (
        reassembled_size == data_size
    ), f"Reassembled data size ({reassembled_size}) does not equal original data size ({data_size})"

    # Verify that the reassembled data matches the original data
    reassembled.seek(0)
    reassembled_data = reassembled.read()
    assert reassembled_data == random_data, "Reassembled data does not match original data"

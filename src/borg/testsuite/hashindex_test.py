import hashlib
import struct

import pytest

from ..hashindex import ChunkIndex


def H(x):
    # make some 32byte long thing that depends on x
    return bytes("%-0.32d" % x, "ascii")


def H2(x):
    # like H(x), but with pseudo-random distribution of the output value
    return hashlib.sha256(H(x)).digest()


def test_chunkindex_add():
    chunks = ChunkIndex()
    x = H2(1)
    chunks.add(x, 5, 6)
    assert chunks[x] == (5, 6)
    chunks.add(x, 1, 2)
    assert chunks[x] == (6, 2)


def test_keyerror():
    chunks = ChunkIndex()
    x = H2(1)
    with pytest.raises(KeyError):
        chunks[x]
    with pytest.raises(struct.error):
        chunks.add(x, -1, 0)

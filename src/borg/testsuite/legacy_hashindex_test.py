"""Tests for borg.legacy.hashindex (NSIndex1)."""

import io
import struct

import pytest

from ..legacy.hashindex import NSIndex1


def written_index():
    idx = NSIndex1()
    idx[b"x" * 32] = (1, 2)
    fd = io.BytesIO()
    idx.write(fd)
    return bytearray(fd.getvalue())


def test_nsindex1_roundtrip():
    idx = NSIndex1.read(io.BytesIO(bytes(written_index())))
    assert idx[b"x" * 32] == (1, 2)


@pytest.mark.parametrize(
    "corrupt",
    [
        lambda data: data.__setitem__(slice(16, 17), b"\x10"),  # ksize
        lambda data: data.__setitem__(slice(17, 18), b"\x04"),  # vsize
    ],
    ids=["ksize", "vsize"],
)
def test_nsindex1_invalid_header(corrupt):
    data = written_index()
    assert struct.calcsize(NSIndex1.HEADER_FMT) == 18
    corrupt(data)
    with pytest.raises(ValueError, match="Invalid file"):
        NSIndex1.read(io.BytesIO(bytes(data)))

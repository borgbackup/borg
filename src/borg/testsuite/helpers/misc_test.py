from io import StringIO, BytesIO

import pytest

from ...helpers.misc import ChunkIteratorFileWrapper, chunkit, iter_separated


def test_chunk_file_wrapper():
    cfw = ChunkIteratorFileWrapper(iter([b"abc", b"def"]))
    assert cfw.read(2) == b"ab"
    assert cfw.read(50) == b"cdef"
    assert cfw.exhausted

    cfw = ChunkIteratorFileWrapper(iter([]))
    assert cfw.read(2) == b""
    assert cfw.exhausted


def test_chunkit():
    it = chunkit("abcdefg", 3)
    assert next(it) == ["a", "b", "c"]
    assert next(it) == ["d", "e", "f"]
    assert next(it) == ["g"]
    with pytest.raises(StopIteration):
        next(it)
    with pytest.raises(StopIteration):
        next(it)

    it = chunkit("ab", 3)
    assert list(it) == [["a", "b"]]

    it = chunkit("", 3)
    assert list(it) == []


def test_iter_separated():
    # newline and utf-8
    sep, items = "\n", ["foo", "bar/baz", "αáčő"]
    fd = StringIO(sep.join(items))
    assert list(iter_separated(fd)) == items
    # null and bogus ending
    sep, items = "\0", ["foo/bar", "baz", "spam"]
    fd = StringIO(sep.join(items) + "\0")
    assert list(iter_separated(fd, sep=sep)) == ["foo/bar", "baz", "spam"]
    # multichar
    sep, items = "SEP", ["foo/bar", "baz", "spam"]
    fd = StringIO(sep.join(items))
    assert list(iter_separated(fd, sep=sep)) == items
    # bytes
    sep, items = b"\n", [b"foo", b"blop\t", b"gr\xe4ezi"]
    fd = BytesIO(sep.join(items))
    assert list(iter_separated(fd)) == items

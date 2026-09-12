import pytest

from ..cache import ChunkListEntry
from ..item import MAX_ALIGN_CHUNKS, MAX_ALIGN_WORK, Item, ItemDiff, chunks_contents_equal, chunks_diff_size
from ..helpers import StableDict
from ..helpers.msgpack import Timestamp
from ..platformflags import is_pypy


def test_item_empty():
    item = Item()

    assert item.as_dict() == {}

    assert "path" not in item
    with pytest.raises(ValueError):
        "invalid-key" in item
    with pytest.raises(TypeError):
        b"path" in item
    with pytest.raises(TypeError):
        42 in item

    assert item.get("mode") is None
    assert item.get("mode", 0o666) == 0o666
    with pytest.raises(ValueError):
        item.get("invalid-key")
    with pytest.raises(TypeError):
        item.get(b"mode")
    with pytest.raises(TypeError):
        item.get(42)

    with pytest.raises(AttributeError):
        item.path

    with pytest.raises(AttributeError):
        del item.path


@pytest.mark.parametrize(
    "item_dict, path, mode",
    [  # It does not matter whether we get str or bytes keys
        ({b"path": "a/b/c", b"mode": 0o666}, "a/b/c", 0o666),
        ({"path": "a/b/c", "mode": 0o666}, "a/b/c", 0o666),
    ],
)
def test_item_from_dict(item_dict, path, mode):
    item = Item(item_dict)
    assert item.path == path
    assert item.mode == mode
    assert "path" in item
    assert "mode" in item


@pytest.mark.parametrize(
    "invalid_item, error",
    [
        (42, TypeError),  # invalid - no dict
        ({42: 23}, TypeError),  # invalid - no bytes/str key
        ({"foobar": "baz"}, ValueError),  # invalid - unknown key
    ],
)
def test_item_invalid(invalid_item, error):
    with pytest.raises(error):
        Item(invalid_item)


def test_item_from_kw():
    item = Item(path="a/b/c", mode=0o666)
    assert item.path == "a/b/c"
    assert item.mode == 0o666


def test_item_int_property():
    item = Item()
    item.mode = 0o666
    assert item.mode == 0o666
    assert item.as_dict() == {"mode": 0o666}
    del item.mode
    assert item.as_dict() == {}
    with pytest.raises(TypeError):
        item.mode = "invalid"


@pytest.mark.parametrize("atime", [42, 2**65])
def test_item_mptimestamp_property(atime):
    item = Item()
    item.atime = atime
    assert item.atime == atime
    assert item.as_dict() == {"atime": Timestamp.from_unix_nano(atime)}


def test_item_se_str_property():
    # Start simple
    item = Item()
    item.path = "a/b/c"
    assert item.path == "a/b/c"
    assert item.as_dict() == {"path": "a/b/c"}
    del item.path
    assert item.as_dict() == {}
    with pytest.raises(TypeError):
        item.path = 42

    # Non-UTF-8 path, requiring surrogate escaping for a Latin-1 u-umlaut
    item = Item(internal_dict={"path": b"a/\xfc/c"})
    assert item.path == "a/\udcfc/c"  # getting a surrogate-escaped representation
    assert item.as_dict() == {"path": "a/\udcfc/c"}
    del item.path
    assert "path" not in item
    item.path = "a/\udcfc/c"  # setting using a surrogate-escaped representation
    assert item.as_dict() == {"path": "a/\udcfc/c"}


def test_item_list_property():
    item = Item()
    item.chunks = []
    assert item.chunks == []
    item.chunks.append(0)
    assert item.chunks == [0]
    item.chunks.append(1)
    assert item.chunks == [0, 1]
    assert item.as_dict() == {"chunks": [0, 1]}


def test_item_dict_property():
    item = Item()
    item.xattrs = StableDict()
    assert item.xattrs == StableDict()
    item.xattrs["foo"] = "bar"
    assert item.xattrs["foo"] == "bar"
    item.xattrs["bar"] = "baz"
    assert item.xattrs == StableDict({"foo": "bar", "bar": "baz"})
    assert item.as_dict() == {"xattrs": {"foo": "bar", "bar": "baz"}}


@pytest.mark.xfail(is_pypy, reason="setting undeclared attributes on cdef class instances is not blocked on pypy")
def test_unknown_property():
    # We do not want the user to be able to set unknown attributes —
    # they will not appear in the .as_dict() result dictionary.
    # Also, they might just be typos of known attributes.
    item = Item()
    with pytest.raises(AttributeError):
        item.unknown_attribute = None


def test_item_file_size():
    item = Item(mode=0o100666, chunks=[ChunkListEntry(size=1000, id=None), ChunkListEntry(size=2000, id=None)])
    assert item.get_size() == 3000
    item.get_size(memorize=True)
    assert item.size == 3000


def test_item_file_size_no_chunks():
    item = Item(mode=0o100666)
    assert item.get_size() == 0


@pytest.mark.parametrize(
    "chunk_a, chunk_b, chunks_equal",
    [
        (["1234", "567A", "bC"], ["1", "23", "4567A", "b", "C"], True),  # equal
        (["12345"], ["1234", "56"], False),  # one iterator exhausted before the other
        (["1234", "65"], ["1234", "56"], False),  # content mismatch
        (["1234", "56"], ["1234", "565"], False),  # the first is a prefix of the second
    ],
)
def test_chunk_content_equal(chunk_a: str, chunk_b: str, chunks_equal):
    chunks_a = [data.encode() for data in chunk_a]
    chunks_b = [data.encode() for data in chunk_b]
    compare1 = chunks_contents_equal(iter(chunks_a), iter(chunks_b))
    compare2 = chunks_contents_equal(iter(chunks_b), iter(chunks_a))
    assert compare1 == compare2
    assert compare1 == chunks_equal


@pytest.mark.parametrize(
    "ctime1_ns, ctime2_ns, change_expected",
    [
        (1000000000_000000_000, 1000000000_000000_000, False),  # identical
        (1000000000_000000_000, 1000000000_000000_001, True),  # nanosecond difference
        (1000000000_000000_000, 1000000000_000001_000, True),  # microsecond difference
        (1000000000_000000_000, 1000000001_000000_000, True),  # second difference
    ],
)
def test_item_diff_time_ns_resolution(ctime1_ns, ctime2_ns, change_expected):
    """ItemDiff compares timestamps with full nanosecond resolution."""
    item1 = Item(path="p", mode=0o100644, mtime=0, ctime=ctime1_ns)
    item2 = Item(path="p", mode=0o100644, mtime=0, ctime=ctime2_ns)
    diff = ItemDiff("p", item1, item2, iter([]), iter([]), can_compare_chunk_ids=True)
    assert (diff.ctime() is not None) == change_expected
    assert diff.mtime() is None


# chunk ids for the chunks_diff_size tests, all chunks are 10 bytes long.
CA, CB, CC, CD = (ChunkListEntry(bytes([n]) * 32, 10) for n in range(4))


@pytest.mark.parametrize(
    "chunks1, chunks2, expected",
    [
        ([], [], (0, 0)),
        ([CA, CB], [CA, CB], (0, 0)),  # identical
        ([CA, CB], [CA, CB, CC], (10, 0)),  # appended
        ([CA, CB, CC], [CA, CB], (0, 10)),  # truncated
        ([CA, CB], [CC, CA, CB], (10, 0)),  # prepended
        ([CA, CB], [CA, CC, CB], (10, 0)),  # inserted in the middle
        ([CA, CB, CC], [CA, CD, CC], (10, 10)),  # replaced in the middle
        ([CA, CB], [CB, CA], (10, 10)),  # swapped: one of the two chunks aligns, the other one moved
        ([CA, CB, CC], [CC, CB, CA], (20, 20)),  # reversed: only one chunk aligns
        ([CA], [CA, CA, CA], (20, 0)),  # duplicated: no new chunk id, but the content grew
        ([CA, CA, CA], [CA], (0, 20)),  # de-duplicated
        ([CA, CB], [CC, CD], (20, 20)),  # nothing in common
    ],
)
def test_chunks_diff_size(chunks1, chunks2, expected):
    assert chunks_diff_size(chunks1, chunks2) == expected


def test_chunks_diff_size_over_length_limit():
    """Above MAX_ALIGN_CHUNKS the chunk lists are not aligned, the chunk ids are only counted."""
    chunks1 = [ChunkListEntry((n + 1).to_bytes(32, "big"), 10) for n in range(MAX_ALIGN_CHUNKS + 1)]
    # the first and the last chunk differ, so neither a common prefix nor a common suffix is stripped.
    chunks2 = [CA] + chunks1[1:-1] + [CB]
    assert chunks_diff_size(chunks1, chunks2) == (20, 20)
    # a pure reordering is not detected on this code path, thus no bytes are reported.
    assert chunks_diff_size(chunks1, chunks1[::-1]) == (0, 0)


def test_chunks_diff_size_over_work_limit():
    """Chunk lists that repeat the same chunk id too often are not aligned either."""
    n = int(MAX_ALIGN_WORK**0.5) + 1  # n * n occurrences of the same id exceed the work limit
    chunks1 = [CA] * n + [CB]
    chunks2 = [CB] + [CA] * n
    # the same multiset of chunks, only reordered: not detected without aligning the lists.
    assert chunks_diff_size(chunks1, chunks2) == (0, 0)
    # a chunk that really was added is still counted correctly.
    assert chunks_diff_size(chunks1, chunks2 + [CC]) == (10, 0)

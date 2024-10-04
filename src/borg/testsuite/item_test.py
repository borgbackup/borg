import pytest

from ..cache import ChunkListEntry
from ..item import Item, chunks_contents_equal
from ..helpers import StableDict
from ..helpers.msgpack import Timestamp


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
    [  # does not matter whether we get str or bytes keys
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
    # start simple
    item = Item()
    item.path = "a/b/c"
    assert item.path == "a/b/c"
    assert item.as_dict() == {"path": "a/b/c"}
    del item.path
    assert item.as_dict() == {}
    with pytest.raises(TypeError):
        item.path = 42

    # non-utf-8 path, needing surrogate-escaping for latin-1 u-umlaut
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


def test_unknown_property():
    # we do not want the user to be able to set unknown attributes -
    # they won't get into the .as_dict() result dictionary.
    # also they might be just typos of known attributes.
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


def test_item_optr():
    item = Item()
    assert Item.from_optr(item.to_optr()) is item


@pytest.mark.parametrize(
    "chunk_a, chunk_b, chunks_equal",
    [
        (["1234", "567A", "bC"], ["1", "23", "4567A", "b", "C"], True),  # equal
        (["12345"], ["1234", "56"], False),  # one iterator exhausted before the other
        (["1234", "65"], ["1234", "56"], False),  # content mismatch
        (["1234", "56"], ["1234", "565"], False),  # first is the prefix of second
    ],
)
def test_chunk_content_equal(chunk_a: str, chunk_b: str, chunks_equal):
    chunks_a = [data.encode() for data in chunk_a]
    chunks_b = [data.encode() for data in chunk_b]
    compare1 = chunks_contents_equal(iter(chunks_a), iter(chunks_b))
    compare2 = chunks_contents_equal(iter(chunks_b), iter(chunks_a))
    assert compare1 == compare2
    assert compare1 == chunks_equal

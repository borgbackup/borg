import json
from collections import OrderedDict
from datetime import datetime, timezone
from io import StringIO
from unittest.mock import Mock

import pytest

from . import BaseTestCase
from ..crypto.key import PlaintextKey
from ..archive import Archive, CacheChunkBuffer, RobustUnpacker, valid_msgpacked_dict, ITEM_KEYS, Statistics
from ..archive import BackupOSError, backup_io, backup_io_iter, get_item_uid_gid
from ..helpers import Manifest
from ..helpers import msgpack
from ..item import Item, ArchiveItem
from ..platform import uid2user, gid2group


@pytest.fixture()
def stats():
    stats = Statistics()
    stats.update(20, unique=True)
    stats.nfiles = 1
    return stats


def test_stats_basic(stats):
    assert stats.osize == 20
    assert stats.usize == 20
    stats.update(20, unique=False)
    assert stats.osize == 40
    assert stats.usize == 20


def tests_stats_progress(stats, monkeypatch, columns=80):
    monkeypatch.setenv("COLUMNS", str(columns))
    out = StringIO()
    stats.show_progress(stream=out)
    s = "20 B O 20 B U 1 N "
    buf = " " * (columns - len(s))
    assert out.getvalue() == s + buf + "\r"

    out = StringIO()
    stats.update(10**3, unique=False)
    stats.show_progress(item=Item(path="foo"), final=False, stream=out)
    s = "1.02 kB O 20 B U 1 N foo"
    buf = " " * (columns - len(s))
    assert out.getvalue() == s + buf + "\r"
    out = StringIO()
    stats.show_progress(item=Item(path="foo" * 40), final=False, stream=out)
    s = "1.02 kB O 20 B U 1 N foofoofoofoofoofoofoofoofo...foofoofoofoofoofoofoofoofoofoo"
    buf = " " * (columns - len(s))
    assert out.getvalue() == s + buf + "\r"


def test_stats_format(stats):
    assert (
        str(stats)
        == """\
Number of files: 1
Original size: 20 B
Deduplicated size: 20 B
"""
    )
    s = f"{stats.osize_fmt}"
    assert s == "20 B"
    # kind of redundant, but id is variable so we can't match reliably
    assert repr(stats) == f"<Statistics object at {id(stats):#x} (20, 20)>"


def test_stats_progress_json(stats):
    stats.output_json = True

    out = StringIO()
    stats.show_progress(item=Item(path="foo"), stream=out)
    result = json.loads(out.getvalue())
    assert result["type"] == "archive_progress"
    assert isinstance(result["time"], float)
    assert result["finished"] is False
    assert result["path"] == "foo"
    assert result["original_size"] == 20
    assert result["nfiles"] == 1

    out = StringIO()
    stats.show_progress(stream=out, final=True)
    result = json.loads(out.getvalue())
    assert result["type"] == "archive_progress"
    assert isinstance(result["time"], float)
    assert result["finished"] is True  # see #6570
    assert "path" not in result
    assert "original_size" not in result
    assert "nfiles" not in result


class MockCache:
    class MockRepo:
        def async_response(self, wait=True):
            pass

    def __init__(self):
        self.objects = {}
        self.repository = self.MockRepo()

    def add_chunk(self, id, chunk, stats=None, wait=True):
        self.objects[id] = chunk
        return id, len(chunk)


class ArchiveTimestampTestCase(BaseTestCase):
    def _test_timestamp_parsing(self, isoformat, expected):
        repository = Mock()
        key = PlaintextKey(repository)
        manifest = Manifest(repository, key)
        a = Archive(repository, key, manifest, "test", create=True)
        a.metadata = ArchiveItem(time=isoformat)
        self.assert_equal(a.ts, expected)

    def test_with_microseconds(self):
        self._test_timestamp_parsing("1970-01-01T00:00:01.000001", datetime(1970, 1, 1, 0, 0, 1, 1, timezone.utc))

    def test_without_microseconds(self):
        self._test_timestamp_parsing("1970-01-01T00:00:01", datetime(1970, 1, 1, 0, 0, 1, 0, timezone.utc))


class ChunkBufferTestCase(BaseTestCase):
    def test(self):
        data = [Item(path="p1"), Item(path="p2")]
        cache = MockCache()
        key = PlaintextKey(None)
        chunks = CacheChunkBuffer(cache, key, None)
        for d in data:
            chunks.add(d)
            chunks.flush()
        chunks.flush(flush=True)
        self.assert_equal(len(chunks.chunks), 2)
        unpacker = msgpack.Unpacker()
        for id in chunks.chunks:
            unpacker.feed(cache.objects[id])
        self.assert_equal(data, [Item(internal_dict=d) for d in unpacker])

    def test_partial(self):
        big = "0123456789abcdefghijklmnopqrstuvwxyz" * 25000
        data = [Item(path="full", source=big), Item(path="partial", source=big)]
        cache = MockCache()
        key = PlaintextKey(None)
        chunks = CacheChunkBuffer(cache, key, None)
        for d in data:
            chunks.add(d)
        chunks.flush(flush=False)
        # the code is expected to leave the last partial chunk in the buffer
        self.assert_equal(len(chunks.chunks), 3)
        assert chunks.buffer.tell() > 0
        # now really flush
        chunks.flush(flush=True)
        self.assert_equal(len(chunks.chunks), 4)
        assert chunks.buffer.tell() == 0
        unpacker = msgpack.Unpacker()
        for id in chunks.chunks:
            unpacker.feed(cache.objects[id])
        self.assert_equal(data, [Item(internal_dict=d) for d in unpacker])


class RobustUnpackerTestCase(BaseTestCase):
    def make_chunks(self, items):
        return b"".join(msgpack.packb({"path": item}) for item in items)

    def _validator(self, value):
        return isinstance(value, dict) and value.get("path") in ("foo", "bar", "boo", "baz")

    def process(self, input):
        unpacker = RobustUnpacker(validator=self._validator, item_keys=ITEM_KEYS)
        result = []
        for should_sync, chunks in input:
            if should_sync:
                unpacker.resync()
            for data in chunks:
                unpacker.feed(data)
                for item in unpacker:
                    result.append(item)
        return result

    def test_extra_garbage_no_sync(self):
        chunks = [
            (False, [self.make_chunks(["foo", "bar"])]),
            (False, [b"garbage"] + [self.make_chunks(["boo", "baz"])]),
        ]
        result = self.process(chunks)
        self.assert_equal(
            result, [{"path": "foo"}, {"path": "bar"}, 103, 97, 114, 98, 97, 103, 101, {"path": "boo"}, {"path": "baz"}]
        )

    def split(self, left, length):
        parts = []
        while left:
            parts.append(left[:length])
            left = left[length:]
        return parts

    def test_correct_stream(self):
        chunks = self.split(self.make_chunks(["foo", "bar", "boo", "baz"]), 2)
        input = [(False, chunks)]
        result = self.process(input)
        self.assert_equal(result, [{"path": "foo"}, {"path": "bar"}, {"path": "boo"}, {"path": "baz"}])

    def test_missing_chunk(self):
        chunks = self.split(self.make_chunks(["foo", "bar", "boo", "baz"]), 4)
        input = [(False, chunks[:3]), (True, chunks[4:])]
        result = self.process(input)
        self.assert_equal(result, [{"path": "foo"}, {"path": "boo"}, {"path": "baz"}])

    def test_corrupt_chunk(self):
        chunks = self.split(self.make_chunks(["foo", "bar", "boo", "baz"]), 4)
        input = [(False, chunks[:3]), (True, [b"gar", b"bage"] + chunks[3:])]
        result = self.process(input)
        self.assert_equal(result, [{"path": "foo"}, {"path": "boo"}, {"path": "baz"}])


@pytest.fixture
def item_keys_serialized():
    return [msgpack.packb(name) for name in ITEM_KEYS]


@pytest.mark.parametrize(
    "packed",
    [b"", b"x", b"foobar"]
    + [
        msgpack.packb(o)
        for o in (
            [None, 0, 0.0, False, "", {}, [], ()]
            + [42, 23.42, True, b"foobar", {b"foo": b"bar"}, [b"foo", b"bar"], (b"foo", b"bar")]
        )
    ],
)
def test_invalid_msgpacked_item(packed, item_keys_serialized):
    assert not valid_msgpacked_dict(packed, item_keys_serialized)


# pytest-xdist requires always same order for the keys and dicts:
IK = sorted(list(ITEM_KEYS))


@pytest.mark.parametrize(
    "packed",
    [
        msgpack.packb(o)
        for o in [
            {"path": b"/a/b/c"},  # small (different msgpack mapping type!)
            OrderedDict((k, b"") for k in IK),  # as big (key count) as it gets
            OrderedDict((k, b"x" * 1000) for k in IK),  # as big (key count and volume) as it gets
        ]
    ],
)
def test_valid_msgpacked_items(packed, item_keys_serialized):
    assert valid_msgpacked_dict(packed, item_keys_serialized)


def test_key_length_msgpacked_items():
    key = "x" * 32  # 31 bytes is the limit for fixstr msgpack type
    data = {key: b""}
    item_keys_serialized = [msgpack.packb(key)]
    assert valid_msgpacked_dict(msgpack.packb(data), item_keys_serialized)


def test_backup_io():
    with pytest.raises(BackupOSError):
        with backup_io:
            raise OSError(123)


def test_backup_io_iter():
    class Iterator:
        def __init__(self, exc):
            self.exc = exc

        def __next__(self):
            raise self.exc()

    oserror_iterator = Iterator(OSError)
    with pytest.raises(BackupOSError):
        for _ in backup_io_iter(oserror_iterator):
            pass

    normal_iterator = Iterator(StopIteration)
    for _ in backup_io_iter(normal_iterator):
        assert False, "StopIteration handled incorrectly"


def test_get_item_uid_gid():
    # test requires that:
    # - a name for user 0 and group 0 exists, usually root:root or root:wheel.
    # - a system user/group udoesnotexist:gdoesnotexist does NOT exist.

    user0, group0 = uid2user(0), gid2group(0)

    # this is intentionally a "strange" item, with not matching ids/names.
    item = Item(path="filename", uid=1, gid=2, user=user0, group=group0)

    uid, gid = get_item_uid_gid(item, numeric=False)
    # these are found via a name-to-id lookup
    assert uid == 0
    assert gid == 0

    uid, gid = get_item_uid_gid(item, numeric=True)
    # these are directly taken from the item.uid and .gid
    assert uid == 1
    assert gid == 2

    uid, gid = get_item_uid_gid(item, numeric=False, uid_forced=3, gid_forced=4)
    # these are enforced (not from item metadata)
    assert uid == 3
    assert gid == 4

    # item metadata broken, has negative ids.
    item = Item(path="filename", uid=-1, gid=-2, user=user0, group=group0)

    uid, gid = get_item_uid_gid(item, numeric=True)
    # use the uid/gid defaults (which both default to 0).
    assert uid == 0
    assert gid == 0

    uid, gid = get_item_uid_gid(item, numeric=True, uid_default=5, gid_default=6)
    # use the uid/gid defaults (as given).
    assert uid == 5
    assert gid == 6

    # item metadata broken, has negative ids and non-existing user/group names.
    item = Item(path="filename", uid=-3, gid=-4, user="udoesnotexist", group="gdoesnotexist")

    uid, gid = get_item_uid_gid(item, numeric=False)
    # use the uid/gid defaults (which both default to 0).
    assert uid == 0
    assert gid == 0

    uid, gid = get_item_uid_gid(item, numeric=True, uid_default=7, gid_default=8)
    # use the uid/gid defaults (as given).
    assert uid == 7
    assert gid == 8

    # item metadata has valid uid/gid, but non-existing user/group names.
    item = Item(path="filename", uid=9, gid=10, user="udoesnotexist", group="gdoesnotexist")

    uid, gid = get_item_uid_gid(item, numeric=False)
    # because user/group name does not exist here, use valid numeric ids from item metadata.
    assert uid == 9
    assert gid == 10

    uid, gid = get_item_uid_gid(item, numeric=False, uid_default=11, gid_default=12)
    # because item uid/gid seems valid, do not use the given uid/gid defaults
    assert uid == 9
    assert gid == 10

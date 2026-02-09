import json
import os
from collections import OrderedDict
from datetime import datetime, timezone
from io import StringIO
from unittest.mock import Mock

import pytest

from . import rejected_dotdot_paths
from ..crypto.key import PlaintextKey
from ..archive import Archive, CacheChunkBuffer, RobustUnpacker, valid_msgpacked_dict, ITEM_KEYS, Statistics
from ..archive import BackupOSError, backup_io, backup_io_iter, get_item_uid_gid
from ..helpers import msgpack
from ..item import Item, ArchiveItem, ChunkListEntry
from ..manifest import Manifest
from ..platform import uid2user, gid2group, is_win32


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


def test_stats_progress_tty(stats, monkeypatch, columns=80):
    class TTYStringIO(StringIO):
        def isatty(self):
            return True

    monkeypatch.setenv("COLUMNS", str(columns))
    out = TTYStringIO()
    stats.show_progress(stream=out)
    s = "20 B O 20 B U 1 N "
    buf = " " * (columns - len(s))
    assert out.getvalue() == s + buf + "\r"

    out = TTYStringIO()
    stats.update(10**3, unique=False)
    stats.show_progress(item=Item(path="foo"), final=False, stream=out)
    s = "1.02 kB O 20 B U 1 N foo"
    buf = " " * (columns - len(s))
    assert out.getvalue() == s + buf + "\r"

    out = TTYStringIO()
    stats.show_progress(item=Item(path="foo" * 40), final=False, stream=out)
    s = "1.02 kB O 20 B U 1 N foofoofoofoofoofoofoofoofo...foofoofoofoofoofoofoofoofoofoo"
    buf = " " * (columns - len(s))
    assert out.getvalue() == s + buf + "\r"


def test_stats_progress_file(stats, monkeypatch):
    out = StringIO()
    stats.show_progress(stream=out)
    s = "20 B O 20 B U 1 N "
    assert out.getvalue() == s + "\n"

    out = StringIO()
    stats.update(10**3, unique=False)
    path = "foo"
    stats.show_progress(item=Item(path=path), final=False, stream=out)
    s = f"1.02 kB O 20 B U 1 N {path}"
    assert out.getvalue() == s + "\n"

    out = StringIO()
    path = "foo" * 40
    stats.show_progress(item=Item(path=path), final=False, stream=out)
    s = f"1.02 kB O 20 B U 1 N {path}"
    assert out.getvalue() == s + "\n"


def test_stats_format(stats):
    assert (
        str(stats)
        == """\
Number of files: 1
Original size: 20 B
Deduplicated size: 20 B
Time spent in hashing: 0.000 seconds
Time spent in chunking: 0.000 seconds
Added files: 0
Unchanged files: 0
Modified files: 0
Error files: 0
Files changed while reading: 0
Bytes read from remote: 0
Bytes sent to remote: 0
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


@pytest.mark.parametrize(
    "isoformat, expected",
    [
        ("1970-01-01T00:00:01.000001", datetime(1970, 1, 1, 0, 0, 1, 1, timezone.utc)),  # test with microseconds
        ("1970-01-01T00:00:01", datetime(1970, 1, 1, 0, 0, 1, 0, timezone.utc)),  # test without microseconds
    ],
)
def test_timestamp_parsing(monkeypatch, isoformat, expected):
    repository = Mock()
    key = PlaintextKey(repository)
    manifest = Manifest(key, repository)
    a = Archive(manifest, "test", create=True)
    a.metadata = ArchiveItem(time=isoformat)
    assert a.ts == expected


class MockCache:
    class MockRepo:
        def async_response(self, wait=True):
            pass

    def __init__(self):
        self.objects = {}
        self.repository = self.MockRepo()

    def add_chunk(self, id, meta, data, stats=None, wait=True, ro_type=None):
        assert ro_type is not None
        self.objects[id] = data
        return id, len(data)

    def fetch_many(self, ids, ro_type=None):
        """Mock implementation of fetch_many"""
        for id in ids:
            yield self.objects[id]


def test_cache_chunk_buffer():
    data = [Item(path="p1"), Item(path="p2")]
    cache = MockCache()
    key = PlaintextKey(None)
    chunks = CacheChunkBuffer(cache, key, None)
    for d in data:
        chunks.add(d)
        chunks.flush()
    chunks.flush(flush=True)
    assert len(chunks.chunks) == 2
    unpacker = msgpack.Unpacker()
    for id in chunks.chunks:
        unpacker.feed(cache.objects[id])
    assert data == [Item(internal_dict=d) for d in unpacker]


def test_partial_cache_chunk_buffer():
    big = "0123456789abcdefghijklmnopqrstuvwxyz" * 25000
    data = [Item(path="full", target=big), Item(path="partial", target=big)]
    cache = MockCache()
    key = PlaintextKey(None)
    chunks = CacheChunkBuffer(cache, key, None)
    for d in data:
        chunks.add(d)
    chunks.flush(flush=False)
    # the code is expected to leave the last partial chunk in the buffer
    assert len(chunks.chunks) == 3
    assert chunks.buffer.tell() > 0
    # now really flush
    chunks.flush(flush=True)
    assert len(chunks.chunks) == 4
    assert chunks.buffer.tell() == 0
    unpacker = msgpack.Unpacker()
    for id in chunks.chunks:
        unpacker.feed(cache.objects[id])
    assert data == [Item(internal_dict=d) for d in unpacker]


def make_chunks(items):
    return b"".join(msgpack.packb({"path": item}) for item in items)


def _validator(value):
    return isinstance(value, dict) and value.get("path") in ("foo", "bar", "boo", "baz")


def process(input):
    unpacker = RobustUnpacker(validator=_validator, item_keys=ITEM_KEYS)
    result = []
    for should_sync, chunks in input:
        if should_sync:
            unpacker.resync()
        for data in chunks:
            unpacker.feed(data)
            for item in unpacker:
                result.append(item)
    return result


def test_extra_garbage_no_sync():
    chunks = [(False, [make_chunks(["foo", "bar"])]), (False, [b"garbage"] + [make_chunks(["boo", "baz"])])]
    res = process(chunks)
    assert res == [{"path": "foo"}, {"path": "bar"}, 103, 97, 114, 98, 97, 103, 101, {"path": "boo"}, {"path": "baz"}]


def split(left, length):
    parts = []
    while left:
        parts.append(left[:length])
        left = left[length:]
    return parts


def test_correct_stream():
    chunks = split(make_chunks(["foo", "bar", "boo", "baz"]), 2)
    input = [(False, chunks)]
    result = process(input)
    assert result == [{"path": "foo"}, {"path": "bar"}, {"path": "boo"}, {"path": "baz"}]


def test_missing_chunk():
    chunks = split(make_chunks(["foo", "bar", "boo", "baz"]), 4)
    input = [(False, chunks[:3]), (True, chunks[4:])]
    result = process(input)
    assert result == [{"path": "foo"}, {"path": "boo"}, {"path": "baz"}]


def test_corrupt_chunk():
    chunks = split(make_chunks(["foo", "bar", "boo", "baz"]), 4)
    input = [(False, chunks[:3]), (True, [b"gar", b"bage"] + chunks[3:])]
    result = process(input)
    assert result == [{"path": "foo"}, {"path": "boo"}, {"path": "baz"}]


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


# pytest-xdist always requires the same order for the keys and dicts:
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
    ids=["minimal", "empty-values", "long-values"],
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
    # - a user/group name for the current process' real uid/gid exists.
    # - a system user/group udoesnotexist:gdoesnotexist does NOT exist.

    try:
        puid, pgid = os.getuid(), os.getgid()  # UNIX only
    except AttributeError:
        puid, pgid = 0, 0
    puser, pgroup = uid2user(puid), gid2group(pgid)

    # This is intentionally a "strange" item, with non-matching IDs/names.
    item = Item(path="filename", uid=1, gid=2, user=puser, group=pgroup)

    uid, gid = get_item_uid_gid(item, numeric=False)
    # these are found via a name-to-id lookup
    assert uid == puid
    assert gid == pgid

    uid, gid = get_item_uid_gid(item, numeric=True)
    # these are directly taken from the item.uid and .gid
    assert uid == 1
    assert gid == 2

    uid, gid = get_item_uid_gid(item, numeric=False, uid_forced=3, gid_forced=4)
    # these are enforced (not from item metadata)
    assert uid == 3
    assert gid == 4

    # item metadata broken, has negative ids.
    item = Item(path="filename", uid=-1, gid=-2, user=puser, group=pgroup)

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

    if not is_win32:
        # Due to the hack in borg.platform.windows_ug, user2uid/group2gid always return 0
        # (no matter which username we ask for), and they never raise a KeyError (e.g., for
        # a non-existing user/group name). Thus, these tests can currently not succeed on win32.

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

    # item metadata only has uid/gid, but no user/group.
    item = Item(path="filename", uid=13, gid=14)

    uid, gid = get_item_uid_gid(item, numeric=False)
    # It will check user/group first, but as there is nothing in the item, it falls back to uid/gid.
    assert uid == 13
    assert gid == 14

    uid, gid = get_item_uid_gid(item, numeric=True)
    # does not check user/group, directly returns uid/gid.
    assert uid == 13
    assert gid == 14

    # item metadata has no uid/gid/user/group.
    item = Item(path="filename")

    uid, gid = get_item_uid_gid(item, numeric=False, uid_default=15)
    # As there is nothing, it will fall back to uid_default/gid_default.
    assert uid == 15
    assert gid == 0

    uid, gid = get_item_uid_gid(item, numeric=True, gid_default=16)
    # As there is nothing, it will fall back to uid_default/gid_default.
    assert uid == 0
    assert gid == 16


def test_reject_non_sanitized_item():
    for path in rejected_dotdot_paths:
        with pytest.raises(ValueError, match="unexpected '..' element in path"):
            Item(path=path, user="root", group="root")


@pytest.fixture
def setup_extractor(tmpdir):
    """Setup common test infrastructure"""

    class MockCache:
        def __init__(self):
            self.objects = {}

    repository = Mock()
    key = PlaintextKey(repository)
    manifest = Manifest(key, repository)
    cache = MockCache()

    extractor = Archive(manifest=manifest, name="test", create=True)
    extractor.pipeline = cache
    extractor.key = key
    extractor.cwd = str(tmpdir)
    extractor.restore_attrs = Mock()

    # Track fetched chunks across tests
    fetched_chunks = []

    def create_mock_chunks(item_data, chunk_size=4):
        chunks = []
        for i in range(0, len(item_data), chunk_size):
            chunk_data = item_data[i : i + chunk_size]
            chunk_id = key.id_hash(chunk_data)
            chunks.append(ChunkListEntry(id=chunk_id, size=len(chunk_data)))
            cache.objects[chunk_id] = chunk_data

        item = Mock(spec=["chunks", "size", "__contains__", "get"])
        item.chunks = chunks
        item.size = len(item_data)
        item.__contains__ = lambda self, item: item == "size"

        return item, str(tmpdir.join("test.txt"))

    def mock_fetch_many(chunk_ids, ro_type=None):
        fetched_chunks.extend(chunk_ids)
        return iter([cache.objects[chunk_id] for chunk_id in chunk_ids])

    def clear_fetched_chunks():
        fetched_chunks.clear()

    def get_fetched_chunks():
        return fetched_chunks

    cache.fetch_many = mock_fetch_many

    return extractor, key, cache, tmpdir, create_mock_chunks, get_fetched_chunks, clear_fetched_chunks


@pytest.mark.parametrize(
    "name, item_data, fs_data, expected_fetched_chunks",
    [
        (
            "no_changes",
            b"1111",  # One complete chunk, no changes needed
            b"1111",  # Identical content
            0,  # No chunks should be fetched
        ),
        (
            "single_chunk_change",
            b"11112222",  # Two chunks
            b"1111XXXX",  # Second chunk different
            1,  # Only second chunk should be fetched
        ),
        (
            "cross_boundary_change",
            b"11112222",  # Two chunks
            b"111XX22",  # Change crosses chunk boundary
            2,  # Both chunks need update
        ),
        (
            "exact_multiple_chunks",
            b"11112222333",  # Three chunks (last one partial)
            b"1111XXXX333",  # Middle chunk different
            1,  # Only middle chunk fetched
        ),
        (
            "first_chunk_change",
            b"11112222",  # Two chunks
            b"XXXX2222",  # First chunk different
            1,  # Only first chunk should be fetched
        ),
        (
            "all_chunks_different",
            b"11112222",  # Two chunks
            b"XXXXYYYY",  # Both chunks different
            2,  # Both chunks should be fetched
        ),
        (
            "partial_last_chunk",
            b"111122",  # One full chunk + partial
            b"1111XX",  # Partial chunk different
            1,  # Only second chunk should be fetched
        ),
        (
            "fs_file_shorter",
            b"11112222",  # Two chunks in archive
            b"111122",  # Shorter on disk - missing part of second chunk
            1,  # Should fetch second chunk
        ),
        (
            "fs_file_longer",
            b"11112222",  # Two chunks in archive
            b"1111222233",  # Longer on disk
            0,  # Should fetch no chunks since content matches up to archive length
        ),
        (
            "empty_archive_file",
            b"",  # Empty in archive
            b"11112222",  # Content on disk
            0,  # No chunks to compare = no chunks to fetch
        ),
        (
            "empty_fs_file",
            b"11112222",  # Two chunks in archive
            b"",  # Empty on disk
            2,  # Should fetch all chunks since file is empty
        ),
    ],
)
def test_compare_and_extract_chunks(setup_extractor, name, item_data, fs_data, expected_fetched_chunks):
    """Test chunk comparison and extraction"""
    extractor, key, cache, tmpdir, create_mock_chunks, get_fetched_chunks, clear_fetched_chunks = setup_extractor
    clear_fetched_chunks()

    chunk_size = 4
    item, target_path = create_mock_chunks(item_data, chunk_size=chunk_size)

    original_chunk_ids = [chunk.id for chunk in item.chunks]

    with open(target_path, "wb") as f:
        f.write(fs_data)

    st = os.stat(target_path)
    result = extractor.compare_and_extract_chunks(item, target_path, st=st)
    assert result

    fetched_chunks = get_fetched_chunks()
    assert len(fetched_chunks) == expected_fetched_chunks

    # For single chunk changes, verify it's the correct chunk
    if expected_fetched_chunks == 1:
        item_chunks = [item_data[i : i + chunk_size] for i in range(0, len(item_data), chunk_size)]
        fs_chunks = [fs_data[i : i + chunk_size] for i in range(0, len(fs_data), chunk_size)]

        # Find which chunk should have changed by comparing item_data with fs_data
        for i, (item_chunk, fs_chunk) in enumerate(zip(item_chunks, fs_chunks)):
            if item_chunk != fs_chunk:
                assert fetched_chunks[0] == original_chunk_ids[i]
                break

    with open(target_path, "rb") as f:
        assert f.read() == item_data

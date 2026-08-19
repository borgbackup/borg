import json
import os
from collections import OrderedDict
from datetime import datetime, timezone
from io import StringIO
from unittest.mock import Mock

import pytest

from . import rejected_dotdot_paths, is_utime_fully_supported
from ..cache import ChunkListEntry
from ..constants import ROBJ_FILE_STREAM, zeros
from ..crypto.key import ChecksumKey
from ..archive import Archive, CacheChunkBuffer, DownloadPipeline, RobustUnpacker, valid_msgpacked_dict
from ..archive import ITEM_KEYS, Statistics
from ..archive import zero_chunk_flags, zero_chunk_id, zero_chunk_ids
from ..archive import BackupOSError, BackupRaceConditionError, backup_io, backup_io_iter, get_item_uid_gid
from ..archive import stat_update_check
from ..helpers import msgpack
from ..repoobj import RepoObj
from ..item import Item, ArchiveItem
from ..manifest import Archives, Manifest
from ..platform import uid2user, gid2group, is_win32


@pytest.fixture()
def stats():
    stats = Statistics()
    stats.update(20, unique=True)
    stats.nfiles = 1
    return stats


def show_progress_force(stats, **kwargs):
    # bypass the BORG_PROGRESS_FPS rate limiting, so every call produces output
    stats.last_progress = float("-inf")
    stats.show_progress(**kwargs)


class TTYStringIO(StringIO):
    def isatty(self):
        return True


def test_stats_basic(stats):
    assert stats.osize == 20
    assert stats.usize == 20
    stats.update(20, unique=False)
    assert stats.osize == 40
    assert stats.usize == 20


def test_stats_progress_tty(stats, monkeypatch, columns=80):
    monkeypatch.setenv("COLUMNS", str(columns))
    out = TTYStringIO()
    show_progress_force(stats, stream=out)
    s = "20 B O 20 B U 1 N "
    buf = " " * (columns - len(s))
    assert out.getvalue() == s + buf + "\r"

    out = TTYStringIO()
    stats.update(10**3, unique=False)
    show_progress_force(stats, item=Item(path="foo"), final=False, stream=out)
    s = "1.02 kB O 20 B U 1 N foo"
    buf = " " * (columns - len(s))
    assert out.getvalue() == s + buf + "\r"

    out = TTYStringIO()
    show_progress_force(stats, item=Item(path="foo" * 40), final=False, stream=out)
    s = "1.02 kB O 20 B U 1 N foofoofoofoofoofoofoofoofo...foofoofoofoofoofoofoofoofoofoo"
    buf = " " * (columns - len(s))
    assert out.getvalue() == s + buf + "\r"


@pytest.mark.parametrize(
    "columns, s",
    [
        (80, "1.00 TB O 20 B U 1 N foo"),  # narrow terminal: compact format, so the path stays visible
        (109, "1.00 TB O 20 B U 1 N foo"),  # still too narrow
        (110, "1.000000 TB O 20 B U 1 N foo"),  # wide terminal: more decimals, see #3559
    ],
)
def test_stats_progress_tty_fine(stats, monkeypatch, columns, s):
    monkeypatch.setenv("COLUMNS", str(columns))
    stats.update(10**12, unique=False)
    out = TTYStringIO()
    show_progress_force(stats, item=Item(path="foo"), final=False, stream=out)
    buf = " " * (columns - len(s))
    assert out.getvalue() == s + buf + "\r"


def test_stats_progress_file(stats, monkeypatch):
    out = StringIO()
    show_progress_force(stats, stream=out)
    s = "20 B O 20 B U 1 N "
    assert out.getvalue() == s + "\n"

    out = StringIO()
    stats.update(10**3, unique=False)
    path = "foo"
    show_progress_force(stats, item=Item(path=path), final=False, stream=out)
    s = f"1.02 kB O 20 B U 1 N {path}"
    assert out.getvalue() == s + "\n"

    out = StringIO()
    path = "foo" * 40
    show_progress_force(stats, item=Item(path=path), final=False, stream=out)
    s = f"1.02 kB O 20 B U 1 N {path}"
    assert out.getvalue() == s + "\n"

    out = StringIO()
    stats.update(10**12, unique=False)
    path = "foo"
    show_progress_force(stats, item=Item(path=path), final=False, stream=out)
    s = f"1.000000 TB O 20 B U 1 N {path}"  # no width limit here, so always more decimals, see #3559
    assert out.getvalue() == s + "\n"


def test_stats_progress_rate_limited(stats):
    out = StringIO()
    stats.show_progress(stream=out)  # the first update is always shown
    assert out.getvalue() != ""
    out = StringIO()
    stats.show_progress(stream=out)  # immediately after: suppressed by the BORG_PROGRESS_FPS rate limit
    assert out.getvalue() == ""
    out = StringIO()
    stats.show_progress(stream=out, final=True)  # the final update is never suppressed
    assert out.getvalue() != ""


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
"""
    )
    s = f"{stats.osize_fmt}"
    assert s == "20 B"
    # kind of redundant, but id is variable so we can't match reliably
    assert repr(stats) == f"<Statistics object at {id(stats):#x} (20, 20)>"


def test_stats_progress_json(stats):
    stats.output_json = True

    out = StringIO()
    show_progress_force(stats, item=Item(path="foo"), stream=out)
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
    key = ChecksumKey(repository)
    manifest = Manifest(key, repository)
    a = Archive(manifest, "test", create=True)
    a.metadata = ArchiveItem(time=isoformat)
    assert a.ts == expected


class MockCache:
    class MockRepo:
        pass

    def __init__(self):
        self.objects = {}
        self.repository = self.MockRepo()

    def add_chunk(self, id, meta, data, stats=None, ro_type=None):
        assert ro_type is not None
        self.objects[id] = data
        return id, len(data)


def test_cache_chunk_buffer():
    data = [Item(path="p1"), Item(path="p2")]
    cache = MockCache()
    key = ChecksumKey(None)
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
    key = ChecksumKey(None)
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


class MockFetchRepo:
    """serve repo objects from a dict, recording all requested ids."""

    def __init__(self, objects):
        self.objects = objects  # id -> cdata
        self.requested_ids = []

    def get_many(self, ids, read_data=True, raise_missing=True):
        for id in ids:
            self.requested_ids.append(id)
            yield self.objects[id]


def test_download_pipeline_parsed_cache():
    # a content data stream may reference the same chunk many times (e.g. the all-zero
    # chunks of a sparse file): repeated chunks shall be parsed (decrypted, authenticated,
    # decompressed) only once, see issue #1678.
    key = ChecksumKey(None)
    repo_objs = RepoObj(key)
    # note: repeated, but not all-zero data, so it is not served via the zeros shortcut
    chunks_data = [b"foobar" * 100, b"idletone" * 125, b"barbaz" * 100]
    entries = []
    objects = {}
    for data in chunks_data:
        id = repo_objs.id_hash(data)
        objects[id] = repo_objs.format(id, {}, data, ro_type=ROBJ_FILE_STREAM)
        entries.append(ChunkListEntry(id, len(data)))
    # reference the second chunk many times, interleaved with the other chunks
    chunk_list = [entries[0]] + [entries[1]] * 5 + [entries[2]] + [entries[1]] * 5
    repository = MockFetchRepo(objects)
    pipeline = DownloadPipeline(repository, repo_objs)
    parsed_ids = []
    orig_parse = repo_objs.parse

    def counting_parse(id, cdata, **kw):
        parsed_ids.append(id)
        return orig_parse(id, cdata, **kw)

    repo_objs.parse = counting_parse
    result = list(pipeline.fetch_many(chunk_list, ro_type=ROBJ_FILE_STREAM))
    assert result == [chunks_data[0]] + [chunks_data[1]] * 5 + [chunks_data[2]] + [chunks_data[1]] * 5
    # each distinct chunk was parsed only once, the repetitions were served from the cache
    assert len(parsed_ids) == 3
    assert len(set(parsed_ids)) == 3


@pytest.mark.parametrize("replacement_chunk", [False, True])
def test_download_pipeline_missing_chunk(replacement_chunk):
    # a chunk missing in the repository is either replaced by all-zero data of the
    # correct size, or reported as None - and never blows up on the size check.
    key = ChecksumKey(None)
    repo_objs = RepoObj(key)
    data = b"foobar" * 100
    id = repo_objs.id_hash(data)
    repository = MockFetchRepo({id: None})  # the object is gone
    pipeline = DownloadPipeline(repository, repo_objs)
    chunk_list = [ChunkListEntry(id, len(data))]
    result = list(pipeline.fetch_many(chunk_list, ro_type=ROBJ_FILE_STREAM, replacement_chunk=replacement_chunk))
    assert result == [zeros[: len(data)] if replacement_chunk else None]


def test_download_pipeline_zero_chunks_served_locally():
    # repeated all-zero chunks (e.g. from the holes of a sparse file) shall be served
    # directly from the zeros constant, without repository access, see issue #1678.
    key = ChecksumKey(None)
    repo_objs = RepoObj(key)
    data = b"foobar" * 100
    data_id = repo_objs.id_hash(data)
    objects = {data_id: repo_objs.format(data_id, {}, data, ro_type=ROBJ_FILE_STREAM)}
    zero_size = 1000
    zero_id = repo_objs.id_hash(zeros[:zero_size])
    # note: the all-zero chunk is intentionally NOT in the repository objects,
    # thus serving it can only work without repository access.
    chunk_list = [
        ChunkListEntry(zero_id, zero_size),
        ChunkListEntry(data_id, len(data)),
        ChunkListEntry(zero_id, zero_size),
        ChunkListEntry(zero_id, zero_size),
    ]
    repository = MockFetchRepo(objects)
    pipeline = DownloadPipeline(repository, repo_objs)
    result = list(pipeline.fetch_many(chunk_list, ro_type=ROBJ_FILE_STREAM))
    assert result == [zeros[:zero_size], data, zeros[:zero_size], zeros[:zero_size]]
    assert repository.requested_ids == [data_id]
    # now that the zero chunk id of this size is known, even a single occurrence
    # is served locally:
    repository.requested_ids.clear()
    result = list(pipeline.fetch_many([ChunkListEntry(zero_id, zero_size)], ro_type=ROBJ_FILE_STREAM))
    assert result == [zeros[:zero_size]]
    assert repository.requested_ids == []
    # but a single occurrence of an all-zero chunk of an unknown size is still
    # fetched from the repository:
    other_size = 500
    other_id = repo_objs.id_hash(zeros[:other_size])
    objects[other_id] = repo_objs.format(other_id, {}, zeros[:other_size], ro_type=ROBJ_FILE_STREAM)
    result = list(pipeline.fetch_many([ChunkListEntry(other_id, other_size)], ro_type=ROBJ_FILE_STREAM))
    assert result == [zeros[:other_size]]
    assert repository.requested_ids == [other_id]


def test_zero_chunk_flags():
    # cheap all-zero chunk detection from the chunk ids/sizes alone: the zero chunk id
    # is computed for ids occurring repeatedly, while unique ids are only compared
    # against already memoized zero chunk ids.
    key = ChecksumKey(None)
    id_hash = key.id_hash
    data = b"foobar" * 100
    data_id = id_hash(data)
    repeated_size, unique_size = 1234, 4321
    repeated_id = id_hash(zeros[:repeated_size])
    unique_id = id_hash(zeros[:unique_size])
    # make sure nothing is memoized for these sizes yet
    for size in (repeated_size, unique_size):
        zero_chunk_ids.pop((id_hash, size), None)
    ids = [repeated_id, data_id, repeated_id, unique_id]
    sizes = [repeated_size, len(data), repeated_size, unique_size]
    # the repeated zero id gets detected, the unique one is missed (nothing memoized yet)
    assert zero_chunk_flags(ids, sizes, id_hash) == [True, False, True, False]
    # once its size's zero chunk id is memoized, the unique one gets detected, too
    zero_chunk_id(id_hash, unique_size)
    assert zero_chunk_flags(ids, sizes, id_hash) == [True, False, True, True]
    # unknown (None) or out-of-range sizes disable the detection
    assert zero_chunk_flags([repeated_id, repeated_id], [None, None], id_hash) == [False, False]


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


def _stat_with_atime(path, atime_ns, mtime_ns=234567890000000000):
    os.utime(path, ns=(atime_ns, mtime_ns))
    return os.stat(path)


@pytest.mark.skipif(not is_utime_fully_supported(), reason="cannot properly setup and execute test without utime")
def test_stat_update_check_atime_updated(tmpdir):
    path = str(tmpdir.join("file"))
    with open(path, "wb") as f:
        f.write(b"12345")
    st_old = _stat_with_atime(path, 123456789000000000)
    st_curr = _stat_with_atime(path, 987654321000000000)
    st = stat_update_check(st_old, st_curr)
    # the atime is the one from before we (usually: by opening the file) touched it, see #6194:
    assert st.st_atime_ns == st_old.st_atime_ns
    assert st.st_atime == st_old.st_atime
    # everything else comes from the current stat:
    assert st.st_mode == st_curr.st_mode
    assert st.st_ino == st_curr.st_ino
    assert st.st_size == st_curr.st_size
    assert st.st_mtime_ns == st_curr.st_mtime_ns
    # optional attributes must be present (or absent) just like on a real stat result:
    assert hasattr(st, "st_birthtime_ns") == hasattr(st_curr, "st_birthtime_ns")
    with pytest.raises(AttributeError):
        st.st_does_not_exist


@pytest.mark.skipif(not is_utime_fully_supported(), reason="cannot properly setup and execute test without utime")
def test_stat_update_check_atime_unchanged(tmpdir):
    path = str(tmpdir.join("file"))
    with open(path, "wb") as f:
        f.write(b"12345")
    st_old = _stat_with_atime(path, 123456789000000000)
    st_curr = os.stat(path)
    assert st_old.st_atime_ns == st_curr.st_atime_ns
    # nothing to fix up, so we get the current stat result as is:
    assert stat_update_check(st_old, st_curr) is st_curr


def test_stat_update_check_race_conditions(tmpdir):
    file_path = str(tmpdir.join("file"))
    with open(file_path, "wb"):
        pass
    other_path = str(tmpdir.join("other_file"))
    with open(other_path, "wb"):
        pass
    st_file, st_other, st_dir = os.stat(file_path), os.stat(other_path), os.stat(str(tmpdir))
    with pytest.raises(BackupRaceConditionError):  # file type changed
        stat_update_check(st_file, st_dir)
    with pytest.raises(BackupRaceConditionError):  # inode changed
        stat_update_check(st_file, st_other)


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


def test_archives_get_by_id_missing_returns_none():
    repo = Mock()
    repo.store_list.return_value = []  # empty store — id will not be found
    manifest = Mock()
    archives = Archives(repo, manifest)
    assert archives.get_by_id(b"\x01" * 32) is None

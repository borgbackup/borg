import json
import os
import stat
from collections import OrderedDict
from datetime import datetime, timezone
from io import StringIO
from unittest.mock import Mock

import pytest

from . import rejected_dotdot_paths
from ..crypto.key import PlaintextKey
from ..archive import Archive, CacheChunkBuffer, RobustUnpacker, valid_msgpacked_dict, ITEM_KEYS, Statistics
from ..archive import BackupError, BackupOSError, backup_io, backup_io_iter, get_item_uid_gid
from ..helpers import msgpack
from ..item import Item, ArchiveItem, ChunkListEntry
from ..manifest import Archives, Manifest
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


def test_archives_get_by_id_missing_returns_none():
    repo = Mock()
    repo.store_list.return_value = []  # empty store — id will not be found
    manifest = Mock()
    archives = Archives(repo, manifest)
    assert archives.get_by_id(b"\x01" * 32) is None


# ---- borg extract: in-place chunk comparison / selective extraction (#5638) ----

CHUNK_SIZE = 4


class FetchManyPipeline:
    """Minimal pipeline stand-in that records which chunk ids fetch_many() requested."""

    def __init__(self, objects):
        self.objects = objects  # id -> data
        self.fetched = []

    def fetch_many(self, chunks, ro_type=None):
        assert ro_type is not None
        for chunk in chunks:
            self.fetched.append(chunk.id)
            yield self.objects[chunk.id]


@pytest.fixture
def extractor(tmpdir):
    repository = Mock()
    key = PlaintextKey(repository)
    manifest = Manifest(key, repository)
    archive = Archive(manifest=manifest, name="test", create=True)
    archive.key = key
    archive.cwd = str(tmpdir)
    return archive


def make_item(key, objects, data):
    """Chunk *data* into CHUNK_SIZE pieces, register them in *objects*, return an Item."""
    chunks = []
    for i in range(0, len(data), CHUNK_SIZE):
        piece = data[i : i + CHUNK_SIZE]
        cid = key.id_hash(piece)
        chunks.append(ChunkListEntry(id=cid, size=len(piece)))
        objects[cid] = piece
    item = Item(path="test", mode=stat.S_IFREG | 0o644, size=len(data))
    item.chunks = chunks
    return item


@pytest.mark.parametrize(
    "name, item_data, fs_data, expected_fetched",
    [
        ("no_change", b"11112222", b"11112222", 0),
        ("first_chunk", b"11112222", b"33332222", 1),
        ("second_chunk", b"11112222", b"11113333", 1),
        ("both_chunks", b"11112222", b"33334444", 2),
        ("cross_boundary", b"11112222", b"11333322", 2),
        ("partial_last_chunk", b"1111222233", b"1111222244", 1),
        ("fs_shorter", b"11112222", b"111122", 1),
        ("fs_longer", b"11112222", b"1111222233", 0),
        ("empty_item", b"", b"11112222", 0),
        ("empty_fs", b"11112222", b"", 2),
    ],
)
def test_compare_and_extract_chunks(extractor, tmpdir, name, item_data, fs_data, expected_fetched):
    objects = {}
    item = make_item(extractor.key, objects, item_data)
    pipeline = FetchManyPipeline(objects)
    extractor.pipeline = pipeline
    # we only exercise the data path here; attribute (re)storing is covered elsewhere.
    extractor.clear_attrs = Mock()
    extractor.restore_attrs = Mock()

    path = str(tmpdir.join("test"))
    with open(path, "wb") as f:
        f.write(fs_data)
    st = os.stat(path)

    assert extractor.compare_and_extract_chunks(item, path, st=st)
    assert len(pipeline.fetched) == expected_fetched
    with open(path, "rb") as f:
        assert f.read() == item_data


def test_compare_and_extract_chunks_fetches_only_differing(extractor, tmpdir):
    objects = {}
    item = make_item(extractor.key, objects, b"11112222")
    pipeline = FetchManyPipeline(objects)
    extractor.pipeline = pipeline
    extractor.clear_attrs = Mock()
    extractor.restore_attrs = Mock()

    path = str(tmpdir.join("test"))
    with open(path, "wb") as f:
        f.write(b"1111XXXX")  # only the second chunk differs

    extractor.compare_and_extract_chunks(item, path, st=os.stat(path))
    # exactly the (differing) second chunk should have been fetched, not the first.
    assert pipeline.fetched == [item.chunks[1].id]


@pytest.mark.parametrize("st_is_none", [True, False])
def test_compare_and_extract_chunks_skips_non_regular(extractor, tmpdir, st_is_none):
    objects = {}
    item = make_item(extractor.key, objects, b"11112222")
    extractor.pipeline = FetchManyPipeline(objects)
    if st_is_none:
        st = None
    else:
        st = os.stat(str(tmpdir))  # a directory, not a regular file
    assert extractor.compare_and_extract_chunks(item, str(tmpdir.join("test")), st=st) is False


def test_compare_and_extract_chunks_size_inconsistency(extractor, tmpdir):
    # if the archived item.size does not match the size implied by its chunks, we must raise
    # rather than silently produce a wrong file (parity with the normal extraction path).
    objects = {}
    item = make_item(extractor.key, objects, b"11112222")
    item.size = 9999  # deliberately wrong (the chunks add up to 8 bytes)
    extractor.pipeline = FetchManyPipeline(objects)
    extractor.clear_attrs = Mock()
    extractor.restore_attrs = Mock()
    path = str(tmpdir.join("test"))
    with open(path, "wb") as f:
        f.write(b"1111XXXX")
    with pytest.raises(BackupError):
        extractor.compare_and_extract_chunks(item, path, st=os.stat(path))


def test_will_patch_in_place(extractor, tmpdir):
    objects = {}

    # no file at the destination yet -> normal extraction
    item = make_item(extractor.key, objects, b"11112222")  # item.path == "test", regular file
    assert extractor.will_patch_in_place(item) is False

    # an existing regular file at the destination -> patch in place
    with open(str(tmpdir.join("test")), "wb") as f:
        f.write(b"11112222")
    assert extractor.will_patch_in_place(item) is True

    # a hard-linked archive item is never patched in place (even if the file exists)
    hl_item = make_item(extractor.key, objects, b"11112222")
    hl_item.hlid = b"\x00" * 32
    assert extractor.will_patch_in_place(hl_item) is False

    # a non-regular archive item (e.g. a directory) is never patched in place
    dir_item = make_item(extractor.key, objects, b"11112222")
    dir_item.mode = stat.S_IFDIR | 0o755
    assert extractor.will_patch_in_place(dir_item) is False


def test_compare_and_extract_chunks_skips_hardlinks(extractor, tmpdir):
    objects = {}
    item = make_item(extractor.key, objects, b"11112222")
    item.hlid = b"\x00" * 32  # a hard link must use the normal (preloaded) extraction path
    path = str(tmpdir.join("test"))
    with open(path, "wb") as f:
        f.write(b"11112222")
    assert extractor.compare_and_extract_chunks(item, path, st=os.stat(path)) is False


def test_compare_and_extract_chunks_skips_hardlinked_file(extractor, tmpdir):
    # a destination file with other hard links (st_nlink > 1) must not be patched in place,
    # as that would change the content seen through those other links.
    # We synthesize st_nlink=2 instead of calling os.link(), because whether a hard link
    # actually bumps st_nlink (or is supported at all) depends on the filesystem.
    objects = {}
    item = make_item(extractor.key, objects, b"11112222")
    extractor.pipeline = FetchManyPipeline(objects)
    path = str(tmpdir.join("test"))
    with open(path, "wb") as f:
        f.write(b"11112222")
    fields = list(os.stat(path))  # the 10 standard stat fields
    fields[3] = 2  # st_nlink
    st = os.stat_result(fields)
    assert extractor.compare_and_extract_chunks(item, path, st=st) is False


def test_compare_and_extract_chunks_skips_file_with_extended_acl(extractor, tmpdir):
    # a file carrying an extended ACL must not be patched in place, because clear_attrs() does
    # not reset ACLs; such files fall back to normal extraction (fresh inode, clean metadata).
    objects = {}
    item = make_item(extractor.key, objects, b"11112222")
    extractor.pipeline = FetchManyPipeline(objects)
    extractor._fs_has_extended_acl = Mock(return_value=True)
    path = str(tmpdir.join("test"))
    with open(path, "wb") as f:
        f.write(b"11112222")
    assert extractor.compare_and_extract_chunks(item, path, st=os.stat(path)) is False


@pytest.mark.skipif(is_win32, reason="xattrs/clear_attrs are POSIX-only")
def test_compare_and_extract_chunks_clears_stale_xattr(extractor, tmpdir):
    from .. import xattr as xattr_mod

    path = str(tmpdir.join("test")).encode()
    with open(path, "wb") as f:
        f.write(b"oldcontent")
    if not xattr_mod.is_enabled(str(tmpdir)):
        pytest.skip("xattrs not supported on this filesystem")
    xattr_mod.set_all(path, {b"user.stale": b"1"})

    objects = {}
    item = make_item(extractor.key, objects, b"11112222")
    extractor.pipeline = FetchManyPipeline(objects)
    extractor.restore_attrs = Mock()  # real clear_attrs, but skip restoring archived attrs

    assert extractor.compare_and_extract_chunks(item, path.decode(), st=os.stat(path))
    # the stale xattr that was not part of the archive item must be gone.
    assert b"user.stale" not in xattr_mod.get_all(path)

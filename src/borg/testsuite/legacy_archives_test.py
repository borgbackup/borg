"""Tests for borg.legacy.archives (LegacyArchives)."""

from argparse import Namespace
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from ..crypto.key import PlaintextKey
from ..helpers.errors import CommandError, Error
from ..legacy.archives import LegacyArchives
from ..legacy.repository import LegacyRepository
from ..manifest import ArchiveInfo, ArchivesInterface, Manifest


# ── helpers ──────────────────────────────────────────────────────────────────────


def _id(n):
    return bytes([n]) * 32


TS = "2020-06-01T12:00:00.000000"
TS2 = "2021-06-01T12:00:00.000000"


def _archives(entries=()):
    """Return LegacyArchives with minimal mocks; entries = [(name, id, ts_str), ...]."""
    repo = MagicMock()
    manifest = MagicMock()
    la = LegacyArchives(repo, manifest)
    for name, id_, ts in entries:
        la._archives[name] = {"id": id_, "time": ts}
    return la, repo, manifest


def _archive_meta(name, id_, ts=TS, *, username="", hostname="", tags=()):
    return {
        "id": id_,
        "name": name,
        "time": ts,
        "exists": True,
        "username": username,
        "hostname": hostname,
        "size": 0,
        "nfiles": 0,
        "comment": "",
        "tags": tags,
    }


def _archiveinfo(name, id_, ts=TS, *, username="", hostname="", tags=()):
    from ..helpers.time import parse_timestamp

    return ArchiveInfo(name=name, id=id_, ts=parse_timestamp(ts), tags=tags, user=username, host=hostname)


def _make_list_target(infos):
    """LegacyArchives with _info_tuples replaced so callers get controlled data."""
    la, repo, manifest = _archives([(i.name, i.id, TS) for i in infos])
    la._info_tuples = lambda deleted=False: iter(infos)
    return la


# ── init / raw-dict operations ───────────────────────────────────────────────────


def test_init():
    la, repo, manifest = _archives()
    assert la._archives == {}
    assert la.repository is repo
    assert la.manifest is manifest


def test_set_raw_dict_and_get_raw_dict():
    la, _, _ = _archives()
    d = {"a": {"id": _id(1), "time": TS}}
    la._set_raw_dict(d)
    assert la._get_raw_dict() == d


def test_prepare():
    la, repo, manifest = _archives()
    m = MagicMock()
    m.archives = {"x": {"id": _id(5), "time": TS}}
    la.prepare(manifest, m)
    assert la._archives == {"x": {"id": _id(5), "time": TS}}


def test_finish():
    la, _, manifest = _archives([("a", _id(1), TS)])
    result = la.finish(manifest)
    assert result == {"a": {"id": _id(1), "time": TS}}


def test_ids():
    la, _, _ = _archives([("a", _id(1), TS), ("b", _id(2), TS)])
    assert list(la.ids()) == [_id(1), _id(2)]


def test_count():
    la, _, _ = _archives([("a", _id(1), TS), ("b", _id(2), TS)])
    assert la.count() == 2


def test_names():
    la, _, _ = _archives([("a", _id(1), TS), ("b", _id(2), TS)])
    assert list(la.names()) == ["a", "b"]


def test_exists_true():
    la, _, _ = _archives([("a", _id(1), TS)])
    assert la.exists("a") is True


def test_exists_false():
    la, _, _ = _archives()
    assert la.exists("missing") is False


# ── create ───────────────────────────────────────────────────────────────────────


def test_create_with_str_ts():
    la, _, _ = _archives()
    la.create("a", _id(1), TS)
    assert la._archives["a"] == {"id": _id(1), "time": TS}


def test_create_with_datetime_ts():
    la, _, _ = _archives()
    dt = datetime(2020, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    la.create("a", _id(1), dt)
    assert la._archives["a"]["time"] == dt.isoformat(timespec="microseconds")


def test_create_raises_if_exists():
    la, _, _ = _archives([("a", _id(1), TS)])
    with pytest.raises(KeyError, match="already exists"):
        la.create("a", _id(2), TS)


def test_create_overwrite():
    la, _, _ = _archives([("a", _id(1), TS)])
    la.create("a", _id(2), TS, overwrite=True)
    assert la._archives["a"]["id"] == _id(2)


# ── get / get_by_id ───────────────────────────────────────────────────────────────


def test_get_missing_returns_none():
    la, _, _ = _archives()
    assert la.get("nope") is None


def test_get_returns_archive_archiveinfo():
    la, _, _ = _archives([("a", _id(1), TS)])
    info = la.get("a")
    assert isinstance(info, ArchiveInfo)
    assert info.name == "a"
    assert info.id == _id(1)


def test_get_raw():
    la, _, _ = _archives([("a", _id(1), TS)])
    result = la.get("a", raw=True)
    assert result == {"name": "a", "id": _id(1), "time": TS}


def test_get_by_id_missing_returns_none():
    la, _, _ = _archives()
    assert la.get_by_id(_id(99)) is None


def test_get_by_id_returns_archive_archiveinfo():
    la, _, _ = _archives([("a", _id(1), TS)])
    info = la.get_by_id(_id(1))
    assert isinstance(info, ArchiveInfo)
    assert info.name == "a"


def test_get_by_id_raw():
    la, _, _ = _archives([("a", _id(1), TS)])
    result = la.get_by_id(_id(1), raw=True)
    assert result == {"name": "a", "id": _id(1), "time": TS}


# ── NotImplementedError stubs ──────────────────────────────────────────────────────


def test_exists_id_not_implemented():
    la, _, _ = _archives()
    with pytest.raises(NotImplementedError):
        la.exists_id(_id(1))


def test_exists_name_and_id_not_implemented():
    la, _, _ = _archives()
    with pytest.raises(NotImplementedError):
        la.exists_name_and_id("a", _id(1))


def test_exists_name_and_ts_not_implemented():
    la, _, _ = _archives()
    with pytest.raises(NotImplementedError):
        la.exists_name_and_ts("a", datetime.now())


def test_delete_by_id_not_implemented():
    la, _, _ = _archives()
    with pytest.raises(NotImplementedError):
        la.delete_by_id(_id(1))


def test_undelete_by_id_not_implemented():
    la, _, _ = _archives()
    with pytest.raises(NotImplementedError):
        la.undelete_by_id(_id(1))


def test_nuke_by_id_not_implemented():
    la, _, _ = _archives()
    with pytest.raises(NotImplementedError):
        la.nuke_by_id(_id(1))


# ── _get_archive_meta ────────────────────────────────────────────────────────────


def test_get_archive_meta_object_not_found():
    la, repo, _ = _archives()
    repo.get.side_effect = LegacyRepository.ObjectNotFound(_id(1), "/fake/path")
    result = la._get_archive_meta(_id(1))
    assert result["exists"] is False
    assert result["name"] == "archive-does-not-exist"
    assert result["id"] == _id(1)
    assert result["tags"] == ()


def test_get_archive_meta_success():
    la, _, manifest = _archives()
    manifest.repo_objs.parse.return_value = (None, b"data")
    manifest.key.unpack_archive.return_value = {}

    with patch("borg.legacy.archives.ArchiveItem") as mock_ai:
        item = MagicMock()
        item.version = 2
        item.name = "myarchive"
        item.time = "2021-03-15T10:00:00.000000"
        item.username = "alice"
        item.hostname = "myhost"
        item.get.side_effect = lambda k, d=None: d
        mock_ai.return_value = item

        result = la._get_archive_meta(_id(1))

    assert result["exists"] is True
    assert result["name"] == "myarchive"
    assert result["username"] == "alice"
    assert result["hostname"] == "myhost"


def test_get_archive_meta_bad_version():
    la, _, manifest = _archives()
    manifest.repo_objs.parse.return_value = (None, b"data")
    manifest.key.unpack_archive.return_value = {}

    with patch("borg.legacy.archives.ArchiveItem") as mock_ai:
        item = MagicMock()
        item.version = 99
        mock_ai.return_value = item

        with pytest.raises(Exception, match="Unknown archive metadata version"):
            la._get_archive_meta(_id(1))


# ── _infos / _info_tuples ────────────────────────────────────────────────────────


def test_infos_and_info_tuples():
    la, _, _ = _archives([("a", _id(1), TS)])
    la._get_archive_meta = lambda id_: _archive_meta("a", _id(1))
    infos = list(la._infos())
    assert len(infos) == 1
    assert infos[0]["name"] == "a"
    tuples = list(la._info_tuples())
    assert len(tuples) == 1
    assert isinstance(tuples[0], ArchiveInfo)
    assert tuples[0].name == "a"


# ── list ──────────────────────────────────────────────────────────────────────────


def test_list_no_filters():
    info = _archiveinfo("a", _id(1))
    la = _make_list_target([info])
    assert la.list() == [info]


def test_list_sort_by_str_raises():
    la = _make_list_target([_archiveinfo("a", _id(1))])
    with pytest.raises(TypeError, match="sequence"):
        la.list(sort_by="name")


def test_list_sort_by():
    i1 = _archiveinfo("b", _id(2), TS2)
    i2 = _archiveinfo("a", _id(1), TS)
    la = _make_list_target([i1, i2])
    result = la.list(sort_by=["name"])
    assert result == [i2, i1]


def test_list_reverse():
    i1 = _archiveinfo("a", _id(1))
    i2 = _archiveinfo("b", _id(2))
    la = _make_list_target([i1, i2])
    assert la.list(reverse=True) == [i2, i1]


def test_list_first():
    infos = [_archiveinfo(f"a{i}", _id(i + 1)) for i in range(5)]
    la = _make_list_target(infos)
    assert la.list(first=3) == infos[:3]


def test_list_last():
    infos = [_archiveinfo(f"a{i}", _id(i + 1)) for i in range(5)]
    la = _make_list_target(infos)
    assert la.list(last=2) == infos[-2:]


def test_list_date_filter():
    i1 = _archiveinfo("a", _id(1))
    la = _make_list_target([i1])
    with patch("borg.legacy.archives.filter_archives_by_date", return_value=[i1]) as mock_filter:
        result = la.list(older="1d")
    assert result == [i1]
    assert mock_filter.called


def test_list_match_name():
    i1 = _archiveinfo("archive-a", _id(1))
    i2 = _archiveinfo("archive-b", _id(2))
    la = _make_list_target([i1, i2])
    result = la.list(match=["archive-a"])
    assert result == [i1]


def test_list_match_name_prefix():
    i1 = _archiveinfo("archive-a", _id(1))
    i2 = _archiveinfo("other", _id(2))
    la = _make_list_target([i1, i2])
    result = la.list(match=["name:archive-a"])
    assert result == [i1]


def test_list_match_user():
    i1 = _archiveinfo("a", _id(1), username="alice")
    i2 = _archiveinfo("b", _id(2), username="bob")
    la = _make_list_target([i1, i2])
    assert la.list(match=["user:alice"]) == [i1]


def test_list_match_host():
    i1 = _archiveinfo("a", _id(1), hostname="laptop")
    i2 = _archiveinfo("b", _id(2), hostname="server")
    la = _make_list_target([i1, i2])
    assert la.list(match=["host:laptop"]) == [i1]


def test_list_match_tags():
    i1 = _archiveinfo("a", _id(1), tags=("prod", "db"))
    i2 = _archiveinfo("b", _id(2), tags=("dev",))
    la = _make_list_target([i1, i2])
    assert la.list(match=["tags:prod"]) == [i1]


def test_list_match_aid():
    from ..helpers.parseformat import bin_to_hex

    i1 = _archiveinfo("a", _id(1))
    la = _make_list_target([i1])
    prefix = bin_to_hex(_id(1))[:4]
    assert la.list(match=[f"aid:{prefix}"]) == [i1]


def test_list_match_aid_ambiguous():
    from ..helpers.parseformat import bin_to_hex

    i1 = _archiveinfo("a", _id(1))
    i2 = _archiveinfo("b", _id(1))
    la = _make_list_target([i1, i2])
    prefix = bin_to_hex(_id(1))[:4]
    with pytest.raises(CommandError):
        la.list(match=[f"aid:{prefix}"])


# ── get_one ───────────────────────────────────────────────────────────────────────


def test_get_one_exact_match():
    i1 = _archiveinfo("backup", _id(1))
    la = _make_list_target([i1])
    assert la.get_one(["backup"]) == i1


def test_get_one_no_match_raises():
    la = _make_list_target([])
    with pytest.raises(CommandError, match="matched 0"):
        la.get_one(["missing"])


def test_get_one_multiple_matches_raises():
    i1 = _archiveinfo("a", _id(1))
    i2 = _archiveinfo("a", _id(2))
    la = _make_list_target([i1, i2])
    with pytest.raises(CommandError, match="matched 2"):
        la.get_one(["a"])


# ── list_considering ──────────────────────────────────────────────────────────────


def test_list_considering_raises_if_name_set():
    la, _, _ = _archives()
    args = MagicMock()
    args.name = "archive"
    with pytest.raises(Error):
        la.list_considering(args)


def test_list_considering_delegates():
    i1 = _archiveinfo("a", _id(1))
    la = _make_list_target([i1])
    args = Namespace(
        name=None,
        sort_by="name",
        match_archives=None,
        first=None,
        last=None,
        older=None,
        newer=None,
        oldest=None,
        newest=None,
        deleted=False,
    )
    result = la.list_considering(args)
    assert result == [i1]


# ── ArchivesInterface Protocol / Manifest dispatch ────────────────────────────────


def test_legacy_archives_satisfies_archives_interface():
    la, _, _ = _archives()
    assert isinstance(la, ArchivesInterface)


class _FakeLegacyRepo(LegacyRepository):
    def __init__(self):
        pass


def test_manifest_creates_legacy_archives_for_legacy_repo():
    repo = _FakeLegacyRepo()
    key = PlaintextKey(repo)
    manifest = Manifest(key, repo)
    assert isinstance(manifest.archives, LegacyArchives)

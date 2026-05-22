from argparse import Namespace
from datetime import datetime, timezone
from unittest.mock import Mock, patch

import pytest

from borgstore.store import ItemInfo, ObjectNotFound as StoreObjectNotFound

from ..helpers.errors import CommandError, Error
from ..helpers.parseformat import bin_to_hex
from ..helpers.time import parse_timestamp
from ..manifest import Archives, ArchiveInfo, ArchivesInterface
from ..repository import Repository


def _id(n):
    return bytes([n]) * 32


TS = "2020-06-01T12:00:00.000000"
TS2 = "2021-06-01T12:00:00.000000"


def _iteminfo(id_bytes):
    return ItemInfo(name=bin_to_hex(id_bytes), exists=True, size=0, directory=False)


def _archives():
    repo = Mock()
    repo.store_list.return_value = []
    manifest = Mock()
    return Archives(repo, manifest), repo, manifest


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
    return ArchiveInfo(name=name, id=id_, ts=parse_timestamp(ts), tags=tags, user=username, host=hostname)


def _stub_matching_info_tuples(infos):
    ar, _, _ = _archives()
    ar._matching_info_tuples = Mock(side_effect=lambda match_patterns, match_end, deleted=False: list(infos))
    return ar


def _stub_info_tuples(infos):
    ar, _, _ = _archives()
    ar._info_tuples = Mock(side_effect=lambda deleted=False: iter(infos))
    return ar


def test_archives_satisfies_archives_interface():
    ar, _, _ = _archives()
    assert isinstance(ar, ArchivesInterface)


def test_prepare_is_noop():
    ar, repo, manifest = _archives()
    m = Mock()
    ar.prepare(manifest, m)
    repo.assert_not_called()
    manifest.assert_not_called()
    m.assert_not_called()


def test_finish_returns_empty_dict():
    ar, _, manifest = _archives()
    assert ar.finish(manifest) == {}


def test_ids_empty():
    ar, _, _ = _archives()
    assert list(ar.ids()) == []


def test_ids_returns_binary_ids():
    ar, repo, _ = _archives()
    repo.store_list.return_value = [_iteminfo(_id(1)), _iteminfo(_id(2))]
    assert list(ar.ids()) == [_id(1), _id(2)]


def test_ids_store_object_not_found_gives_empty():
    ar, repo, _ = _archives()
    repo.store_list.side_effect = StoreObjectNotFound("archives")
    assert list(ar.ids()) == []


def test_ids_passes_deleted_flag():
    ar, repo, _ = _archives()
    repo.store_list.return_value = [_iteminfo(_id(1))]
    result = list(ar.ids(deleted=True))
    assert result == [_id(1)]
    repo.store_list.assert_called_once_with("archives", deleted=True)


def test_count_empty():
    ar, _, _ = _archives()
    assert ar.count() == 0


def test_count():
    ar, repo, _ = _archives()
    repo.store_list.return_value = [_iteminfo(_id(1)), _iteminfo(_id(2))]
    assert ar.count() == 2


def test_names():
    ar, _, _ = _archives()
    metas = [_archive_meta("a", _id(1)), _archive_meta("b", _id(2))]
    ar._infos = Mock(side_effect=lambda deleted=False: iter(metas))
    assert list(ar.names()) == ["a", "b"]


def test_exists_true():
    ar, _, _ = _archives()
    ar._infos = Mock(side_effect=lambda deleted=False: iter([_archive_meta("a", _id(1))]))
    assert ar.exists("a") is True


def test_exists_false():
    ar, _, _ = _archives()
    ar._infos = Mock(side_effect=lambda deleted=False: iter([]))
    assert ar.exists("missing") is False


def test_exists_id_true():
    ar, repo, _ = _archives()
    repo.store_list.return_value = [_iteminfo(_id(1))]
    assert ar.exists_id(_id(1)) is True


def test_exists_id_false():
    ar, repo, _ = _archives()
    repo.store_list.return_value = []
    assert ar.exists_id(_id(99)) is False


def test_exists_id_deleted():
    ar, repo, _ = _archives()
    repo.store_list.return_value = [_iteminfo(_id(1))]
    assert ar.exists_id(_id(1), deleted=True) is True
    repo.store_list.assert_called_with("archives", deleted=True)


def test_exists_name_and_id_true():
    ar, _, _ = _archives()
    ar._infos = Mock(side_effect=lambda deleted=False: iter([_archive_meta("a", _id(1))]))
    assert ar.exists_name_and_id("a", _id(1)) is True


def test_exists_name_and_id_false_wrong_name():
    ar, _, _ = _archives()
    ar._infos = Mock(side_effect=lambda deleted=False: iter([_archive_meta("a", _id(1))]))
    assert ar.exists_name_and_id("b", _id(1)) is False


def test_exists_name_and_id_false_wrong_id():
    ar, _, _ = _archives()
    ar._infos = Mock(side_effect=lambda deleted=False: iter([_archive_meta("a", _id(1))]))
    assert ar.exists_name_and_id("a", _id(2)) is False


def test_exists_name_and_ts_true():
    ar, _, _ = _archives()
    ar._info_tuples = Mock(side_effect=lambda deleted=False: iter([_archiveinfo("a", _id(1))]))
    assert ar.exists_name_and_ts("a", parse_timestamp(TS)) is True


def test_exists_name_and_ts_false_wrong_ts():
    ar, _, _ = _archives()
    ar._info_tuples = Mock(side_effect=lambda deleted=False: iter([_archiveinfo("a", _id(1))]))
    assert ar.exists_name_and_ts("a", parse_timestamp(TS2)) is False


def test_exists_name_and_ts_false_wrong_name():
    ar, _, _ = _archives()
    ar._info_tuples = Mock(side_effect=lambda deleted=False: iter([_archiveinfo("a", _id(1))]))
    assert ar.exists_name_and_ts("b", parse_timestamp(TS)) is False


def test_get_archive_meta_object_not_found():
    ar, repo, _ = _archives()
    repo.get.side_effect = Repository.ObjectNotFound(_id(1), "/fake/path")
    result = ar._get_archive_meta(_id(1))
    assert result == {
        "id": _id(1),
        "name": "archive-does-not-exist",
        "time": "1970-01-01T00:00:00.000000",
        "exists": False,
        "username": "",
        "hostname": "",
        "tags": (),
    }


def test_get_archive_meta_success():
    ar, _, manifest = _archives()
    manifest.repo_objs.parse.return_value = (None, b"data")
    manifest.key.unpack_archive.return_value = {
        "version": 2,
        "name": "myarchive",
        "time": "2021-03-15T10:00:00.000000",
        "username": "alice",
        "hostname": "myhost",
        "size": 1024,
        "nfiles": 3,
        "comment": "weekly",
    }

    result = ar._get_archive_meta(_id(1))

    assert result["exists"] is True
    assert result["id"] == _id(1)
    assert result["name"] == "myarchive"
    assert result["time"] == "2021-03-15T10:00:00.000000"
    assert result["username"] == "alice"
    assert result["hostname"] == "myhost"
    assert result["size"] == 1024
    assert result["nfiles"] == 3
    assert result["comment"] == "weekly"
    assert result["tags"] == ()


def test_get_archive_meta_success_with_tags():
    ar, _, manifest = _archives()
    manifest.repo_objs.parse.return_value = (None, b"data")
    manifest.key.unpack_archive.return_value = {
        "version": 2,
        "name": "tagged",
        "time": TS,
        "username": "",
        "hostname": "",
        "tags": ["beta", "alpha"],
    }

    result = ar._get_archive_meta(_id(1))

    assert result["tags"] == ("alpha", "beta")
    assert result["size"] == 0
    assert result["nfiles"] == 0
    assert result["comment"] == ""


def test_get_archive_meta_bad_version():
    ar, _, manifest = _archives()
    manifest.repo_objs.parse.return_value = (None, b"data")
    manifest.key.unpack_archive.return_value = {"version": 99}

    with pytest.raises(Exception, match="Unknown archive metadata version"):
        ar._get_archive_meta(_id(1))


def test_get_missing_returns_none():
    ar, _, _ = _archives()
    ar._infos = Mock(side_effect=lambda deleted=False: iter([]))
    assert ar.get("nope") is None


def test_get_returns_archive_archiveinfo():
    ar, _, _ = _archives()
    ar._infos = Mock(side_effect=lambda deleted=False: iter([_archive_meta("a", _id(1))]))
    info = ar.get("a")
    assert isinstance(info, ArchiveInfo)
    assert info.name == "a"
    assert info.id == _id(1)


def test_get_raw():
    ar, _, _ = _archives()
    ar._infos = Mock(side_effect=lambda deleted=False: iter([_archive_meta("a", _id(1))]))
    result = ar.get("a", raw=True)
    assert result["name"] == "a"
    assert result["id"] == _id(1)
    assert result["time"] == TS
    assert result["exists"] is True


def test_get_by_id_missing_returns_none():
    ar, repo, _ = _archives()
    repo.store_list.return_value = []
    assert ar.get_by_id(_id(99)) is None


@pytest.mark.parametrize("raw", [False, True])
def test_get_by_id(raw):
    ar, repo, _ = _archives()
    repo.store_list.return_value = [_iteminfo(_id(1))]
    ar._get_archive_meta = Mock(side_effect=lambda id_: _archive_meta("a", _id(1)))
    result = ar.get_by_id(_id(1), raw=raw)
    if raw:
        assert result["name"] == "a"
        assert result["id"] == _id(1)
        assert result["time"] == TS
        assert result["exists"] is True
    else:
        assert isinstance(result, ArchiveInfo)
        assert result.name == "a"
        assert result.id == _id(1)


def test_get_by_id_exists_false_returns_none():
    ar, repo, _ = _archives()
    repo.store_list.return_value = [_iteminfo(_id(1))]
    meta = _archive_meta("a", _id(1))
    meta["exists"] = False
    ar._get_archive_meta = Mock(side_effect=lambda id_: meta)
    assert ar.get_by_id(_id(1)) is None


def test_get_by_id_deleted():
    ar, repo, _ = _archives()
    repo.store_list.return_value = [_iteminfo(_id(1))]
    ar._get_archive_meta = Mock(side_effect=lambda id_: _archive_meta("a", _id(1)))
    info = ar.get_by_id(_id(1), deleted=True)
    assert isinstance(info, ArchiveInfo)
    repo.store_list.assert_called_with("archives", deleted=True)


def test_create_calls_store_store():
    ar, repo, _ = _archives()
    ar.create("a", _id(1), TS)
    repo.store_store.assert_called_once_with(f"archives/{bin_to_hex(_id(1))}", b"")


def test_create_with_datetime_ts():
    ar, repo, _ = _archives()
    dt = datetime(2020, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    ar.create("a", _id(1), dt)
    repo.store_store.assert_called_once_with(f"archives/{bin_to_hex(_id(1))}", b"")


def test_create_overwrite_kwarg_ignored():
    # borgstore store_store is ID-addressed and idempotent; overwrite is an ArchivesInterface
    # compatibility parameter that Archives intentionally ignores (unlike LegacyArchives).
    ar, repo, _ = _archives()
    ar.create("a", _id(1), TS, overwrite=True)
    repo.store_store.assert_called_once_with(f"archives/{bin_to_hex(_id(1))}", b"")


def test_delete_by_id():
    ar, repo, _ = _archives()
    ar.delete_by_id(_id(1))
    repo.store_move.assert_called_once_with(f"archives/{bin_to_hex(_id(1))}", delete=True)


def test_undelete_by_id():
    ar, repo, _ = _archives()
    ar.undelete_by_id(_id(1))
    repo.store_move.assert_called_once_with(f"archives/{bin_to_hex(_id(1))}", undelete=True)


def test_nuke_by_id():
    ar, repo, _ = _archives()
    ar.nuke_by_id(_id(1))
    repo.store_delete.assert_called_once_with(f"archives/{bin_to_hex(_id(1))}", deleted=True)


def test_list_no_filters():
    info = _archiveinfo("a", _id(1))
    ar = _stub_matching_info_tuples([info])
    assert ar.list() == [info]


def test_list_sort_by_str_raises():
    ar, _, _ = _archives()
    with pytest.raises(TypeError, match="sort_by must be a sequence"):
        ar.list(sort_by="name")


def test_list_sort_generator_not_materialised_regression():
    # _matching_info_tuples must materialise _info_tuples() via list() before returning;
    # if that list() call is removed, the raw generator reaches .sort() and raises AttributeError.
    ar = _stub_info_tuples([])
    assert ar.list(sort_by=["name"]) == []


def test_list_sort_by():
    i1 = _archiveinfo("b", _id(2), TS2)
    i2 = _archiveinfo("a", _id(1), TS)
    ar = _stub_matching_info_tuples([i1, i2])
    result = ar.list(sort_by=["name"])
    assert result == [i2, i1]


def test_list_reverse():
    i1 = _archiveinfo("a", _id(1))
    i2 = _archiveinfo("b", _id(2))
    ar = _stub_matching_info_tuples([i1, i2])
    assert ar.list(reverse=True) == [i2, i1]


def test_list_first():
    infos = [_archiveinfo(f"a{i}", _id(i + 1)) for i in range(5)]
    ar = _stub_matching_info_tuples(infos)
    assert ar.list(first=3) == infos[:3]


def test_list_last():
    infos = [_archiveinfo(f"a{i}", _id(i + 1)) for i in range(5)]
    ar = _stub_matching_info_tuples(infos)
    assert ar.list(last=2) == infos[-2:]


def test_list_first_zero():
    infos = [_archiveinfo(f"a{i}", _id(i + 1)) for i in range(3)]
    ar = _stub_matching_info_tuples(infos)
    assert ar.list(first=0) == infos


def test_list_last_zero():
    infos = [_archiveinfo(f"a{i}", _id(i + 1)) for i in range(3)]
    ar = _stub_matching_info_tuples(infos)
    assert ar.list(last=0) == infos


def test_list_date_filter():
    i1 = _archiveinfo("a", _id(1))
    ar = _stub_matching_info_tuples([i1])
    with patch("borg.manifest.filter_archives_by_date", return_value=[i1]) as mock_filter:
        result = ar.list(older="1d")
    assert result == [i1]
    mock_filter.assert_called_once_with([i1], oldest=None, newest=None, newer=None, older="1d")


def test_list_deleted_passes_flag():
    ar, _, _ = _archives()
    ar._info_tuples = Mock(side_effect=lambda deleted=False: iter([]))
    ar.list(deleted=True)
    ar._info_tuples.assert_called_once_with(deleted=True)


def test_list_match_name():
    i1 = _archiveinfo("archive-a", _id(1))
    i2 = _archiveinfo("archive-b", _id(2))
    ar = _stub_info_tuples([i1, i2])
    assert ar.list(match=["archive-a"]) == [i1]


def test_list_match_name_prefix():
    i1 = _archiveinfo("archive-a", _id(1))
    i2 = _archiveinfo("other", _id(2))
    ar = _stub_info_tuples([i1, i2])
    assert ar.list(match=["name:archive-a"]) == [i1]


def test_list_match_user():
    i1 = _archiveinfo("a", _id(1), username="alice")
    i2 = _archiveinfo("b", _id(2), username="bob")
    ar = _stub_info_tuples([i1, i2])
    assert ar.list(match=["user:alice"]) == [i1]


def test_list_match_host():
    i1 = _archiveinfo("a", _id(1), hostname="laptop")
    i2 = _archiveinfo("b", _id(2), hostname="server")
    ar = _stub_info_tuples([i1, i2])
    assert ar.list(match=["host:laptop"]) == [i1]


def test_list_match_tags():
    i1 = _archiveinfo("a", _id(1), tags=("prod", "db"))
    i2 = _archiveinfo("b", _id(2), tags=("dev",))
    ar = _stub_info_tuples([i1, i2])
    assert ar.list(match=["tags:prod"]) == [i1]


def test_list_match_aid():
    i1 = _archiveinfo("a", _id(1))
    ar = _stub_info_tuples([i1])
    prefix = bin_to_hex(_id(1))[:4]
    assert ar.list(match=[f"aid:{prefix}"]) == [i1]


def test_list_match_aid_ambiguous():
    # Two distinct IDs that share the same leading byte — a realistic prefix collision.
    id1 = bytes([0x01, 0x00]) + bytes(30)
    id2 = bytes([0x01, 0x01]) + bytes(30)
    i1 = _archiveinfo("a", id1)
    i2 = _archiveinfo("b", id2)
    ar = _stub_info_tuples([i1, i2])
    prefix = bin_to_hex(id1)[:2]  # "01" — matches both IDs
    with pytest.raises(CommandError, match=r"precisely one"):
        ar.list(match=[f"aid:{prefix}"])


def test_list_match_multiple_patterns():
    i1 = _archiveinfo("archive-a", _id(1), username="alice", hostname="laptop")
    i2 = _archiveinfo("archive-b", _id(2), username="alice", hostname="server")
    i3 = _archiveinfo("archive-c", _id(3), username="bob", hostname="laptop")
    ar = _stub_info_tuples([i1, i2, i3])
    result = ar.list(match=["user:alice", "host:laptop"])
    assert result == [i1]


def test_list_match_end_custom():
    i1 = _archiveinfo("archive-a", _id(1))
    i2 = _archiveinfo("other", _id(2))
    ar = _stub_info_tuples([i1, i2])
    result = ar.list(match=["archive"], match_end="")
    assert result == [i1]


def test_get_one_exact_match():
    i1 = _archiveinfo("backup", _id(1))
    ar = _stub_info_tuples([i1])
    assert ar.get_one(["backup"]) == i1


def test_get_one_no_match_raises():
    ar = _stub_info_tuples([])
    with pytest.raises(CommandError, match=r"matched 0\."):
        ar.get_one(["missing"])


def test_get_one_multiple_matches_raises():
    i1 = _archiveinfo("a", _id(1))
    i2 = _archiveinfo("a", _id(2))
    ar = _stub_info_tuples([i1, i2])
    with pytest.raises(CommandError, match=r"matched 2\."):
        ar.get_one(["a"])


def test_get_one_deleted_passes_flag():
    i1 = _archiveinfo("a", _id(1))
    ar, _, _ = _archives()
    ar._info_tuples = Mock(side_effect=lambda deleted=False: iter([i1]))
    ar.get_one(["a"], deleted=True)
    ar._info_tuples.assert_called_once_with(deleted=True)


def test_list_considering_raises_if_name_set():
    ar, _, _ = _archives()
    args = Mock()
    args.name = "archive"
    with pytest.raises(Error):
        ar.list_considering(args)


def test_list_considering_delegates():
    i1 = _archiveinfo("b", _id(2), TS2)
    i2 = _archiveinfo("a", _id(1), TS)
    ar = _stub_matching_info_tuples([i1, i2])
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
    result = ar.list_considering(args)
    assert result == [i2, i1]


def test_list_considering_with_match_archives():
    i1 = _archiveinfo("archive-a", _id(1))
    i2 = _archiveinfo("other", _id(2))
    ar = _stub_info_tuples([i1, i2])
    args = Namespace(
        name=None,
        sort_by="name",
        match_archives=["archive-a"],
        first=None,
        last=None,
        older=None,
        newer=None,
        oldest=None,
        newest=None,
        deleted=False,
    )
    result = ar.list_considering(args)
    assert result == [i1]


def test_list_considering_multi_key_sort():
    i1 = _archiveinfo("b", _id(1), TS2)
    i2 = _archiveinfo("a", _id(2), TS2)
    i3 = _archiveinfo("c", _id(3), TS)
    ar = _stub_matching_info_tuples([i1, i2, i3])
    args = Namespace(
        name=None,
        sort_by="ts,name",
        match_archives=None,
        first=None,
        last=None,
        older=None,
        newer=None,
        oldest=None,
        newest=None,
        deleted=False,
    )
    result = ar.list_considering(args)
    assert result == [i3, i2, i1]

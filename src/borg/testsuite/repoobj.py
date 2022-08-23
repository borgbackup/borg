import pytest

from ..crypto.key import PlaintextKey
from ..repository import Repository
from ..repoobj import RepoObj, RepoObj1


@pytest.fixture
def repository(tmpdir):
    return Repository(tmpdir, create=True)


@pytest.fixture
def key(repository):
    return PlaintextKey(repository)


def test_format_parse_roundtrip(key):
    repo_objs = RepoObj(key)
    data = b"foobar" * 10
    id = repo_objs.id_hash(data)
    meta = {"custom": "something"}  # size and csize are computed automatically
    cdata = repo_objs.format(id, meta, data)

    got_meta = repo_objs.parse_meta(id, cdata)
    assert got_meta["size"] == len(data)
    assert got_meta["csize"] < len(data)
    assert got_meta["custom"] == "something"

    got_meta, got_data = repo_objs.parse(id, cdata)
    assert got_meta["size"] == len(data)
    assert got_meta["csize"] < len(data)
    assert got_meta["custom"] == "something"
    assert data == got_data

    edata = repo_objs.extract_crypted_data(cdata)
    compressor = repo_objs.compressor
    key = repo_objs.key
    assert edata.startswith(bytes((key.TYPE, compressor.ID[0], compressor.level)))


def test_format_parse_roundtrip_borg1(key):  # legacy
    repo_objs = RepoObj1(key)
    data = b"foobar" * 10
    id = repo_objs.id_hash(data)
    meta = {}  # borg1 does not support this kind of metadata
    cdata = repo_objs.format(id, meta, data)

    # borg1 does not support separate metadata and borg2 does not invoke parse_meta for borg1 repos

    got_meta, got_data = repo_objs.parse(id, cdata)
    assert got_meta["size"] == len(data)
    assert got_meta["csize"] < len(data)
    assert data == got_data

    edata = repo_objs.extract_crypted_data(cdata)
    compressor = repo_objs.compressor
    key = repo_objs.key
    assert edata.startswith(bytes((key.TYPE, compressor.ID[0], compressor.level)))

import os
import sys
from hashlib import sha256

import pytest
from ..constants import ROBJ_FILE_STREAM
from ..helpers import IntegrityError, Location
from ..repository import Repository, MAX_DATA_SIZE, cache_if_remote, rest_serve_command, PackWriter
from ..repoobj import RepoObj, OBJ_MAGIC, OBJ_VERSION
from ..crypto.key import PlaintextKey
from .hashindex_test import H
from .crypto.key_test import TestKey


def test_rest_serve_command_local():
    # rest:// without a host runs "borg serve --rest" locally, talking over stdio.
    cmd = rest_serve_command(Location("rest:////tmp/repo"))
    assert "ssh" not in cmd
    assert cmd[0] == sys.executable
    assert cmd[-4:] == ["serve", "--rest", "--backend", "FILE:/tmp/repo"]


def test_rest_serve_command_ssh(monkeypatch):
    # rest:// with a host is reached via ssh, running "borg serve --rest" remotely.
    monkeypatch.delenv("BORGSTORE_RSH", raising=False)
    monkeypatch.delenv("BORG_REMOTE_PATH", raising=False)
    cmd = rest_serve_command(Location("rest://user@host:2222/repo/path"))
    assert cmd[:4] == ["ssh", "-p", "2222", "user@host"]
    assert cmd[4:] == ["borg", "serve", "--rest", "--backend", "FILE:repo/path"]


@pytest.fixture()
def repository(tmp_path):
    repository_location = os.fspath(tmp_path / "repository")
    yield Repository(repository_location, exclusive=True, create=True)


def pytest_generate_tests(metafunc):
    # Generate tests that run on repositories.
    if "repo_fixtures" in metafunc.fixturenames:
        metafunc.parametrize("repo_fixtures", ["repository"])


def get_repository_from_fixture(repo_fixtures, request):
    # Return the repository object from the fixture.
    return request.getfixturevalue(repo_fixtures)


def reopen(repository, exclusive: bool | None = True, create=False):
    if isinstance(repository, Repository):
        if repository.opened:
            raise RuntimeError("Repo must be closed before a reopen. Cannot support nested repository contexts.")
        return Repository(repository._location, exclusive=exclusive, create=create)

    raise TypeError(f"Invalid argument type. Expected 'Repository', received '{type(repository).__name__}'.")


def fchunk(data, meta=b"", chunk_id=b"\x00" * 32):
    # Format chunk: create a raw chunk that has a valid RepoObj layout, but does not use encryption or compression.
    hdr = RepoObj.obj_header.pack(OBJ_MAGIC, OBJ_VERSION, chunk_id, len(meta), len(data))
    assert isinstance(data, bytes)
    chunk = hdr + meta + data
    return chunk


def pchunk(chunk):
    # Parse chunk: extract data and metadata from a raw chunk made by fchunk.
    hdr_size = RepoObj.obj_header.size
    hdr = chunk[:hdr_size]
    meta_size, data_size = RepoObj.obj_header.unpack(hdr)[3:5]
    meta = chunk[hdr_size : hdr_size + meta_size]
    data = chunk[hdr_size + meta_size : hdr_size + meta_size + data_size]
    return data, meta


def pdchunk(chunk):
    # Parse only the data from a raw chunk made by fchunk.
    return pchunk(chunk)[0]


def test_basic_operations(repo_fixtures, request):
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        for x in range(100):
            repository.put(H(x), fchunk(b"SOMEDATA"))
        key50 = H(50)
        assert pdchunk(repository.get(key50)) == b"SOMEDATA"
        repository.delete(key50)
        with pytest.raises(Repository.ObjectNotFound):
            repository.get(key50)
    with reopen(repository) as repository:
        with pytest.raises(Repository.ObjectNotFound):
            repository.get(key50)
        for x in range(100):
            if x == 50:
                continue
            assert pdchunk(repository.get(H(x))) == b"SOMEDATA"


def test_read_data(repo_fixtures, request):
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        meta, data = b"meta", b"data"
        hdr = RepoObj.obj_header.pack(OBJ_MAGIC, OBJ_VERSION, H(0), len(meta), len(data))
        chunk_complete = hdr + meta + data
        chunk_short = hdr + meta
        repository.put(H(0), chunk_complete)
        assert repository.get(H(0)) == chunk_complete
        assert repository.get(H(0), read_data=True) == chunk_complete
        assert repository.get(H(0), read_data=False) == chunk_short


def test_consistency(repo_fixtures, request):
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        repository.put(H(0), fchunk(b"foo"))
        assert pdchunk(repository.get(H(0))) == b"foo"
        repository.put(H(0), fchunk(b"foo2"))
        assert pdchunk(repository.get(H(0))) == b"foo2"
        repository.put(H(0), fchunk(b"bar"))
        assert pdchunk(repository.get(H(0))) == b"bar"
        repository.delete(H(0))
        with pytest.raises(Repository.ObjectNotFound):
            repository.get(H(0))


def test_list(repo_fixtures, request):
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        for x in range(100):
            repository.put(H(x), fchunk(b"SOMEDATA"))
        repo_list = repository.list()
        assert len(repo_list) == 100
        first_half = repository.list(limit=50)
        assert len(first_half) == 50
        assert first_half == repo_list[:50]
        second_half = repository.list(marker=first_half[-1][0])
        assert len(second_half) == 50
        assert second_half == repo_list[50:]
        assert len(repository.list(limit=50)) == 50


def test_max_data_size(repo_fixtures, request):
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        max_data = b"x" * (MAX_DATA_SIZE - RepoObj.obj_header.size)
        repository.put(H(0), fchunk(max_data))
        assert pdchunk(repository.get(H(0))) == max_data
        with pytest.raises(IntegrityError):
            repository.put(H(1), fchunk(max_data + b"x"))
        repository.delete(H(0))


def check(repository, repo_path, repair=False, status=True):
    assert repository.check(repair=repair) == status
    # Make sure no tmp files are left behind
    tmp_files = [name for name in os.listdir(repo_path) if "tmp" in name]
    assert tmp_files == [], "Found tmp files"


class TestCacheIfRemote:
    @pytest.fixture
    def cache_repository(self, tmpdir):
        repository_location = os.path.join(str(tmpdir), "repository")
        with Repository(repository_location, exclusive=True, create=True) as repository:
            repository.put(H(1), fchunk(b"1234"))
            repository.put(H(2), fchunk(b"5678"))
            repository.put(H(3), fchunk(bytes(100)))
            yield repository

    def test_passthrough(self, cache_repository):
        # Without decrypted_cache, raw repository data is passed through unchanged.
        with cache_if_remote(cache_repository) as cached:
            assert pdchunk(cached.get(H(1))) == b"1234"
            assert [pdchunk(ch) for ch in cached.get_many([H(1), H(2)])] == [b"1234", b"5678"]

    @pytest.fixture
    def key(self, cache_repository, monkeypatch):
        monkeypatch.setenv("BORG_PASSPHRASE", "test")
        return PlaintextKey.create(cache_repository, TestKey.MockArgs())

    @pytest.fixture
    def repo_objs(self, key):
        return RepoObj(key)

    def _put_encrypted_object(self, repo_objs, repository, data):
        id_ = repo_objs.id_hash(data)
        repository.put(id_, repo_objs.format(id_, {}, data, ro_type=ROBJ_FILE_STREAM))
        return id_

    @pytest.fixture
    def H1(self, repo_objs, cache_repository):
        return self._put_encrypted_object(repo_objs, cache_repository, b"1234")

    @pytest.fixture
    def H2(self, repo_objs, cache_repository):
        return self._put_encrypted_object(repo_objs, cache_repository, b"5678")

    def test_decrypted_cache(self, repo_objs, cache_repository, H1, H2):
        # With decrypted_cache, get/get_many return (csize, plaintext) tuples.
        with cache_if_remote(cache_repository, decrypted_cache=repo_objs) as cached:
            csize, plaintext = cached.get(H1)
            assert plaintext == b"1234"
            assert [pt for _csize, pt in cached.get_many([H1, H2])] == [b"1234", b"5678"]

    def test_decrypted_cache_and_transform_incompatible(self, cache_repository, repo_objs):
        with pytest.raises(ValueError):
            cache_if_remote(cache_repository, decrypted_cache=repo_objs, transform=lambda key, data: data)


class MockStore:
    def __init__(self):
        self.stored = {}

    def store(self, key, data):
        self.stored[key] = data


def test_pack_writer_returns_none_when_not_full():
    pw = PackWriter(MockStore(), max_count=2)
    assert pw.add(b"a" * 32, b"data") is None


def test_pack_writer_flush_returns_none_when_empty():
    pw = PackWriter(MockStore(), max_count=1)
    assert pw.flush() is None


def test_pack_writer_n1_flush():
    store = MockStore()
    chunk_id = b"c" * 32
    cdata = b"payload"
    pw = PackWriter(store, max_count=1)
    results = pw.add(chunk_id, cdata)
    assert results is not None
    assert len(results) == 1
    stored_id, pack_id, obj_offset, obj_size = results[0]
    assert stored_id == chunk_id
    assert pack_id == chunk_id  # N=1: pack_id == chunk_id
    assert obj_offset == 0
    assert obj_size == len(cdata)


def test_pack_writer_n2_flush():
    store = MockStore()
    id1, id2 = b"a" * 32, b"b" * 32
    data1, data2 = b"first", b"second"
    pw = PackWriter(store, max_count=2)
    assert pw.add(id1, data1) is None
    results = pw.add(id2, data2)
    assert results is not None
    assert len(results) == 2
    pack_data = data1 + data2
    expected_pack_id = sha256(pack_data).digest()
    assert results[0] == (id1, expected_pack_id, 0, len(data1))
    assert results[1] == (id2, expected_pack_id, len(data1), len(data2))


def test_pack_writer_final_partial_pack_uses_sha256():
    # When max_count > 1, a final flush with only 1 piece must still use SHA256,
    # not the N=1 pack_id == chunk_id hack.
    store = MockStore()
    chunk_id = b"d" * 32
    cdata = b"solo"
    pw = PackWriter(store, max_count=3)
    assert pw.add(chunk_id, cdata) is None
    results = pw.flush()
    assert results is not None
    assert len(results) == 1
    _, pack_id, _, _ = results[0]
    assert pack_id == sha256(cdata).digest()
    assert pack_id != chunk_id

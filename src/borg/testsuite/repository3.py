import logging
import os
import sys
from typing import Optional

import pytest

from ..helpers import Location
from ..helpers import IntegrityError
from ..platformflags import is_win32
from ..remote3 import RemoteRepository3, InvalidRPCMethod, PathNotAllowed
from ..repository3 import Repository3, MAX_DATA_SIZE
from ..repoobj import RepoObj
from .hashindex import H


@pytest.fixture()
def repository(tmp_path):
    repository_location = os.fspath(tmp_path / "repository")
    yield Repository3(repository_location, exclusive=True, create=True)


@pytest.fixture()
def remote_repository(tmp_path):
    if is_win32:
        pytest.skip("Remote repository does not yet work on Windows.")
    repository_location = Location("ssh://__testsuite__" + os.fspath(tmp_path / "repository"))
    yield RemoteRepository3(repository_location, exclusive=True, create=True)


def pytest_generate_tests(metafunc):
    # Generates tests that run on both local and remote repos
    if "repo_fixtures" in metafunc.fixturenames:
        metafunc.parametrize("repo_fixtures", ["repository", "remote_repository"])


def get_repository_from_fixture(repo_fixtures, request):
    # returns the repo object from the fixture for tests that run on both local and remote repos
    return request.getfixturevalue(repo_fixtures)


def reopen(repository, exclusive: Optional[bool] = True, create=False):
    if isinstance(repository, Repository3):
        if repository.opened:
            raise RuntimeError("Repo must be closed before a reopen. Cannot support nested repository contexts.")
        return Repository3(repository.path, exclusive=exclusive, create=create)

    if isinstance(repository, RemoteRepository3):
        if repository.p is not None or repository.sock is not None:
            raise RuntimeError("Remote repo must be closed before a reopen. Cannot support nested repository contexts.")
        return RemoteRepository3(repository.location, exclusive=exclusive, create=create)

    raise TypeError(
        f"Invalid argument type. Expected 'Repository3' or 'RemoteRepository3', received '{type(repository).__name__}'."
    )


def fchunk(data, meta=b""):
    # format chunk: create a raw chunk that has valid RepoObj layout, but does not use encryption or compression.
    meta_len = RepoObj.meta_len_hdr.pack(len(meta))
    assert isinstance(data, bytes)
    chunk = meta_len + meta + data
    return chunk


def pchunk(chunk):
    # parse chunk: parse data and meta from a raw chunk made by fchunk
    meta_len_size = RepoObj.meta_len_hdr.size
    meta_len = chunk[:meta_len_size]
    meta_len = RepoObj.meta_len_hdr.unpack(meta_len)[0]
    meta = chunk[meta_len_size : meta_len_size + meta_len]
    data = chunk[meta_len_size + meta_len :]
    return data, meta


def pdchunk(chunk):
    # parse only data from a raw chunk made by fchunk
    return pchunk(chunk)[0]


def test_basic_operations(repo_fixtures, request):
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        for x in range(100):
            repository.put(H(x), fchunk(b"SOMEDATA"))
        key50 = H(50)
        assert pdchunk(repository.get(key50)) == b"SOMEDATA"
        repository.delete(key50)
        with pytest.raises(Repository3.ObjectNotFound):
            repository.get(key50)
    with reopen(repository) as repository:
        with pytest.raises(Repository3.ObjectNotFound):
            repository.get(key50)
        for x in range(100):
            if x == 50:
                continue
            assert pdchunk(repository.get(H(x))) == b"SOMEDATA"


def test_read_data(repo_fixtures, request):
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        meta, data = b"meta", b"data"
        meta_len = RepoObj.meta_len_hdr.pack(len(meta))
        chunk_complete = meta_len + meta + data
        chunk_short = meta_len + meta
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
        with pytest.raises(Repository3.ObjectNotFound):
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
        second_half = repository.list(marker=first_half[-1])
        assert len(second_half) == 50
        assert second_half == repo_list[50:]
        assert len(repository.list(limit=50)) == 50


def test_scan(repo_fixtures, request):
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        for x in range(100):
            repository.put(H(x), fchunk(b"SOMEDATA"))
        ids, _ = repository.scan()
        assert len(ids) == 100
        first_half, state = repository.scan(limit=50)
        assert len(first_half) == 50
        assert first_half == ids[:50]
        second_half, _ = repository.scan(state=state)
        assert len(second_half) == 50
        assert second_half == ids[50:]


def test_max_data_size(repo_fixtures, request):
    with get_repository_from_fixture(repo_fixtures, request) as repository:
        max_data = b"x" * (MAX_DATA_SIZE - RepoObj.meta_len_hdr.size)
        repository.put(H(0), fchunk(max_data))
        assert pdchunk(repository.get(H(0))) == max_data
        with pytest.raises(IntegrityError):
            repository.put(H(1), fchunk(max_data + b"x"))


def check(repository, repo_path, repair=False, status=True):
    assert repository.check(repair=repair) == status
    # Make sure no tmp files are left behind
    tmp_files = [name for name in os.listdir(repo_path) if "tmp" in name]
    assert tmp_files == [], "Found tmp files"


def _get_mock_args():
    class MockArgs:
        remote_path = "borg"
        umask = 0o077
        debug_topics = []
        rsh = None

        def __contains__(self, item):
            # to behave like argparse.Namespace
            return hasattr(self, item)

    return MockArgs()


def test_remote_invalid_rpc(remote_repository):
    with remote_repository:
        with pytest.raises(InvalidRPCMethod):
            remote_repository.call("__init__", {})


def test_remote_rpc_exception_transport(remote_repository):
    with remote_repository:
        s1 = "test string"

        try:
            remote_repository.call("inject_exception", {"kind": "DoesNotExist"})
        except Repository3.DoesNotExist as e:
            assert len(e.args) == 1
            assert e.args[0] == remote_repository.location.processed

        try:
            remote_repository.call("inject_exception", {"kind": "AlreadyExists"})
        except Repository3.AlreadyExists as e:
            assert len(e.args) == 1
            assert e.args[0] == remote_repository.location.processed

        try:
            remote_repository.call("inject_exception", {"kind": "CheckNeeded"})
        except Repository3.CheckNeeded as e:
            assert len(e.args) == 1
            assert e.args[0] == remote_repository.location.processed

        try:
            remote_repository.call("inject_exception", {"kind": "IntegrityError"})
        except IntegrityError as e:
            assert len(e.args) == 1
            assert e.args[0] == s1

        try:
            remote_repository.call("inject_exception", {"kind": "PathNotAllowed"})
        except PathNotAllowed as e:
            assert len(e.args) == 1
            assert e.args[0] == "foo"

        try:
            remote_repository.call("inject_exception", {"kind": "ObjectNotFound"})
        except Repository3.ObjectNotFound as e:
            assert len(e.args) == 2
            assert e.args[0] == s1
            assert e.args[1] == remote_repository.location.processed

        try:
            remote_repository.call("inject_exception", {"kind": "InvalidRPCMethod"})
        except InvalidRPCMethod as e:
            assert len(e.args) == 1
            assert e.args[0] == s1

        try:
            remote_repository.call("inject_exception", {"kind": "divide"})
        except RemoteRepository3.RPCError as e:
            assert e.unpacked
            assert e.get_message() == "ZeroDivisionError: integer division or modulo by zero\n"
            assert e.exception_class == "ZeroDivisionError"
            assert len(e.exception_full) > 0


def test_remote_ssh_cmd(remote_repository):
    with remote_repository:
        args = _get_mock_args()
        remote_repository._args = args
        assert remote_repository.ssh_cmd(Location("ssh://example.com/foo")) == ["ssh", "example.com"]
        assert remote_repository.ssh_cmd(Location("ssh://user@example.com/foo")) == ["ssh", "user@example.com"]
        assert remote_repository.ssh_cmd(Location("ssh://user@example.com:1234/foo")) == [
            "ssh",
            "-p",
            "1234",
            "user@example.com",
        ]
        os.environ["BORG_RSH"] = "ssh --foo"
        assert remote_repository.ssh_cmd(Location("ssh://example.com/foo")) == ["ssh", "--foo", "example.com"]


def test_remote_borg_cmd(remote_repository):
    with remote_repository:
        assert remote_repository.borg_cmd(None, testing=True) == [sys.executable, "-m", "borg", "serve"]
        args = _get_mock_args()
        # XXX without next line we get spurious test fails when using pytest-xdist, root cause unknown:
        logging.getLogger().setLevel(logging.INFO)
        # note: test logger is on info log level, so --info gets added automagically
        assert remote_repository.borg_cmd(args, testing=False) == ["borg", "serve", "--info"]
        args.remote_path = "borg-0.28.2"
        assert remote_repository.borg_cmd(args, testing=False) == ["borg-0.28.2", "serve", "--info"]
        args.debug_topics = ["something_client_side", "repository_compaction"]
        assert remote_repository.borg_cmd(args, testing=False) == [
            "borg-0.28.2",
            "serve",
            "--info",
            "--debug-topic=borg.debug.repository_compaction",
        ]
        args = _get_mock_args()
        args.storage_quota = 0
        assert remote_repository.borg_cmd(args, testing=False) == ["borg", "serve", "--info"]
        args.storage_quota = 314159265
        assert remote_repository.borg_cmd(args, testing=False) == [
            "borg",
            "serve",
            "--info",
            "--storage-quota=314159265",
        ]
        args.rsh = "ssh -i foo"
        remote_repository._args = args
        assert remote_repository.ssh_cmd(Location("ssh://example.com/foo")) == ["ssh", "-i", "foo", "example.com"]

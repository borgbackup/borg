"""
Do benchmarks using pytest-benchmark.

Usage:

    py.test --benchmark-only
"""

import os

import pytest

from .archiver import changedir, cmd_fixture  # NOQA
from .item_test import Item
from ..constants import zeros


@pytest.fixture
def repo_url(request, tmpdir, monkeypatch):
    monkeypatch.setenv("BORG_PASSPHRASE", "123456")
    monkeypatch.setenv("BORG_CHECK_I_KNOW_WHAT_I_AM_DOING", "YES")
    monkeypatch.setenv("BORG_DELETE_I_KNOW_WHAT_I_AM_DOING", "YES")
    monkeypatch.setenv("BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK", "yes")
    monkeypatch.setenv("BORG_KEYS_DIR", str(tmpdir.join("keys")))
    monkeypatch.setenv("BORG_CACHE_DIR", str(tmpdir.join("cache")))
    yield str(tmpdir.join("repository"))
    tmpdir.remove(rec=1)


@pytest.fixture(params=["none", "repokey-aes-ocb"])
def repo(request, cmd_fixture, repo_url):
    cmd_fixture(f"--repo={repo_url}", "repo-create", "--encryption", request.param)
    return repo_url


@pytest.fixture(scope="session", params=["zeros", "random"])
def testdata(request, tmpdir_factory):
    count, size = 10, 1000 * 1000
    assert size <= len(zeros)
    p = tmpdir_factory.mktemp("data")
    data_type = request.param
    if data_type == "zeros":
        # do not use a binary zero (\0) to avoid sparse detection
        def data(size):
            return memoryview(zeros)[:size]

    elif data_type == "random":

        def data(size):
            return os.urandom(size)

    else:
        raise ValueError("data_type must be 'random' or 'zeros'.")
    for i in range(count):
        with open(str(p.join(str(i))), "wb") as f:
            f.write(data(size))
    yield str(p)
    p.remove(rec=1)


@pytest.fixture(params=["none", "lz4"])
def repo_archive(request, cmd_fixture, repo, testdata):
    archive = "test"
    cmd_fixture(f"--repo={repo}", "create", "--compression", request.param, archive, testdata)
    return repo, archive


def test_create_none(benchmark, cmd_fixture, repo, testdata):
    result, out = benchmark.pedantic(
        cmd_fixture, (f"--repo={repo}", "create", "--compression", "none", "test", testdata)
    )
    assert result == 0


def test_create_lz4(benchmark, cmd_fixture, repo, testdata):
    result, out = benchmark.pedantic(
        cmd_fixture, (f"--repo={repo}", "create", "--compression", "lz4", "test", testdata)
    )
    assert result == 0


def test_extract(benchmark, cmd_fixture, repo_archive, tmpdir):
    repo, archive = repo_archive
    with changedir(str(tmpdir)):
        result, out = benchmark.pedantic(cmd_fixture, (f"--repo={repo}", "extract", archive))
    assert result == 0


def test_delete(benchmark, cmd_fixture, repo_archive):
    repo, archive = repo_archive
    result, out = benchmark.pedantic(cmd_fixture, (f"--repo={repo}", "delete", "-a", archive))
    assert result == 0


def test_list(benchmark, cmd_fixture, repo_archive):
    repo, archive = repo_archive
    result, out = benchmark(cmd_fixture, f"--repo={repo}", "list", archive)
    assert result == 0


def test_info(benchmark, cmd_fixture, repo_archive):
    repo, archive = repo_archive
    result, out = benchmark(cmd_fixture, f"--repo={repo}", "info", "-a", archive)
    assert result == 0


def test_check(benchmark, cmd_fixture, repo_archive):
    repo, archive = repo_archive
    result, out = benchmark(cmd_fixture, f"--repo={repo}", "check")
    assert result == 0


def test_help(benchmark, cmd_fixture):
    result, out = benchmark(cmd_fixture, "help")
    assert result == 0


@pytest.mark.parametrize("type, key, value", [(Item, "size", 1000), (Item, "mode", 0x777), (Item, "deleted", False)])
def test_propdict_attributes(benchmark, type, key, value):
    propdict = type()

    def getattr_setattr(item, key, value):
        setattr(item, key, value)
        assert item.get(key) == value
        assert getattr(item, key) == value
        item.as_dict()

    benchmark(getattr_setattr, propdict, key, value)

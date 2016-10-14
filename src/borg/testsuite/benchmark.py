"""
Do benchmarks using pytest-benchmark.

Usage:

    py.test --benchmark-only
"""

import os

import pytest

from .archiver import changedir, cmd


@pytest.yield_fixture
def repo_url(request, tmpdir, monkeypatch):
    monkeypatch.setenv('BORG_PASSPHRASE', '123456')
    monkeypatch.setenv('BORG_CHECK_I_KNOW_WHAT_I_AM_DOING', 'YES')
    monkeypatch.setenv('BORG_DELETE_I_KNOW_WHAT_I_AM_DOING', 'YES')
    monkeypatch.setenv('BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK', 'yes')
    monkeypatch.setenv('BORG_KEYS_DIR', str(tmpdir.join('keys')))
    monkeypatch.setenv('BORG_CACHE_DIR', str(tmpdir.join('cache')))
    yield str(tmpdir.join('repository'))
    tmpdir.remove(rec=1)


@pytest.fixture(params=["none", "repokey"])
def repo(request, cmd, repo_url):
    cmd('init', '--encryption', request.param, repo_url)
    return repo_url


@pytest.yield_fixture(scope='session', params=["zeros", "random"])
def testdata(request, tmpdir_factory):
    count, size = 10, 1000*1000
    p = tmpdir_factory.mktemp('data')
    data_type = request.param
    if data_type == 'zeros':
        # do not use a binary zero (\0) to avoid sparse detection
        def data(size):
            return b'0' * size
    if data_type == 'random':
        def data(size):
            return os.urandom(size)
    for i in range(count):
        with open(str(p.join(str(i))), "wb") as f:
            f.write(data(size))
    yield str(p)
    p.remove(rec=1)


@pytest.fixture(params=['none', 'lz4'])
def archive(request, cmd, repo, testdata):
    archive_url = repo + '::test'
    cmd('create', '--compression', request.param, archive_url, testdata)
    return archive_url


def test_create_none(benchmark, cmd, repo, testdata):
    result, out = benchmark.pedantic(cmd, ('create', '--compression', 'none', repo + '::test', testdata))
    assert result == 0


def test_create_lz4(benchmark, cmd, repo, testdata):
    result, out = benchmark.pedantic(cmd, ('create', '--compression', 'lz4', repo + '::test', testdata))
    assert result == 0


def test_extract(benchmark, cmd, archive, tmpdir):
    with changedir(str(tmpdir)):
        result, out = benchmark.pedantic(cmd, ('extract', archive))
    assert result == 0


def test_delete(benchmark, cmd, archive):
    result, out = benchmark.pedantic(cmd, ('delete', archive))
    assert result == 0


def test_list(benchmark, cmd, archive):
    result, out = benchmark(cmd, 'list', archive)
    assert result == 0


def test_info(benchmark, cmd, archive):
    result, out = benchmark(cmd, 'info', archive)
    assert result == 0


def test_check(benchmark, cmd, archive):
    repo = archive.split('::')[0]
    result, out = benchmark(cmd, 'check', repo)
    assert result == 0


def test_help(benchmark, cmd):
    result, out = benchmark(cmd, 'help')
    assert result == 0

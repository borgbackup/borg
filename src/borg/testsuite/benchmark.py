"""
Do benchmarks using pytest-benchmark.

Usage:

    py.test --benchmark-only
"""

import os
from hashlib import sha256

import pytest

from .archiver import changedir, cmd
from .hashindex import ChunkIndex
from .hashindex import H
import borg.hashindex

bench_getitem = borg.hashindex.bench_getitem
bench_setitem = borg.hashindex.bench_setitem
bench_delete = borg.hashindex.bench_delete
bench_churn = borg.hashindex.bench_churn


@pytest.yield_fixture
def repo_url(request, tmpdir):
    os.environ['BORG_PASSPHRASE'] = '123456'
    os.environ['BORG_CHECK_I_KNOW_WHAT_I_AM_DOING'] = 'YES'
    os.environ['BORG_DELETE_I_KNOW_WHAT_I_AM_DOING'] = 'YES'
    os.environ['BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK'] = 'yes'
    os.environ['BORG_KEYS_DIR'] = str(tmpdir.join('keys'))
    os.environ['BORG_CACHE_DIR'] = str(tmpdir.join('cache'))
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


def test_chunk_indexer_setitem(benchmark):
    max_key = 2**17
    # we want 32 byte keys, since that's what we use day to day
    keys = [sha256(H(k)).digest() for k in range(max_key)]
    bucket_val = (0, 0, 0)

    def setup():
        # return *args, **kwargs for the benchmarked function
        return [ChunkIndex(445649), ], dict()

    def do_inserts(index):
        for key in keys:
            index[key] = bucket_val
    benchmark.pedantic(do_inserts, rounds=200, setup=setup)


def test_chunk_indexer_getitem(benchmark):
    max_key = 2**20
    index = ChunkIndex(445649)
    keys = [sha256(H(k)).digest() for k in range(max_key)]
    missing_keys = [
        sha256(H(k)).digest()
        for k in range(max_key, (max_key+int(len(keys)/3)))]
    bucket_val = (0, 0, 0)
    for i, key in enumerate(keys):
        # we want 32 byte keys, since that's what we use day to day
        index[key] = (i, i, i)

    def do_gets(keys=keys):
        for i, key in enumerate(keys):
            # we want 32 byte keys, since that's what we use day to day
            assert index[key] == (i, i, i)  # noqa
        for i in range(32, len(missing_keys), 32):
            index.get(key)  # noqa

    benchmark.pedantic(do_gets, rounds=200)


rounds = 10
@pytest.fixture(
    # params=[.30, .50, .75, .80, .85, .90, .93, .95]
    params=[.30, .50, .75, .85, .93, .95]
    # params=[.75, .93]
)
def fill(request):
    return request.param


def test_chunk_indexer_c_getitem(benchmark, fill):
    max_key = int(445649 * fill - 10)
    index = ChunkIndex(445649)
    keys = [sha256(H(k)).digest()
     for k in range(max_key)]
    bucket_val = (0, 0, 0)
    for key in keys:
        # we want 32 byte keys, since that's what we use day to day
        index[key] = bucket_val
    keys = b"".join(keys)

    def do_gets(keys=keys):
        bench_getitem(index, keys)
    # import yep
    # yep.start('getitem.perf')
    benchmark.pedantic(do_gets, rounds=rounds)
    # yep.stop()


def test_chunk_indexer_c_getitem_with_misses(benchmark, fill):
    max_key = int(445649 * fill - 10)
    index = ChunkIndex(445649)
    keys = [sha256(H(k)).digest()
     for k in range(max_key)]
    bucket_val = (0, 0, 0)
    for key in keys:
        # we want 32 byte keys, since that's what we use day to day
        index[key] = bucket_val
    missing_keys = b"".join([
        sha256(H(k)).digest()
        for k in range(max_key, (max_key+int(len(keys)/3)))])
    keys = b"".join(keys) + missing_keys

    def do_gets(keys=keys):
        bench_getitem(index, keys)
    benchmark.pedantic(do_gets, rounds=rounds)


def test_chunk_indexer_c_setitem_update(benchmark, fill):
    max_key = int(445649 * fill - 10)
    index = ChunkIndex(445649)
    keys = b"".join((sha256(H(k)).digest()
            for k in range(max_key)))
    bucket_val = (0, 0, 0)
    for i in range(0, 32*max_key, 32):
        key = keys[i:i+32]
        index[key] = bucket_val

    def do_sets():
        bench_setitem(index, keys)
    # import yep
    # yep.start('setitem.perf')
    benchmark.pedantic(do_sets, rounds=rounds)
    # yep.stop()


def test_chunk_indexer_c_setitem(benchmark, fill):
    max_key = int(445649 * fill - 10)
    keys = b"".join((sha256(H(k)).digest()
                     for k in range(max_key)))
    def setup():
        # return *args, **kwargs for the benchmarked function
        index = ChunkIndex(445649)
        bucket_val = (5, 5, 5)
        for i in range(0, 32*max_key, 32):
            key = keys[i:i+32]
            index[key] = bucket_val
        return (index, ), dict()

    def do_sets(index):
        bench_setitem(index, keys)
    benchmark.pedantic(do_sets, rounds=rounds, setup=setup)


def test_chunk_indexer_c_delete(benchmark, fill):
    max_key = int(445649 * fill - 10)
    keys = b"".join((sha256(H(k)).digest()
                     for k in range(max_key)))
    delete_keys = b"".join((sha256(H(k)).digest()
                            for k in range(0, max_key, 3)))
    def setup():
        # return *args, **kwargs for the benchmarked function
        index = ChunkIndex(445649)
        bucket_val = (5, 5, 5)
        for i in range(0, 32*max_key, 32):
            key = keys[i:i+32]
            index[key] = bucket_val
        return (index, ), dict()

    def do_delete(index):
        bench_delete(index, delete_keys)
    benchmark.pedantic(do_delete, rounds=rounds, setup=setup)


def test_chunk_indexer_c_setitem_after_deletion(benchmark, fill):
    max_key = int(445649 * fill - 10)
    keys = b"".join((sha256(H(k)).digest()
                     for k in range(max_key)
                     if k%5))
    delete_keys = b"".join((sha256(H(k)).digest()
                     for k in range(0, max_key, 5)))
    def setup():
        # return *args, **kwargs for the benchmarked function
        index = ChunkIndex(445649)
        bucket_val = (5, 5, 5)
        for i in range(0, len(delete_keys), 32):
            key = delete_keys[i:i+32]
            index[key] = bucket_val
        for i in range(0, len(keys), 32):
            key = keys[i:i+32]
            index[key] = bucket_val
        for i in range(0, len(delete_keys), 32):
            key = delete_keys[i:i+32]
            del index[key]
        return (index, ), dict()

    def do_sets(index):
        bench_setitem(index, keys)
    benchmark.pedantic(do_sets, rounds=rounds, setup=setup)


def test_chunk_indexer_c_churn(benchmark, fill):
    max_key = int(445649 * fill - 10)
    keys = b"".join((sha256(H(k)).digest()
                     for k in range(max_key)))
    def setup():
        # return *args, **kwargs for the benchmarked function
        index = ChunkIndex(445649)
        bucket_val = (5, 5, 5)
        for i in range(0, len(keys), 32):
            key = keys[i:i+32]
            index[key] = bucket_val
        return [index, ], dict()

    def do_sets(index):
        bench_churn(index, keys)
    benchmark.pedantic(do_sets, rounds=rounds, setup=setup)

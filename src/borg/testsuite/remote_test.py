import errno
import os
import io
import time
from unittest.mock import patch

import pytest

from ..constants import ROBJ_FILE_STREAM
from ..remote import SleepingBandwidthLimiter, RepositoryCache, cache_if_remote
from ..repository import Repository
from ..crypto.key import PlaintextKey
from ..helpers import IntegrityError
from ..repoobj import RepoObj
from .hashindex_test import H
from .repository_test import fchunk, pdchunk
from .crypto.key_test import TestKey


class TestSleepingBandwidthLimiter:
    def expect_write(self, fd, data):
        self.expected_fd = fd
        self.expected_data = data

    def check_write(self, fd, data):
        assert fd == self.expected_fd
        assert data == self.expected_data
        return len(data)

    def test_write_unlimited(self, monkeypatch):
        monkeypatch.setattr(os, "write", self.check_write)

        it = SleepingBandwidthLimiter(0)
        self.expect_write(5, b"test")
        it.write(5, b"test")

    def test_write(self, monkeypatch):
        monkeypatch.setattr(os, "write", self.check_write)
        monkeypatch.setattr(time, "monotonic", lambda: now)
        monkeypatch.setattr(time, "sleep", lambda x: None)

        now = 100

        it = SleepingBandwidthLimiter(100)  # bandwidth quota

        # all fits
        self.expect_write(5, b"test")
        it.write(5, b"test")

        # only partial write
        self.expect_write(5, b"123456")
        it.write(5, b"1234567890")

        # sleeps
        self.expect_write(5, b"123456")
        it.write(5, b"123456")

        # long time interval between writes
        now += 10
        self.expect_write(5, b"1")
        it.write(5, b"1")

        # long time interval between writes, filling up quota
        now += 10
        self.expect_write(5, b"1")
        it.write(5, b"1")

        # long time interval between writes, filling up quota to clip to maximum
        now += 10
        self.expect_write(5, b"1")
        it.write(5, b"1")


class TestRepositoryCache:
    @pytest.fixture
    def repository(self, tmpdir):
        self.repository_location = os.path.join(str(tmpdir), "repository")
        with Repository(self.repository_location, exclusive=True, create=True) as repository:
            repository.put(H(1), fchunk(b"1234"))
            repository.put(H(2), fchunk(b"5678"))
            repository.put(H(3), fchunk(bytes(100)))
            yield repository

    @pytest.fixture
    def cache(self, repository):
        return RepositoryCache(repository)

    def test_simple(self, cache: RepositoryCache):
        # Single get()s are not cached, since they are used for unique objects like archives.
        assert pdchunk(cache.get(H(1))) == b"1234"
        assert cache.misses == 1
        assert cache.hits == 0

        assert [pdchunk(ch) for ch in cache.get_many([H(1)])] == [b"1234"]
        assert cache.misses == 2
        assert cache.hits == 0

        assert [pdchunk(ch) for ch in cache.get_many([H(1)])] == [b"1234"]
        assert cache.misses == 2
        assert cache.hits == 1

        assert pdchunk(cache.get(H(1))) == b"1234"
        assert cache.misses == 2
        assert cache.hits == 2

    def test_meta(self, cache: RepositoryCache):
        # same as test_simple, but not reading the chunk data (metadata only).
        # Single get()s are not cached, since they are used for unique objects like archives.
        assert pdchunk(cache.get(H(1), read_data=False)) == b""
        assert cache.misses == 1
        assert cache.hits == 0

        assert [pdchunk(ch) for ch in cache.get_many([H(1)], read_data=False)] == [b""]
        assert cache.misses == 2
        assert cache.hits == 0

        assert [pdchunk(ch) for ch in cache.get_many([H(1)], read_data=False)] == [b""]
        assert cache.misses == 2
        assert cache.hits == 1

        assert pdchunk(cache.get(H(1), read_data=False)) == b""
        assert cache.misses == 2
        assert cache.hits == 2

    def test_mixed(self, cache: RepositoryCache):
        assert [pdchunk(ch) for ch in cache.get_many([H(1)], read_data=False)] == [b""]
        assert cache.misses == 1
        assert cache.hits == 0

        assert [pdchunk(ch) for ch in cache.get_many([H(1)], read_data=True)] == [b"1234"]
        assert cache.misses == 2
        assert cache.hits == 0

        assert [pdchunk(ch) for ch in cache.get_many([H(1)], read_data=False)] == [b""]
        assert cache.misses == 2
        assert cache.hits == 1

        assert [pdchunk(ch) for ch in cache.get_many([H(1)], read_data=True)] == [b"1234"]
        assert cache.misses == 2
        assert cache.hits == 2

    def test_backoff(self, cache: RepositoryCache):
        def query_size_limit():
            cache.size_limit = 0

        assert [pdchunk(ch) for ch in cache.get_many([H(1), H(2)])] == [b"1234", b"5678"]
        assert cache.misses == 2
        assert cache.evictions == 0
        iterator = cache.get_many([H(1), H(3), H(2)])
        assert pdchunk(next(iterator)) == b"1234"

        # Force cache to back off
        qsl = cache.query_size_limit
        cache.query_size_limit = query_size_limit  # type: ignore[assignment]
        cache.backoff()
        cache.query_size_limit = qsl  # type: ignore[assignment]
        # Evicted H(1) and H(2)
        assert cache.evictions == 2
        assert H(1) not in cache.cache
        assert H(2) not in cache.cache
        assert pdchunk(next(iterator)) == bytes(100)
        assert cache.slow_misses == 0
        # Since H(2) was in the cache when we called get_many(), but has
        # been evicted during iterating the generator, it will be a slow miss.
        assert pdchunk(next(iterator)) == b"5678"
        assert cache.slow_misses == 1

    def test_enospc(self, cache: RepositoryCache):
        class enospc_open:
            def __init__(self, *args):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                pass

            def write(self, data):
                raise OSError(errno.ENOSPC, "foo")

            def truncate(self, n=None):
                pass

        iterator = cache.get_many([H(1), H(2), H(3)])
        assert pdchunk(next(iterator)) == b"1234"

        with patch("builtins.open", enospc_open):
            assert pdchunk(next(iterator)) == b"5678"
            assert cache.enospc == 1
            # We didn't patch query_size_limit which would set size_limit to some low
            # value, so nothing was actually evicted.
            assert cache.evictions == 0

        assert pdchunk(next(iterator)) == bytes(100)

    @pytest.fixture
    def key(self, repository, monkeypatch):
        monkeypatch.setenv("BORG_PASSPHRASE", "test")
        key = PlaintextKey.create(repository, TestKey.MockArgs())
        return key

    @pytest.fixture
    def repo_objs(self, key):
        return RepoObj(key)

    def _put_encrypted_object(self, repo_objs, repository, data):
        id_ = repo_objs.id_hash(data)
        repository.put(id_, repo_objs.format(id_, {}, data, ro_type=ROBJ_FILE_STREAM))
        return id_

    @pytest.fixture
    def H1(self, repo_objs, repository):
        return self._put_encrypted_object(repo_objs, repository, b"1234")

    @pytest.fixture
    def H2(self, repo_objs, repository):
        return self._put_encrypted_object(repo_objs, repository, b"5678")

    @pytest.fixture
    def H3(self, repo_objs, repository):
        return self._put_encrypted_object(repo_objs, repository, bytes(100))

    @pytest.fixture
    def decrypted_cache(self, repo_objs, repository):
        return cache_if_remote(repository, decrypted_cache=repo_objs, force_cache=True)

    def test_cache_corruption(self, decrypted_cache: RepositoryCache, H1, H2, H3):
        list(decrypted_cache.get_many([H1, H2, H3]))

        iterator = decrypted_cache.get_many([H1, H2, H3])
        assert next(iterator) == (4, b"1234")

        pkey = decrypted_cache.prefixed_key(H2, complete=True)
        with open(decrypted_cache.key_filename(pkey), "a+b") as fd:
            fd.seek(-1, io.SEEK_END)
            corrupted = (int.from_bytes(fd.read(), "little") ^ 2).to_bytes(1, "little")
            fd.seek(-1, io.SEEK_END)
            fd.write(corrupted)
            fd.truncate()

        with pytest.raises(IntegrityError):
            assert next(iterator) == (4, b"5678")

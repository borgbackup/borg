import os

import pytest

from ..constants import ROBJ_FILE_STREAM
from ..remote import cache_if_remote
from ..repository import Repository
from ..crypto.key import PlaintextKey
from ..repoobj import RepoObj
from .hashindex_test import H
from .repository_test import fchunk, pdchunk
from .crypto.key_test import TestKey


class TestCacheIfRemote:
    @pytest.fixture
    def repository(self, tmpdir):
        self.repository_location = os.path.join(str(tmpdir), "repository")
        with Repository(self.repository_location, exclusive=True, create=True) as repository:
            repository.put(H(1), fchunk(b"1234"))
            repository.put(H(2), fchunk(b"5678"))
            repository.put(H(3), fchunk(bytes(100)))
            yield repository

    def test_passthrough(self, repository):
        # Without decrypted_cache, raw repository data is passed through unchanged.
        with cache_if_remote(repository) as cached:
            assert pdchunk(cached.get(H(1))) == b"1234"
            assert [pdchunk(ch) for ch in cached.get_many([H(1), H(2)])] == [b"1234", b"5678"]

    @pytest.fixture
    def key(self, repository, monkeypatch):
        monkeypatch.setenv("BORG_PASSPHRASE", "test")
        return PlaintextKey.create(repository, TestKey.MockArgs())

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

    def test_decrypted_cache(self, repo_objs, repository, H1, H2):
        # With decrypted_cache, get/get_many return (csize, plaintext) tuples.
        with cache_if_remote(repository, decrypted_cache=repo_objs) as cached:
            csize, plaintext = cached.get(H1)
            assert plaintext == b"1234"
            assert [pt for _csize, pt in cached.get_many([H1, H2])] == [b"1234", b"5678"]

    def test_decrypted_cache_and_transform_incompatible(self, repository, repo_objs):
        with pytest.raises(ValueError):
            cache_if_remote(repository, decrypted_cache=repo_objs, transform=lambda key, data: data)

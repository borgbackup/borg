import os
import shutil
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

import pytest

from ...cache import Cache, LocalCache
from ...constants import *  # NOQA
from ...crypto.key import TAMRequiredError
from ...helpers import Location, get_security_dir
from ...helpers import EXIT_ERROR
from ...helpers import bin_to_hex
from ...helpers import msgpack
from ...manifest import Manifest, MandatoryFeatureUnsupported
from ...remote import RemoteRepository, PathNotAllowed
from ...repository import Repository
from .. import llfuse
from .. import changedir, environment_variable
from . import ArchiverTestCaseBase, RemoteArchiverTestCaseBase, RK_ENCRYPTION


class ArchiverTestCase(ArchiverTestCaseBase):
    def get_security_dir(self):
        repository_id = bin_to_hex(self._extract_repository_id(self.repository_path))
        return get_security_dir(repository_id)

    def test_repository_swap_detection(self):
        self.create_test_files()
        os.environ["BORG_PASSPHRASE"] = "passphrase"
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        repository_id = self._extract_repository_id(self.repository_path)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        shutil.rmtree(self.repository_path)
        self.cmd(f"--repo={self.repository_location}", "rcreate", "--encryption=none")
        self._set_repository_id(self.repository_path, repository_id)
        self.assert_equal(repository_id, self._extract_repository_id(self.repository_path))
        if self.FORK_DEFAULT:
            self.cmd(f"--repo={self.repository_location}", "create", "test.2", "input", exit_code=EXIT_ERROR)
        else:
            with pytest.raises(Cache.EncryptionMethodMismatch):
                self.cmd(f"--repo={self.repository_location}", "create", "test.2", "input")

    def test_repository_swap_detection2(self):
        self.create_test_files()
        self.cmd(f"--repo={self.repository_location}_unencrypted", "rcreate", "--encryption=none")
        os.environ["BORG_PASSPHRASE"] = "passphrase"
        self.cmd(f"--repo={self.repository_location}_encrypted", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}_encrypted", "create", "test", "input")
        shutil.rmtree(self.repository_path + "_encrypted")
        os.rename(self.repository_path + "_unencrypted", self.repository_path + "_encrypted")
        if self.FORK_DEFAULT:
            self.cmd(f"--repo={self.repository_location}_encrypted", "create", "test.2", "input", exit_code=EXIT_ERROR)
        else:
            with pytest.raises(Cache.RepositoryAccessAborted):
                self.cmd(f"--repo={self.repository_location}_encrypted", "create", "test.2", "input")

    def test_repository_swap_detection_no_cache(self):
        self.create_test_files()
        os.environ["BORG_PASSPHRASE"] = "passphrase"
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        repository_id = self._extract_repository_id(self.repository_path)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        shutil.rmtree(self.repository_path)
        self.cmd(f"--repo={self.repository_location}", "rcreate", "--encryption=none")
        self._set_repository_id(self.repository_path, repository_id)
        self.assert_equal(repository_id, self._extract_repository_id(self.repository_path))
        self.cmd(f"--repo={self.repository_location}", "rdelete", "--cache-only")
        if self.FORK_DEFAULT:
            self.cmd(f"--repo={self.repository_location}", "create", "test.2", "input", exit_code=EXIT_ERROR)
        else:
            with pytest.raises(Cache.EncryptionMethodMismatch):
                self.cmd(f"--repo={self.repository_location}", "create", "test.2", "input")

    def test_repository_swap_detection2_no_cache(self):
        self.create_test_files()
        self.cmd(f"--repo={self.repository_location}_unencrypted", "rcreate", "--encryption=none")
        os.environ["BORG_PASSPHRASE"] = "passphrase"
        self.cmd(f"--repo={self.repository_location}_encrypted", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}_encrypted", "create", "test", "input")
        self.cmd(f"--repo={self.repository_location}_unencrypted", "rdelete", "--cache-only")
        self.cmd(f"--repo={self.repository_location}_encrypted", "rdelete", "--cache-only")
        shutil.rmtree(self.repository_path + "_encrypted")
        os.rename(self.repository_path + "_unencrypted", self.repository_path + "_encrypted")
        if self.FORK_DEFAULT:
            self.cmd(f"--repo={self.repository_location}_encrypted", "create", "test.2", "input", exit_code=EXIT_ERROR)
        else:
            with pytest.raises(Cache.RepositoryAccessAborted):
                self.cmd(f"--repo={self.repository_location}_encrypted", "create", "test.2", "input")

    def test_repository_swap_detection_repokey_blank_passphrase(self):
        # Check that a repokey repo with a blank passphrase is considered like a plaintext repo.
        self.create_test_files()
        # User initializes her repository with her passphrase
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        # Attacker replaces it with her own repository, which is encrypted but has no passphrase set
        shutil.rmtree(self.repository_path)
        with environment_variable(BORG_PASSPHRASE=""):
            self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
            # Delete cache & security database, AKA switch to user perspective
            self.cmd(f"--repo={self.repository_location}", "rdelete", "--cache-only")
            shutil.rmtree(self.get_security_dir())
        with environment_variable(BORG_PASSPHRASE=None):
            # This is the part were the user would be tricked, e.g. she assumes that BORG_PASSPHRASE
            # is set, while it isn't. Previously this raised no warning,
            # since the repository is, technically, encrypted.
            if self.FORK_DEFAULT:
                self.cmd(f"--repo={self.repository_location}", "create", "test.2", "input", exit_code=EXIT_ERROR)
            else:
                with pytest.raises(Cache.CacheInitAbortedError):
                    self.cmd(f"--repo={self.repository_location}", "create", "test.2", "input")

    def test_repository_move(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        security_dir = self.get_security_dir()
        os.rename(self.repository_path, self.repository_path + "_new")
        with environment_variable(BORG_RELOCATED_REPO_ACCESS_IS_OK="yes"):
            self.cmd(f"--repo={self.repository_location}_new", "rinfo")
        with open(os.path.join(security_dir, "location")) as fd:
            location = fd.read()
            assert location == Location(self.repository_location + "_new").canonical_path()
        # Needs no confirmation anymore
        self.cmd(f"--repo={self.repository_location}_new", "rinfo")
        shutil.rmtree(self.cache_path)
        self.cmd(f"--repo={self.repository_location}_new", "rinfo")
        shutil.rmtree(security_dir)
        self.cmd(f"--repo={self.repository_location}_new", "rinfo")
        for file in ("location", "key-type", "manifest-timestamp"):
            assert os.path.exists(os.path.join(security_dir, file))

    def test_security_dir_compat(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        with open(os.path.join(self.get_security_dir(), "location"), "w") as fd:
            fd.write("something outdated")
        # This is fine, because the cache still has the correct information. security_dir and cache can disagree
        # if older versions are used to confirm a renamed repository.
        self.cmd(f"--repo={self.repository_location}", "rinfo")

    def test_unknown_unencrypted(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", "--encryption=none")
        # Ok: repository is known
        self.cmd(f"--repo={self.repository_location}", "rinfo")

        # Ok: repository is still known (through security_dir)
        shutil.rmtree(self.cache_path)
        self.cmd(f"--repo={self.repository_location}", "rinfo")

        # Needs confirmation: cache and security dir both gone (eg. another host or rm -rf ~)
        shutil.rmtree(self.cache_path)
        shutil.rmtree(self.get_security_dir())
        if self.FORK_DEFAULT:
            self.cmd(f"--repo={self.repository_location}", "rinfo", exit_code=EXIT_ERROR)
        else:
            with pytest.raises(Cache.CacheInitAbortedError):
                self.cmd(f"--repo={self.repository_location}", "rinfo")
        with environment_variable(BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK="yes"):
            self.cmd(f"--repo={self.repository_location}", "rinfo")

    def add_unknown_feature(self, operation):
        with Repository(self.repository_path, exclusive=True) as repository:
            manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            manifest.config["feature_flags"] = {operation.value: {"mandatory": ["unknown-feature"]}}
            manifest.write()
            repository.commit(compact=False)

    def cmd_raises_unknown_feature(self, args):
        if self.FORK_DEFAULT:
            self.cmd(*args, exit_code=EXIT_ERROR)
        else:
            with pytest.raises(MandatoryFeatureUnsupported) as excinfo:
                self.cmd(*args)
            assert excinfo.value.args == (["unknown-feature"],)

    def test_unknown_feature_on_create(self):
        print(self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION))
        self.add_unknown_feature(Manifest.Operation.WRITE)
        self.cmd_raises_unknown_feature([f"--repo={self.repository_location}", "create", "test", "input"])

    def test_unknown_feature_on_cache_sync(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "rdelete", "--cache-only")
        self.add_unknown_feature(Manifest.Operation.READ)
        self.cmd_raises_unknown_feature([f"--repo={self.repository_location}", "create", "test", "input"])

    def test_unknown_feature_on_change_passphrase(self):
        print(self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION))
        self.add_unknown_feature(Manifest.Operation.CHECK)
        self.cmd_raises_unknown_feature([f"--repo={self.repository_location}", "key", "change-passphrase"])

    def test_unknown_feature_on_read(self):
        print(self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION))
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        self.add_unknown_feature(Manifest.Operation.READ)
        with changedir("output"):
            self.cmd_raises_unknown_feature([f"--repo={self.repository_location}", "extract", "test"])

        self.cmd_raises_unknown_feature([f"--repo={self.repository_location}", "rlist"])
        self.cmd_raises_unknown_feature([f"--repo={self.repository_location}", "info", "-a", "test"])

    def test_unknown_feature_on_rename(self):
        print(self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION))
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        self.add_unknown_feature(Manifest.Operation.CHECK)
        self.cmd_raises_unknown_feature([f"--repo={self.repository_location}", "rename", "test", "other"])

    def test_unknown_feature_on_delete(self):
        print(self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION))
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        self.add_unknown_feature(Manifest.Operation.DELETE)
        # delete of an archive raises
        self.cmd_raises_unknown_feature([f"--repo={self.repository_location}", "delete", "-a", "test"])
        self.cmd_raises_unknown_feature([f"--repo={self.repository_location}", "prune", "--keep-daily=3"])
        # delete of the whole repository ignores features
        self.cmd(f"--repo={self.repository_location}", "rdelete")

    @unittest.skipUnless(llfuse, "llfuse not installed")
    def test_unknown_feature_on_mount(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        self.add_unknown_feature(Manifest.Operation.READ)
        mountpoint = os.path.join(self.tmpdir, "mountpoint")
        os.mkdir(mountpoint)
        # XXX this might hang if it doesn't raise an error
        self.cmd_raises_unknown_feature([f"--repo={self.repository_location}::test", "mount", mountpoint])

    @pytest.mark.allow_cache_wipe
    def test_unknown_mandatory_feature_in_cache(self):
        remote_repo = bool(self.prefix)
        print(self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION))

        with Repository(self.repository_path, exclusive=True) as repository:
            if remote_repo:
                repository._location = Location(self.repository_location)
            manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            with Cache(repository, manifest) as cache:
                cache.begin_txn()
                cache.cache_config.mandatory_features = {"unknown-feature"}
                cache.commit()

        if self.FORK_DEFAULT:
            self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        else:
            called = False
            wipe_cache_safe = LocalCache.wipe_cache

            def wipe_wrapper(*args):
                nonlocal called
                called = True
                wipe_cache_safe(*args)

            with patch.object(LocalCache, "wipe_cache", wipe_wrapper):
                self.cmd(f"--repo={self.repository_location}", "create", "test", "input")

            assert called

        with Repository(self.repository_path, exclusive=True) as repository:
            if remote_repo:
                repository._location = Location(self.repository_location)
            manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            with Cache(repository, manifest) as cache:
                assert cache.cache_config.mandatory_features == set()

    def test_check_cache(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        with self.open_repository() as repository:
            manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            with Cache(repository, manifest, sync=False) as cache:
                cache.begin_txn()
                cache.chunks.incref(list(cache.chunks.iteritems())[0][0])
                cache.commit()
        with pytest.raises(AssertionError):
            self.check_cache()


class ManifestAuthenticationTest(ArchiverTestCaseBase):
    def spoof_manifest(self, repository):
        with repository:
            manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            cdata = manifest.repo_objs.format(
                Manifest.MANIFEST_ID,
                {},
                msgpack.packb(
                    {
                        "version": 1,
                        "archives": {},
                        "config": {},
                        "timestamp": (datetime.now(tz=timezone.utc) + timedelta(days=1)).isoformat(
                            timespec="microseconds"
                        ),
                    }
                ),
            )
            repository.put(Manifest.MANIFEST_ID, cdata)
            repository.commit(compact=False)

    def test_fresh_init_tam_required(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        repository = Repository(self.repository_path, exclusive=True)
        with repository:
            manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
            cdata = manifest.repo_objs.format(
                Manifest.MANIFEST_ID,
                {},
                msgpack.packb(
                    {
                        "version": 1,
                        "archives": {},
                        "timestamp": (datetime.now(tz=timezone.utc) + timedelta(days=1)).isoformat(
                            timespec="microseconds"
                        ),
                    }
                ),
            )
            repository.put(Manifest.MANIFEST_ID, cdata)
            repository.commit(compact=False)

        with pytest.raises(TAMRequiredError):
            self.cmd(f"--repo={self.repository_location}", "rlist")

    def test_not_required(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_src_archive("archive1234")
        repository = Repository(self.repository_path, exclusive=True)
        # Manifest must be authenticated now
        output = self.cmd(f"--repo={self.repository_location}", "rlist", "--debug")
        assert "archive1234" in output
        assert "TAM-verified manifest" in output
        # Try to spoof / modify pre-1.0.9
        self.spoof_manifest(repository)
        # Fails
        with pytest.raises(TAMRequiredError):
            self.cmd(f"--repo={self.repository_location}", "rlist")


class RemoteArchiverTestCase(RemoteArchiverTestCaseBase, ArchiverTestCase):
    def test_remote_repo_restrict_to_path(self):
        # restricted to repo directory itself:
        with patch.object(RemoteRepository, "extra_test_args", ["--restrict-to-path", self.repository_path]):
            self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        # restricted to repo directory itself, fail for other directories with same prefix:
        with patch.object(RemoteRepository, "extra_test_args", ["--restrict-to-path", self.repository_path]):
            with pytest.raises(PathNotAllowed):
                self.cmd(f"--repo={self.repository_location}_0", "rcreate", RK_ENCRYPTION)

        # restricted to a completely different path:
        with patch.object(RemoteRepository, "extra_test_args", ["--restrict-to-path", "/foo"]):
            with pytest.raises(PathNotAllowed):
                self.cmd(f"--repo={self.repository_location}_1", "rcreate", RK_ENCRYPTION)
        path_prefix = os.path.dirname(self.repository_path)
        # restrict to repo directory's parent directory:
        with patch.object(RemoteRepository, "extra_test_args", ["--restrict-to-path", path_prefix]):
            self.cmd(f"--repo={self.repository_location}_2", "rcreate", RK_ENCRYPTION)
        # restrict to repo directory's parent directory and another directory:
        with patch.object(
            RemoteRepository, "extra_test_args", ["--restrict-to-path", "/foo", "--restrict-to-path", path_prefix]
        ):
            self.cmd(f"--repo={self.repository_location}_3", "rcreate", RK_ENCRYPTION)

    def test_remote_repo_restrict_to_repository(self):
        # restricted to repo directory itself:
        with patch.object(RemoteRepository, "extra_test_args", ["--restrict-to-repository", self.repository_path]):
            self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        parent_path = os.path.join(self.repository_path, "..")
        with patch.object(RemoteRepository, "extra_test_args", ["--restrict-to-repository", parent_path]):
            with pytest.raises(PathNotAllowed):
                self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)

    def test_remote_repo_strip_components_doesnt_leak(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_regular_file("dir/file", contents=b"test file contents 1")
        self.create_regular_file("dir/file2", contents=b"test file contents 2")
        self.create_regular_file("skipped-file1", contents=b"test file contents 3")
        self.create_regular_file("skipped-file2", contents=b"test file contents 4")
        self.create_regular_file("skipped-file3", contents=b"test file contents 5")
        self.cmd(f"--repo={self.repository_location}", "create", "test", "input")
        marker = "cached responses left in RemoteRepository"
        with changedir("output"):
            res = self.cmd(
                f"--repo={self.repository_location}", "extract", "test", "--debug", "--strip-components", "3"
            )
            assert marker not in res
            with self.assert_creates_file("file"):
                res = self.cmd(
                    f"--repo={self.repository_location}", "extract", "test", "--debug", "--strip-components", "2"
                )
                assert marker not in res
            with self.assert_creates_file("dir/file"):
                res = self.cmd(
                    f"--repo={self.repository_location}", "extract", "test", "--debug", "--strip-components", "1"
                )
                assert marker not in res
            with self.assert_creates_file("input/dir/file"):
                res = self.cmd(
                    f"--repo={self.repository_location}", "extract", "test", "--debug", "--strip-components", "0"
                )
                assert marker not in res

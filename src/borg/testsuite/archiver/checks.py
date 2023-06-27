import os
import shutil
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

import pytest

from ...cache import Cache, LocalCache
from ...constants import *  # NOQA
from ...crypto.key import TAMRequiredError
from ...helpers import Location, get_security_dir, bin_to_hex
from ...helpers import EXIT_ERROR
from ...helpers import msgpack
from ...manifest import Manifest, MandatoryFeatureUnsupported
from ...remote import RemoteRepository, PathNotAllowed
from ...repository import Repository
from .. import llfuse
from .. import changedir, environment_variable


def get_security_directory(_extract_repository_id):
    repository_id = bin_to_hex(_extract_repository_id())
    return get_security_dir(repository_id)


def add_unknown_feature(archiver_setup, operation):
    with Repository(archiver_setup.repository_path, exclusive=True) as repository:
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        manifest.config["feature_flags"] = {operation.value: {"mandatory": ["unknown-feature"]}}
        manifest.write()
        repository.commit(compact=False)


def cmd_raises_unknown_feature(archiver_setup, cmd_fixture, args):
    if archiver_setup.FORK_DEFAULT:
        cmd_fixture(*args, exit_code=EXIT_ERROR)
    else:
        with pytest.raises(MandatoryFeatureUnsupported) as excinfo:
            cmd_fixture(*args)
        assert excinfo.value.args == (["unknown-feature"],)


def test_repository_swap_detection(
    archiver_setup, create_test_files, cmd_fixture, _extract_repository_id, _set_repository_id
):
    repo_location, repo_path = archiver_setup.repository_location, archiver_setup.repository_path
    create_test_files()
    os.environ["BORG_PASSPHRASE"] = "passphrase"
    cmd_fixture(f"--repo={repo_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
    repository_id = _extract_repository_id()
    cmd_fixture(f"--repo={repo_location}", "create", "test", "input")
    shutil.rmtree(repo_path)
    cmd_fixture(f"--repo={repo_location}", "rcreate", "--encryption=none")
    _set_repository_id(repo_path, repository_id)
    assert repository_id == _extract_repository_id()
    if archiver_setup.FORK_DEFAULT:
        cmd_fixture(f"--repo={repo_location}", "create", "test.2", "input", exit_code=EXIT_ERROR)
    else:
        with pytest.raises(Cache.EncryptionMethodMismatch):
            cmd_fixture(f"--repo={repo_location}", "create", "test.2", "input")


def test_repository_swap_detection2(archiver_setup, cmd_fixture, create_test_files):
    repo_location = archiver_setup.repository_location
    repo_path = archiver_setup.repository_path
    create_test_files()
    cmd_fixture(f"--repo={repo_location}_unencrypted", "rcreate", "--encryption=none")
    os.environ["BORG_PASSPHRASE"] = "passphrase"
    cmd_fixture(f"--repo={repo_location}_encrypted", "rcreate", archiver_setup.RK_ENCRYPTION)
    cmd_fixture(f"--repo={repo_location}_encrypted", "create", "test", "input")
    shutil.rmtree(repo_path + "_encrypted")
    os.replace(repo_path + "_unencrypted", repo_path + "_encrypted")
    if archiver_setup.FORK_DEFAULT:
        cmd_fixture(f"--repo={repo_location}_encrypted", "create", "test.2", "input", exit_code=EXIT_ERROR)
    else:
        with pytest.raises(Cache.RepositoryAccessAborted):
            cmd_fixture(f"--repo={repo_location}_encrypted", "create", "test.2", "input")


def test_repository_swap_detection_no_cache(
    archiver_setup, cmd_fixture, create_test_files, _extract_repository_id, _set_repository_id
):
    repo_location, repo_path = archiver_setup.repository_location, archiver_setup.repository_path
    create_test_files()
    os.environ["BORG_PASSPHRASE"] = "passphrase"
    cmd_fixture(f"--repo={repo_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
    repository_id = _extract_repository_id()
    cmd_fixture(f"--repo={repo_location}", "create", "test", "input")
    shutil.rmtree(repo_path)
    cmd_fixture(f"--repo={repo_location}", "rcreate", "--encryption=none")
    _set_repository_id(repo_path, repository_id)
    assert repository_id == _extract_repository_id()
    cmd_fixture(f"--repo={repo_location}", "rdelete", "--cache-only")
    if archiver_setup.FORK_DEFAULT:
        cmd_fixture(f"--repo={repo_location}", "create", "test.2", "input", exit_code=EXIT_ERROR)
    else:
        with pytest.raises(Cache.EncryptionMethodMismatch):
            cmd_fixture(f"--repo={repo_location}", "create", "test.2", "input")


def test_repository_swap_detection2_no_cache(archiver_setup, cmd_fixture, create_test_files):
    repo_location, repo_path = archiver_setup.repository_location, archiver_setup.repository_path
    create_test_files()
    cmd_fixture(f"--repo={repo_location}_unencrypted", "rcreate", "--encryption=none")
    os.environ["BORG_PASSPHRASE"] = "passphrase"
    cmd_fixture(f"--repo={repo_location}_encrypted", "rcreate", archiver_setup.RK_ENCRYPTION)
    cmd_fixture(f"--repo={repo_location}_encrypted", "create", "test", "input")
    cmd_fixture(f"--repo={repo_location}_unencrypted", "rdelete", "--cache-only")
    cmd_fixture(f"--repo={repo_location}_encrypted", "rdelete", "--cache-only")
    shutil.rmtree(repo_path + "_encrypted")
    os.replace(repo_path + "_unencrypted", repo_path + "_encrypted")
    if archiver_setup.FORK_DEFAULT:
        cmd_fixture(f"--repo={repo_location}_encrypted", "create", "test.2", "input", exit_code=EXIT_ERROR)
    else:
        with pytest.raises(Cache.RepositoryAccessAborted):
            cmd_fixture(f"--repo={repo_location}_encrypted", "create", "test.2", "input")


def test_repository_swap_detection_repokey_blank_passphrase(
    archiver_setup, cmd_fixture, create_test_files, _extract_repository_id
):
    repo_location, repo_path = archiver_setup.repository_location, archiver_setup.repository_path
    # Check that a repokey repo with a blank passphrase is considered like a plaintext repo.
    create_test_files()
    # User initializes her repository with her passphrase
    cmd_fixture(f"--repo={repo_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
    cmd_fixture(f"--repo={repo_location}", "create", "test", "input")
    # Attacker replaces it with her own repository, which is encrypted but has no passphrase set
    shutil.rmtree(repo_path)
    with environment_variable(BORG_PASSPHRASE=""):
        cmd_fixture(f"--repo={repo_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
        # Delete cache & security database, AKA switch to user perspective
        cmd_fixture(f"--repo={repo_location}", "rdelete", "--cache-only")
        shutil.rmtree(get_security_directory(_extract_repository_id))
    with environment_variable(BORG_PASSPHRASE=None):
        # This is the part were the user would be tricked, e.g. she assumes that BORG_PASSPHRASE
        # is set, while it isn't. Previously this raised no warning,
        # since the repository is, technically, encrypted.
        if archiver_setup.FORK_DEFAULT:
            cmd_fixture(f"--repo={repo_location}", "create", "test.2", "input", exit_code=EXIT_ERROR)
        else:
            with pytest.raises(Cache.CacheInitAbortedError):
                cmd_fixture(f"--repo={repo_location}", "create", "test.2", "input")


def test_repository_move(archiver_setup, cmd_fixture, _extract_repository_id):
    repo_location, repo_path = archiver_setup.repository_location, archiver_setup.repository_path
    cmd_fixture(f"--repo={repo_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
    security_dir = get_security_directory(_extract_repository_id)
    os.replace(repo_path, repo_path + "_new")
    with environment_variable(BORG_RELOCATED_REPO_ACCESS_IS_OK="yes"):
        cmd_fixture(f"--repo={repo_location}_new", "rinfo")
    with open(os.path.join(security_dir, "location")) as fd:
        location = fd.read()
        assert location == Location(repo_location + "_new").canonical_path()
    # Needs no confirmation anymore
    cmd_fixture(f"--repo={repo_location}_new", "rinfo")
    shutil.rmtree(archiver_setup.cache_path)
    cmd_fixture(f"--repo={repo_location}_new", "rinfo")
    shutil.rmtree(security_dir)
    cmd_fixture(f"--repo={repo_location}_new", "rinfo")
    for file in ("location", "key-type", "manifest-timestamp"):
        assert os.path.exists(os.path.join(security_dir, file))


def test_security_dir_compat(archiver_setup, cmd_fixture, _extract_repository_id):
    repo_location = archiver_setup.repository_location
    cmd_fixture(f"--repo={repo_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
    with open(os.path.join(get_security_directory(_extract_repository_id), "location"), "w") as fd:
        fd.write("something outdated")
    # This is fine, because the cache still has the correct information. security_dir and cache can disagree
    # if older versions are used to confirm a renamed repository.
    cmd_fixture(f"--repo={repo_location}", "rinfo")


def test_unknown_unencrypted(archiver_setup, cmd_fixture, _extract_repository_id):
    repo_location, cache_path = archiver_setup.repository_location, archiver_setup.cache_path
    cmd_fixture(f"--repo={repo_location}", "rcreate", "--encryption=none")
    # Ok: repository is known
    cmd_fixture(f"--repo={repo_location}", "rinfo")

    # Ok: repository is still known (through security_dir)
    shutil.rmtree(cache_path)
    cmd_fixture(f"--repo={repo_location}", "rinfo")

    # Needs confirmation: cache and security dir both gone (e.g. another host or rm -rf ~)
    shutil.rmtree(get_security_directory(_extract_repository_id))
    if archiver_setup.FORK_DEFAULT:
        cmd_fixture(f"--repo={repo_location}", "rinfo", exit_code=EXIT_ERROR)
    else:
        with pytest.raises(Cache.CacheInitAbortedError):
            cmd_fixture(f"--repo={repo_location}", "rinfo")
    with environment_variable(BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK="yes"):
        cmd_fixture(f"--repo={repo_location}", "rinfo")


def test_unknown_feature_on_create(archiver_setup, cmd_fixture):
    repo_location = archiver_setup.repository_location
    print(cmd_fixture(f"--repo={repo_location}", "rcreate", archiver_setup.RK_ENCRYPTION))
    add_unknown_feature(archiver_setup, Manifest.Operation.WRITE)
    cmd_raises_unknown_feature(archiver_setup, cmd_fixture, [f"--repo={repo_location}", "create", "test", "input"])


def test_unknown_feature_on_cache_sync(archiver_setup, cmd_fixture):
    repo_location = archiver_setup.repository_location
    cmd_fixture(f"--repo={repo_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
    cmd_fixture(f"--repo={repo_location}", "rdelete", "--cache-only")
    add_unknown_feature(archiver_setup, Manifest.Operation.READ)
    cmd_raises_unknown_feature(archiver_setup, cmd_fixture, [f"--repo={repo_location}", "create", "test", "input"])


def test_unknown_feature_on_change_passphrase(archiver_setup, cmd_fixture):
    repo_location = archiver_setup.repository_location
    print(cmd_fixture(f"--repo={repo_location}", "rcreate", archiver_setup.RK_ENCRYPTION))
    add_unknown_feature(archiver_setup, Manifest.Operation.CHECK)
    cmd_raises_unknown_feature(archiver_setup, cmd_fixture, [f"--repo={repo_location}", "key", "change-passphrase"])


def test_unknown_feature_on_read(archiver_setup, cmd_fixture):
    repo_location = archiver_setup.repository_location
    print(cmd_fixture(f"--repo={repo_location}", "rcreate", archiver_setup.RK_ENCRYPTION))
    cmd_fixture(f"--repo={repo_location}", "create", "test", "input")
    add_unknown_feature(archiver_setup, Manifest.Operation.READ)
    with changedir("output"):
        cmd_raises_unknown_feature(archiver_setup, cmd_fixture, [f"--repo={repo_location}", "extract", "test"])

    cmd_raises_unknown_feature(archiver_setup, cmd_fixture, [f"--repo={repo_location}", "rlist"])
    cmd_raises_unknown_feature(archiver_setup, cmd_fixture, [f"--repo={repo_location}", "info", "-a", "test"])


def test_unknown_feature_on_rename(archiver_setup, cmd_fixture):
    repo_location = archiver_setup.repository_location
    print(cmd_fixture(f"--repo={repo_location}", "rcreate", archiver_setup.RK_ENCRYPTION))
    cmd_fixture(f"--repo={repo_location}", "create", "test", "input")
    add_unknown_feature(archiver_setup, Manifest.Operation.CHECK)
    cmd_raises_unknown_feature(archiver_setup, cmd_fixture, [f"--repo={repo_location}", "rename", "test", "other"])


def test_unknown_feature_on_delete(archiver_setup, cmd_fixture):
    repo_location = archiver_setup.repository_location
    print(cmd_fixture(f"--repo={repo_location}", "rcreate", archiver_setup.RK_ENCRYPTION))
    cmd_fixture(f"--repo={repo_location}", "create", "test", "input")
    add_unknown_feature(archiver_setup, Manifest.Operation.DELETE)
    # delete of an archive raises
    cmd_raises_unknown_feature(archiver_setup, cmd_fixture, [f"--repo={repo_location}", "delete", "-a", "test"])
    cmd_raises_unknown_feature(archiver_setup, cmd_fixture, [f"--repo={repo_location}", "prune", "--keep-daily=3"])
    # delete of the whole repository ignores features
    cmd_fixture(f"--repo={repo_location}", "rdelete")


@pytest.mark.skipif(not llfuse, reason="llfuse not installed")
def test_unknown_feature_on_mount(archiver_setup, cmd_fixture):
    repo_location = archiver_setup.repository_location
    cmd_fixture(f"--repo={repo_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
    cmd_fixture(f"--repo={repo_location}", "create", "test", "input")
    add_unknown_feature(Manifest.Operation.READ)
    mountpoint = os.path.join(archiver_setup.tmpdir, "mountpoint")
    os.mkdir(mountpoint)
    # XXX this might hang if it doesn't raise an error
    cmd_raises_unknown_feature(archiver_setup, cmd_fixture, [f"--repo={repo_location}::test", "mount", mountpoint])


@pytest.mark.allow_cache_wipe
def test_unknown_mandatory_feature_in_cache(archiver_setup, cmd_fixture):
    repo_location, repo_path = archiver_setup.repository_location, archiver_setup.repository_path
    remote_repo = bool(archiver_setup.prefix)
    print(cmd_fixture(f"--repo={repo_location}", "rcreate", archiver_setup.RK_ENCRYPTION))

    with Repository(repo_path, exclusive=True) as repository:
        if remote_repo:
            repository._location = Location(repo_location)
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        with Cache(repository, manifest) as cache:
            cache.begin_txn()
            cache.cache_config.mandatory_features = {"unknown-feature"}
            cache.commit()

    if archiver_setup.FORK_DEFAULT:
        cmd_fixture(f"--repo={repo_location}", "create", "test", "input")
    else:
        called = False
        wipe_cache_safe = LocalCache.wipe_cache

        def wipe_wrapper(*args):
            nonlocal called
            called = True
            wipe_cache_safe(*args)

        with patch.object(LocalCache, "wipe_cache", wipe_wrapper):
            cmd_fixture(f"--repo={repo_location}", "create", "test", "input")

        assert called

    with Repository(repo_path, exclusive=True) as repository:
        if remote_repo:
            repository._location = Location(repo_location)
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        with Cache(repository, manifest) as cache:
            assert cache.cache_config.mandatory_features == set()


def test_check_cache(archiver_setup, cmd_fixture, check_cache, open_repository):
    repo_location = archiver_setup.repository_location
    cmd_fixture(f"--repo={repo_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
    cmd_fixture(f"--repo={repo_location}", "create", "test", "input")
    with open_repository() as repository:
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        with Cache(repository, manifest, sync=False) as cache:
            cache.begin_txn()
            cache.chunks.incref(list(cache.chunks.iteritems())[0][0])
            cache.commit()
    with pytest.raises(AssertionError):
        check_cache()


def test_fresh_init_tam_required(archiver_setup, cmd_fixture):
    repo_location, repo_path = archiver_setup.repository_location, archiver_setup.repository_path
    cmd_fixture(f"--repo={repo_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
    repository = Repository(repo_path, exclusive=True)
    with repository:
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        cdata = manifest.repo_objs.format(
            Manifest.MANIFEST_ID,
            {},
            msgpack.packb(
                {
                    "version": 1,
                    "archives": {},
                    "timestamp": (datetime.now(tz=timezone.utc) + timedelta(days=1)).isoformat(timespec="microseconds"),
                }
            ),
        )
        repository.put(Manifest.MANIFEST_ID, cdata)
        repository.commit(compact=False)

    with pytest.raises(TAMRequiredError):
        cmd_fixture(f"--repo={repo_location}", "rlist")


def test_not_required(archiver_setup, cmd_fixture, create_src_archive, spoof_manifest):
    repo_location, repo_path = archiver_setup.repository_location, archiver_setup.repository_path
    cmd_fixture(f"--repo={repo_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
    create_src_archive("archive1234")
    repository = Repository(repo_path, exclusive=True)
    # Manifest must be authenticated now
    output = cmd_fixture(f"--repo={repo_location}", "rlist", "--debug")
    assert "archive1234" in output
    assert "TAM-verified manifest" in output
    # Try to spoof / modify pre-1.0.9
    spoof_manifest(repository)
    # Fails
    with pytest.raises(TAMRequiredError):
        cmd_fixture(f"--repo={repo_location}", "rlist")


def test_remote_repo_restrict_to_path(archiver_setup, cmd_fixture, remote_prefix):
    repo_location, repo_path = archiver_setup.repository_location, archiver_setup.repository_path
    # restricted to repo directory itself:
    with patch.object(RemoteRepository, "extra_test_args", ["--restrict-to-path", repo_path]):
        cmd_fixture(f"--repo={repo_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
    # restricted to repo directory itself, fail for other directories with same prefix:
    with patch.object(RemoteRepository, "extra_test_args", ["--restrict-to-path", repo_path]):
        with pytest.raises(PathNotAllowed):
            cmd_fixture(f"--repo={repo_location}_0", "rcreate", archiver_setup.RK_ENCRYPTION)
    # restricted to a completely different path:
    with patch.object(RemoteRepository, "extra_test_args", ["--restrict-to-path", "/foo"]):
        with pytest.raises(PathNotAllowed):
            cmd_fixture(f"--repo={repo_location}_1", "rcreate", archiver_setup.RK_ENCRYPTION)
    path_prefix = os.path.dirname(repo_path)
    # restrict to repo directory's parent directory:
    with patch.object(RemoteRepository, "extra_test_args", ["--restrict-to-path", path_prefix]):
        cmd_fixture(f"--repo={repo_location}_2", "rcreate", archiver_setup.RK_ENCRYPTION)
    # restrict to repo directory's parent directory and another directory:
    with patch.object(
        RemoteRepository, "extra_test_args", ["--restrict-to-path", "/foo", "--restrict-to-path", path_prefix]
    ):
        cmd_fixture(f"--repo={repo_location}_3", "rcreate", archiver_setup.RK_ENCRYPTION)


def test_remote_repo_restrict_to_repository(archiver_setup, cmd_fixture, remote_prefix):
    repo_location, repo_path = archiver_setup.repository_location, archiver_setup.repository_path
    # restricted to repo directory itself:
    with patch.object(RemoteRepository, "extra_test_args", ["--restrict-to-repository", repo_path]):
        cmd_fixture(f"--repo={repo_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
    parent_path = os.path.join(repo_path, "..")
    with patch.object(RemoteRepository, "extra_test_args", ["--restrict-to-repository", parent_path]):
        with pytest.raises(PathNotAllowed):
            cmd_fixture(f"--repo={repo_location}", "rcreate", archiver_setup.RK_ENCRYPTION)


def test_remote_repo_strip_components_doesnt_leak(
    archiver_setup, cmd_fixture, create_regular_file, assert_creates_file, remote_prefix
):
    repo_location = archiver_setup.repository_location
    cmd_fixture(f"--repo={repo_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
    create_regular_file("dir/file", contents=b"test file contents 1")
    create_regular_file("dir/file2", contents=b"test file contents 2")
    create_regular_file("skipped-file1", contents=b"test file contents 3")
    create_regular_file("skipped-file2", contents=b"test file contents 4")
    create_regular_file("skipped-file3", contents=b"test file contents 5")
    cmd_fixture(f"--repo={repo_location}", "create", "test", "input")
    marker = "cached responses left in RemoteRepository"
    with changedir("output"):
        res = cmd_fixture(f"--repo={repo_location}", "extract", "test", "--debug", "--strip-components", "3")
        assert marker not in res
        with assert_creates_file("file"):
            res = cmd_fixture(f"--repo={repo_location}", "extract", "test", "--debug", "--strip-components", "2")
            assert marker not in res
        with assert_creates_file("dir/file"):
            res = cmd_fixture(f"--repo={repo_location}", "extract", "test", "--debug", "--strip-components", "1")
            assert marker not in res
        with assert_creates_file("input/dir/file"):
            res = cmd_fixture(f"--repo={repo_location}", "extract", "test", "--debug", "--strip-components", "0")
            assert marker not in res

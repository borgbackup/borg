import os
import shutil
from unittest.mock import patch

import pytest

from ...cache import Cache
from ...constants import *  # NOQA
from ...helpers import Location, get_security_dir, bin_to_hex
from ...helpers import EXIT_ERROR
from ...manifest import Manifest, MandatoryFeatureUnsupported
from ...remote import RemoteRepository, PathNotAllowed
from ...repository import Repository
from .. import llfuse
from .. import changedir
from . import cmd, _extract_repository_id, create_test_files
from . import _set_repository_id, create_regular_file, assert_creates_file, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote")  # NOQA


def get_security_directory(repo_path):
    repository_id = bin_to_hex(_extract_repository_id(repo_path))
    return get_security_dir(repository_id)


def add_unknown_feature(repo_path, operation):
    with Repository(repo_path, exclusive=True) as repository:
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        manifest.config["feature_flags"] = {operation.value: {"mandatory": ["unknown-feature"]}}
        manifest.write()


def cmd_raises_unknown_feature(archiver, args):
    if archiver.FORK_DEFAULT:
        cmd(archiver, *args, exit_code=EXIT_ERROR)
    else:
        with pytest.raises(MandatoryFeatureUnsupported) as excinfo:
            cmd(archiver, *args)
        assert excinfo.value.args == (["unknown-feature"],)


def test_repository_swap_detection(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path)
    os.environ["BORG_PASSPHRASE"] = "passphrase"
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repository_id = _extract_repository_id(archiver.repository_path)
    cmd(archiver, "create", "test", "input")
    shutil.rmtree(archiver.repository_path)
    cmd(archiver, "repo-create", "--encryption=none")
    _set_repository_id(archiver.repository_path, repository_id)
    assert repository_id == _extract_repository_id(archiver.repository_path)
    if archiver.FORK_DEFAULT:
        cmd(archiver, "create", "test.2", "input", exit_code=EXIT_ERROR)
    else:
        with pytest.raises(Cache.EncryptionMethodMismatch):
            cmd(archiver, "create", "test.2", "input")


def test_repository_swap_detection2(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path)
    original_location = archiver.repository_location
    archiver.repository_location = original_location + "_unencrypted"
    cmd(archiver, "repo-create", "--encryption=none")
    os.environ["BORG_PASSPHRASE"] = "passphrase"
    archiver.repository_location = original_location + "_encrypted"
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    shutil.rmtree(archiver.repository_path + "_encrypted")
    os.replace(archiver.repository_path + "_unencrypted", archiver.repository_path + "_encrypted")
    if archiver.FORK_DEFAULT:
        cmd(archiver, "create", "test.2", "input", exit_code=EXIT_ERROR)
    else:
        with pytest.raises(Cache.RepositoryAccessAborted):
            cmd(archiver, "create", "test.2", "input")


def test_repository_swap_detection_no_cache(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path)
    os.environ["BORG_PASSPHRASE"] = "passphrase"
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repository_id = _extract_repository_id(archiver.repository_path)
    cmd(archiver, "create", "test", "input")
    shutil.rmtree(archiver.repository_path)
    cmd(archiver, "repo-create", "--encryption=none")
    _set_repository_id(archiver.repository_path, repository_id)
    assert repository_id == _extract_repository_id(archiver.repository_path)
    cmd(archiver, "repo-delete", "--cache-only")
    if archiver.FORK_DEFAULT:
        cmd(archiver, "create", "test.2", "input", exit_code=EXIT_ERROR)
    else:
        with pytest.raises(Cache.EncryptionMethodMismatch):
            cmd(archiver, "create", "test.2", "input")


def test_repository_swap_detection2_no_cache(archivers, request):
    archiver = request.getfixturevalue(archivers)
    original_location = archiver.repository_location
    create_test_files(archiver.input_path)
    archiver.repository_location = original_location + "_unencrypted"
    cmd(archiver, "repo-create", "--encryption=none")
    os.environ["BORG_PASSPHRASE"] = "passphrase"
    archiver.repository_location = original_location + "_encrypted"
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    archiver.repository_location = original_location + "_unencrypted"
    cmd(archiver, "repo-delete", "--cache-only")
    archiver.repository_location = original_location + "_encrypted"
    cmd(archiver, "repo-delete", "--cache-only")
    shutil.rmtree(archiver.repository_path + "_encrypted")
    os.replace(archiver.repository_path + "_unencrypted", archiver.repository_path + "_encrypted")
    if archiver.FORK_DEFAULT:
        cmd(archiver, "create", "test.2", "input", exit_code=EXIT_ERROR)
    else:
        with pytest.raises(Cache.RepositoryAccessAborted):
            cmd(archiver, "create", "test.2", "input")


def test_repository_swap_detection_repokey_blank_passphrase(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    # Check that a repokey repo with a blank passphrase is considered like a plaintext repo.
    create_test_files(archiver.input_path)
    # User initializes her repository with her passphrase
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    # Attacker replaces it with her own repository, which is encrypted but has no passphrase set
    shutil.rmtree(archiver.repository_path)

    monkeypatch.setenv("BORG_PASSPHRASE", "")
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    # Delete cache & security database, AKA switch to user perspective
    cmd(archiver, "repo-delete", "--cache-only")
    shutil.rmtree(get_security_directory(archiver.repository_path))

    monkeypatch.delenv("BORG_PASSPHRASE")
    # This is the part were the user would be tricked, e.g. she assumes that BORG_PASSPHRASE
    # is set, while it isn't. Previously this raised no warning,
    # since the repository is, technically, encrypted.
    if archiver.FORK_DEFAULT:
        cmd(archiver, "create", "test.2", "input", exit_code=EXIT_ERROR)
    else:
        with pytest.raises(Cache.CacheInitAbortedError):
            cmd(archiver, "create", "test.2", "input")


def test_repository_move(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    security_dir = get_security_directory(archiver.repository_path)
    os.replace(archiver.repository_path, archiver.repository_path + "_new")
    archiver.repository_location += "_new"
    # borg should notice that the repository location changed and abort.
    if archiver.FORK_DEFAULT:
        cmd(archiver, "repo-info", exit_code=EXIT_ERROR)
    else:
        with pytest.raises(Cache.RepositoryAccessAborted):
            cmd(archiver, "repo-info")
    # if we explicitly allow relocated repos, it should work fine.
    monkeypatch.setenv("BORG_RELOCATED_REPO_ACCESS_IS_OK", "yes")
    cmd(archiver, "repo-info")
    monkeypatch.delenv("BORG_RELOCATED_REPO_ACCESS_IS_OK")
    with open(os.path.join(security_dir, "location")) as fd:
        location = fd.read()
        assert location == Location(archiver.repository_location).canonical_path()
    # after new repo location was confirmed once, it needs no further confirmation anymore.
    cmd(archiver, "repo-info")
    shutil.rmtree(security_dir)
    # it also needs no confirmation if we have no knowledge about the previous location.
    cmd(archiver, "repo-info")
    # it will re-create security-related infos in the security dir:
    for file in ("location", "key-type", "manifest-timestamp"):
        assert os.path.exists(os.path.join(security_dir, file))


def test_unknown_unencrypted(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", "--encryption=none")
    # Ok: repository is known
    cmd(archiver, "repo-info")

    # Ok: repository is still known (through security_dir)
    shutil.rmtree(archiver.cache_path)
    cmd(archiver, "repo-info")

    # Needs confirmation: cache and security dir both gone (e.g. another host or rm -rf ~)
    shutil.rmtree(get_security_directory(archiver.repository_path))
    if archiver.FORK_DEFAULT:
        cmd(archiver, "repo-info", exit_code=EXIT_ERROR)
    else:
        with pytest.raises(Cache.CacheInitAbortedError):
            cmd(archiver, "repo-info")
    monkeypatch.setenv("BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK", "yes")
    cmd(archiver, "repo-info")


def test_unknown_feature_on_create(archivers, request):
    archiver = request.getfixturevalue(archivers)
    print(cmd(archiver, "repo-create", RK_ENCRYPTION))
    add_unknown_feature(archiver.repository_path, Manifest.Operation.WRITE)
    cmd_raises_unknown_feature(archiver, ["create", "test", "input"])


def test_unknown_feature_on_change_passphrase(archivers, request):
    archiver = request.getfixturevalue(archivers)
    print(cmd(archiver, "repo-create", RK_ENCRYPTION))
    add_unknown_feature(archiver.repository_path, Manifest.Operation.CHECK)
    cmd_raises_unknown_feature(archiver, ["key", "change-passphrase"])


def test_unknown_feature_on_read(archivers, request):
    archiver = request.getfixturevalue(archivers)
    print(cmd(archiver, "repo-create", RK_ENCRYPTION))
    cmd(archiver, "create", "test", "input")
    add_unknown_feature(archiver.repository_path, Manifest.Operation.READ)
    with changedir("output"):
        cmd_raises_unknown_feature(archiver, ["extract", "test"])
    cmd_raises_unknown_feature(archiver, ["repo-list"])
    cmd_raises_unknown_feature(archiver, ["info", "-a", "test"])


def test_unknown_feature_on_rename(archivers, request):
    archiver = request.getfixturevalue(archivers)
    print(cmd(archiver, "repo-create", RK_ENCRYPTION))
    cmd(archiver, "create", "test", "input")
    add_unknown_feature(archiver.repository_path, Manifest.Operation.CHECK)
    cmd_raises_unknown_feature(archiver, ["rename", "test", "other"])


def test_unknown_feature_on_delete(archivers, request):
    archiver = request.getfixturevalue(archivers)
    print(cmd(archiver, "repo-create", RK_ENCRYPTION))
    cmd(archiver, "create", "test", "input")
    add_unknown_feature(archiver.repository_path, Manifest.Operation.DELETE)
    # delete of an archive raises
    cmd_raises_unknown_feature(archiver, ["delete", "-a", "test"])
    cmd_raises_unknown_feature(archiver, ["prune", "--keep-daily=3"])
    # delete of the whole repository ignores features
    cmd(archiver, "repo-delete")


@pytest.mark.skipif(not llfuse, reason="llfuse not installed")
def test_unknown_feature_on_mount(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    add_unknown_feature(archiver.repository_path, Manifest.Operation.READ)
    mountpoint = os.path.join(archiver.tmpdir, "mountpoint")
    os.mkdir(mountpoint)
    # XXX this might hang if it doesn't raise an error
    cmd_raises_unknown_feature(archiver, ["mount", mountpoint])


def test_unknown_mandatory_feature_in_cache(archivers, request):
    archiver = request.getfixturevalue(archivers)
    remote_repo = archiver.get_kind() == "remote"
    print(cmd(archiver, "repo-create", RK_ENCRYPTION))

    with Repository(archiver.repository_path, exclusive=True) as repository:
        if remote_repo:
            repository._location = Location(archiver.repository_location)
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        with Cache(repository, manifest) as cache:
            cache.cache_config.mandatory_features = {"unknown-feature"}

    if archiver.FORK_DEFAULT:
        cmd(archiver, "create", "test", "input")

    with Repository(archiver.repository_path, exclusive=True) as repository:
        if remote_repo:
            repository._location = Location(archiver.repository_location)
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        with Cache(repository, manifest) as cache:
            assert cache.cache_config.mandatory_features == set()


# Begin Remote Tests
def test_remote_repo_restrict_to_path(remote_archiver):
    original_location, repo_path = remote_archiver.repository_location, remote_archiver.repository_path
    # restricted to repo directory itself:
    with patch.object(RemoteRepository, "extra_test_args", ["--restrict-to-path", repo_path]):
        cmd(remote_archiver, "repo-create", RK_ENCRYPTION)
    # restricted to repo directory itself, fail for other directories with same prefix:
    with patch.object(RemoteRepository, "extra_test_args", ["--restrict-to-path", repo_path]):
        with pytest.raises(PathNotAllowed):
            remote_archiver.repository_location = original_location + "_0"
            cmd(remote_archiver, "repo-create", RK_ENCRYPTION)
    # restricted to a completely different path:
    with patch.object(RemoteRepository, "extra_test_args", ["--restrict-to-path", "/foo"]):
        with pytest.raises(PathNotAllowed):
            remote_archiver.repository_location = original_location + "_1"
            cmd(remote_archiver, "repo-create", RK_ENCRYPTION)
    path_prefix = os.path.dirname(repo_path)
    # restrict to repo directory's parent directory:
    with patch.object(RemoteRepository, "extra_test_args", ["--restrict-to-path", path_prefix]):
        remote_archiver.repository_location = original_location + "_2"
        cmd(remote_archiver, "repo-create", RK_ENCRYPTION)
    # restrict to repo directory's parent directory and another directory:
    with patch.object(
        RemoteRepository, "extra_test_args", ["--restrict-to-path", "/foo", "--restrict-to-path", path_prefix]
    ):
        remote_archiver.repository_location = original_location + "_3"
        cmd(remote_archiver, "repo-create", RK_ENCRYPTION)


def test_remote_repo_restrict_to_repository(remote_archiver):
    repo_path = remote_archiver.repository_path
    # restricted to repo directory itself:
    with patch.object(RemoteRepository, "extra_test_args", ["--restrict-to-repository", repo_path]):
        cmd(remote_archiver, "repo-create", RK_ENCRYPTION)
    parent_path = os.path.join(repo_path, "..")
    with patch.object(RemoteRepository, "extra_test_args", ["--restrict-to-repository", parent_path]):
        with pytest.raises(PathNotAllowed):
            cmd(remote_archiver, "repo-create", RK_ENCRYPTION)


def test_remote_repo_strip_components_doesnt_leak(remote_archiver):
    cmd(remote_archiver, "repo-create", RK_ENCRYPTION)
    create_regular_file(remote_archiver.input_path, "dir/file", contents=b"test file contents 1")
    create_regular_file(remote_archiver.input_path, "dir/file2", contents=b"test file contents 2")
    create_regular_file(remote_archiver.input_path, "skipped-file1", contents=b"test file contents 3")
    create_regular_file(remote_archiver.input_path, "skipped-file2", contents=b"test file contents 4")
    create_regular_file(remote_archiver.input_path, "skipped-file3", contents=b"test file contents 5")
    cmd(remote_archiver, "create", "test", "input")
    marker = "cached responses left in RemoteRepository"
    with changedir("output"):
        res = cmd(remote_archiver, "extract", "test", "--debug", "--strip-components", "3")
        assert marker not in res
        with assert_creates_file("file"):
            res = cmd(remote_archiver, "extract", "test", "--debug", "--strip-components", "2")
            assert marker not in res
        with assert_creates_file("dir/file"):
            res = cmd(remote_archiver, "extract", "test", "--debug", "--strip-components", "1")
            assert marker not in res
        with assert_creates_file("input/dir/file"):
            res = cmd(remote_archiver, "extract", "test", "--debug", "--strip-components", "0")
            assert marker not in res

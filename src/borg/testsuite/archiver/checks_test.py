import os
import shutil

import pytest

from ...cache import Cache
from ...constants import *  # NOQA
from ...helpers import Location, get_security_dir, bin_to_hex
from ...helpers import EXIT_ERROR
from .. import changedir
from . import cmd, _extract_repository_id, create_test_files
from . import _set_repository_id, create_regular_file, assert_creates_file, generate_archiver_tests, RK_ENCRYPTION
from . import set_empty_passphrase

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote")  # NOQA


def get_security_directory(repo_path):
    repository_id = bin_to_hex(_extract_repository_id(repo_path))
    return get_security_dir(repository_id)


def test_repository_swap_detection(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path)
    os.environ["BORG_PASSPHRASE"] = "passphrase"
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    repository_id = _extract_repository_id(archiver.repository_path)
    cmd(archiver, "create", "test", "input")
    shutil.rmtree(archiver.repository_path)
    cmd(archiver, "repo-create", "--encryption=none-sha256")
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
    cmd(archiver, "repo-create", "--encryption=none-sha256")
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
    cmd(archiver, "repo-create", "--encryption=none-sha256")
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
    cmd(archiver, "repo-create", "--encryption=none-sha256")
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
    for file in ("location", "key-type"):
        assert os.path.exists(os.path.join(security_dir, file))


def test_unknown_unencrypted(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", "--encryption=none-sha256")
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
    output = cmd(archiver, "repo-info")
    # the warning says why the repository counts as unencrypted, see #9072
    assert "previously unknown unencrypted repository" in output
    assert "uses the none-sha256 mode, which does not encrypt the data" in output


def test_unknown_unencrypted_empty_passphrase(archivers, request, monkeypatch):
    # a repokey repository with an empty passphrase is treated like an unencrypted one, but the
    # warning must say so, as "borg repo-info" reports the repository as encrypted, see #9072.
    archiver = request.getfixturevalue(archivers)
    set_empty_passphrase(monkeypatch)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    # Ok: repository is known
    cmd(archiver, "repo-info")

    # Needs confirmation: cache and security dir both gone (e.g. another host or rm -rf ~)
    shutil.rmtree(archiver.cache_path)
    shutil.rmtree(get_security_directory(archiver.repository_path))
    monkeypatch.setenv("BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK", "yes")
    output = cmd(archiver, "repo-info")
    assert "previously unknown unencrypted repository" in output
    assert "stored inside the repository (repokey) and has an empty passphrase" in output


# Begin Remote Tests
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


def test_stale_manifest_timestamp_file_is_ignored(archivers, request):
    # older borg 2 versions stored the manifest timestamp in the security dir and refused access when the
    # repository's manifest was older than that. that check is gone: a leftover (even "future") file is ignored.
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    security_dir = get_security_directory(archiver.repository_path)
    with open(os.path.join(security_dir, "manifest-timestamp"), "w") as fd:
        fd.write("9999-01-01T00:00:00.000000")
    cmd(archiver, "repo-info")
    cmd(archiver, "create", "test", "input")


def test_repository_restored_from_older_copy_is_accepted(archivers, request):
    # restoring an older copy of the repository (a "rollback") must not lock the user out of it.
    archiver = request.getfixturevalue(archivers)
    if archiver.get_kind() != "local":
        pytest.skip("needs a local repository to copy")
    create_regular_file(archiver.input_path, "file1", size=1024)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "archive1", "input")
    backup_path = archiver.repository_path + "_copy"
    shutil.copytree(archiver.repository_path, backup_path)
    cmd(archiver, "create", "archive2", "input")
    shutil.rmtree(archiver.repository_path)
    shutil.copytree(backup_path, archiver.repository_path)
    output = cmd(archiver, "repo-list")
    assert "archive1" in output
    assert "archive2" not in output
    # the files cache still knows the files from archive2 (whose chunks are gone), that must not matter.
    cmd(archiver, "create", "archive3", "input")
    cmd(archiver, "check")

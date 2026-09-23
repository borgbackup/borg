import os
from unittest.mock import patch

import pytest

from ...archiver import repo_create_cmd
from ...cache import list_chunkindex_hashes, read_chunkindex_from_repo
from ...helpers.errors import Error, CancelledByUser
from ...constants import *  # NOQA
from ...crypto.key import FlexiKey
from . import cmd, create_src_archive, generate_archiver_tests, open_repository
from . import RK_ENCRYPTION, KF_ENCRYPTION, KF_LOCATION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,binary")  # NOQA


def test_repo_create_interrupt(archivers, request):
    archiver = request.getfixturevalue(archivers)
    if archiver.EXE:
        pytest.skip("patches object")

    def raise_eof(*args, **kwargs):
        raise EOFError

    with patch.object(FlexiKey, "create", raise_eof):
        if archiver.FORK_DEFAULT:
            cmd(archiver, "repo-create", RK_ENCRYPTION, exit_code=2)
        else:
            with pytest.raises(CancelledByUser):
                cmd(archiver, "repo-create", RK_ENCRYPTION)

    assert not os.path.exists(archiver.repository_location)


def test_repo_create_requires_encryption_option(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", exit_code=2)


@pytest.mark.parametrize(
    "extra_args, expected",
    [
        # --encryption x --id-hash -> crypto suite shown by "borg repo-info"
        (["--encryption=aes256-ocb"], "Yes (repokey, aes256-ocb, sha256)"),  # default id-hash is sha256
        (["--encryption=aes256-ocb", "--id-hash=sha256"], "Yes (repokey, aes256-ocb, sha256)"),
        (["--encryption=aes256-ocb", "--id-hash=blake3"], "Yes (repokey, aes256-ocb, blake3)"),
        (["--encryption=chacha20-poly1305"], "Yes (repokey, chacha20-poly1305, sha256)"),
        (["--encryption=chacha20-poly1305", "--id-hash=blake3"], "Yes (repokey, chacha20-poly1305, blake3)"),
        # the modes that do not encrypt name their id hash themselves, --id-hash does not apply
        (["--encryption=authenticated-sha256"], "No (repokey, authenticated-sha256)"),
        (["--encryption=authenticated-blake3"], "No (repokey, authenticated-blake3)"),
        # giving the matching --id-hash in addition is accepted
        (["--encryption=authenticated-blake3", "--id-hash=blake3"], "No (repokey, authenticated-blake3)"),
    ],
)
def test_repo_create_encryption_id_hash_combinations(archivers, request, extra_args, expected):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", *extra_args)
    info = cmd(archiver, "repo-info")
    assert expected in info


@pytest.mark.parametrize("mode", ["none", "authenticated"])
def test_repo_create_rejects_unsupported_unencrypted_mode_names(archivers, request, mode):
    # there is no "none" mode, and the "authenticated-*" modes always name their id hash, see #9104.
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", f"--encryption={mode}", exit_code=2)


@pytest.mark.parametrize("mode", ["authenticated-sha256", "authenticated-blake3"])
def test_repo_create_rejects_conflicting_id_hash(archivers, request, mode):
    # the id hash of these modes is part of the mode name, so a contradicting --id-hash is an error.
    archiver = request.getfixturevalue(archivers)
    conflicting = "blake3" if mode.endswith("sha256") else "sha256"
    arg = ("repo-create", f"--encryption={mode}", f"--id-hash={conflicting}")
    if archiver.FORK_DEFAULT:
        cmd(archiver, *arg, exit_code=2)
    else:
        with pytest.raises(Error):
            cmd(archiver, *arg)


def test_repo_create_rejects_legacy_combined_mode(archivers, request):
    # clean break: the old combined "--encryption" names are no longer accepted (argparse choices).
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", "--encryption=blake3-aes-ocb", exit_code=2)


def test_repo_create_related_authenticated_repos_store_identical_objects(archivers, request, monkeypatch):
    # The envelope MAC key of the "authenticated-*" modes is derived from crypt_key, and the tag is
    # deterministic, so two related repositories created with --copy-crypt-key store byte-identical
    # objects for identical input (which allows deduplicating them on the filesystem level).
    # Without --copy-crypt-key, crypt_key is a fresh random key and the objects differ.
    archiver = request.getfixturevalue(archivers)
    src_location = archiver.repository_location
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_src_archive(archiver, "arch")
    monkeypatch.setenv("BORG_OTHER_PASSPHRASE", os.environ["BORG_PASSPHRASE"])

    def transferred_objects(suffix, *extra_args):
        archiver.repository_location = archiver.repository_path = src_location + suffix
        cmd(archiver, "repo-create", "--encryption=authenticated-sha256", f"--other-repo={src_location}", *extra_args)
        cmd(archiver, "transfer", f"--other-repo={src_location}")
        objects = []
        for dirpath, _, filenames in os.walk(os.path.join(archiver.repository_path, "packs")):
            for filename in sorted(filenames):
                with open(os.path.join(dirpath, filename), "rb") as fd:
                    objects.append(fd.read())
        assert objects  # we did transfer something
        return sorted(objects)

    same_key = transferred_objects("dst1", "--copy-crypt-key")
    same_key_again = transferred_objects("dst2", "--copy-crypt-key")
    assert same_key == same_key_again
    assert transferred_objects("dst3") != same_key  # a fresh crypt_key gives different tags


def test_repo_create_refuse_to_overwrite_keyfile(archivers, request, monkeypatch):
    #  BORG_KEY_FILE=something borg repo-create should quit if "something" already exists.
    #  See: https://github.com/borgbackup/borg/pull/6046
    archiver = request.getfixturevalue(archivers)
    keyfile = os.path.join(archiver.tmpdir, "keyfile")
    monkeypatch.setenv("BORG_KEY_FILE", keyfile)
    original_location = archiver.repository_location
    archiver.repository_location = original_location + "0"
    cmd(archiver, "repo-create", KF_ENCRYPTION, KF_LOCATION)
    with open(keyfile) as file:
        before = file.read()
    archiver.repository_location = original_location + "1"
    arg = ("repo-create", KF_ENCRYPTION, KF_LOCATION)
    if archiver.FORK_DEFAULT:
        cmd(archiver, *arg, exit_code=2)
    else:
        with pytest.raises(Error):
            cmd(archiver, *arg)
    with open(keyfile) as file:
        after = file.read()
    assert before == after


def test_repo_create_failure_leaves_nothing_behind(archivers, request, monkeypatch):
    # not only a cancelled, also a failed repo-create must not leave a (partial) repository or a keyfile.
    archiver = request.getfixturevalue(archivers)
    if archiver.EXE:
        pytest.skip("patches object")
    keys_dir = os.path.join(archiver.tmpdir, "keys")
    monkeypatch.setenv("BORG_KEYS_DIR", keys_dir)

    def failing_save_config(self, key=None):
        raise OSError("simulated store failure while writing the config")

    from ...repository import Repository

    with patch.object(Repository, "save_config", failing_save_config):
        if archiver.FORK_DEFAULT:
            cmd(archiver, "repo-create", KF_ENCRYPTION, KF_LOCATION, exit_code=2)
        else:
            with pytest.raises(OSError, match="simulated store failure"):
                cmd(archiver, "repo-create", KF_ENCRYPTION, KF_LOCATION)
    assert not os.path.exists(archiver.repository_location)
    assert not os.path.exists(keys_dir) or not os.listdir(keys_dir)  # the keyfile written before the failure is gone
    # and nothing stands in the way of creating the repository there now.
    cmd(archiver, "repo-create", KF_ENCRYPTION, KF_LOCATION)
    assert os.listdir(keys_dir)


def test_repo_create_writes_an_empty_chunk_index(archivers, request):
    # repo-create stores an empty chunk index (in the key's envelope), so the first use of the repository
    # does not have to build it by listing the packs.
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    with open_repository(archiver) as repository:
        hashes = list_chunkindex_hashes(repository)
        assert len(hashes) == 1
        chunks = read_chunkindex_from_repo(repository, hashes[0])
        assert chunks is not None and len(chunks) == 0


def test_repo_create_chunk_index_failure_leaves_nothing_behind(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    if archiver.EXE:
        pytest.skip("patches object")
    keys_dir = os.path.join(archiver.tmpdir, "keys")
    monkeypatch.setenv("BORG_KEYS_DIR", keys_dir)

    def failing_write_chunkindex_to_repo(*args, **kwargs):
        raise OSError("simulated store failure while writing the chunk index")

    with patch.object(repo_create_cmd, "write_chunkindex_to_repo", failing_write_chunkindex_to_repo):
        if archiver.FORK_DEFAULT:
            cmd(archiver, "repo-create", KF_ENCRYPTION, KF_LOCATION, exit_code=2)
        else:
            with pytest.raises(OSError, match="simulated store failure"):
                cmd(archiver, "repo-create", KF_ENCRYPTION, KF_LOCATION)
    assert not os.path.exists(archiver.repository_location)
    assert not os.path.exists(keys_dir) or not os.listdir(keys_dir)

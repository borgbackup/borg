import json
import os
from unittest.mock import patch

import pytest

from ...archiver import repo_create_cmd
from ...cache import list_chunkindex_hashes, read_chunkindex_from_repo
from ...compress import CNONE, LZ4, ZLIB, ZSTD
from ...helpers.errors import Error, CancelledByUser, IntegrityError
from ...constants import *  # NOQA
from ...crypto.key import FlexiKey
from ...manifest import Manifest
from ...repository import Repository, repo_lister
from . import cmd, create_regular_file, create_src_archive, generate_archiver_tests, open_repository
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


def stored_compression(archiver):
    """Return the set of (ctype, clevel) of the compressed objects in the repository.

    Objects that do not get smaller by compression are stored uncompressed, they are left out.
    """
    with open_repository(archiver) as repository:
        manifest = Manifest.load(repository)
        result = set()
        for id, _ in repo_lister(repository, limit=LIST_SCAN_LIMIT):
            meta = manifest.repo_objs.parse_meta(id, repository.get(id, read_data=False), ro_type=ROBJ_DONTCARE)
            if meta["ctype"] != CNONE.ID:
                result.add((meta["ctype"], meta["clevel"]))
        return result


def test_repo_create_default_compression(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION, "--compression=zstd,5")
    assert "Default compression: zstd,5" + os.linesep in cmd(archiver, "repo-info")
    assert json.loads(cmd(archiver, "repo-info", "--json"))["defaults"]["compression"] == "zstd,5"
    # without --compression, create uses the repository default.
    cmd(archiver, "create", "test", "input")
    assert stored_compression(archiver) == {(ZSTD.ID, 5)}
    # --compression wins over the repository default, and without it, the repository default is used again.
    cmd(archiver, "repo-compress", "--compression=lz4")
    assert stored_compression(archiver) == {(LZ4.ID, 255)}
    cmd(archiver, "repo-compress")
    assert stored_compression(archiver) == {(ZSTD.ID, 5)}
    # a compression given via the environment wins over the repository default, too.
    monkeypatch.setenv("BORG_REPO_COMPRESS__COMPRESSION", "zlib,3")
    cmd(archiver, "repo-compress")
    assert stored_compression(archiver) == {(ZLIB.ID, 3)}


def test_repo_create_without_default_compression(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    with open_repository(archiver) as repository:
        assert repository.load_defaults() == {}  # the object exists (else DefaultsMissing), but is empty
    output = cmd(archiver, "repo-info")
    assert "Default compression: lz4 (built-in)" + os.linesep in output
    assert "Default chunker params: %s,%d,%d,%d,%d (built-in)" % CHUNKER_PARAMS + os.linesep in output
    assert json.loads(cmd(archiver, "repo-info", "--json"))["defaults"] == {
        "compression": "lz4",
        "chunker_params": "%s,%d,%d,%d,%d" % CHUNKER_PARAMS,
    }
    cmd(archiver, "create", "test", "input")
    assert stored_compression(archiver) == {(LZ4.ID, 255)}
    assert archive_chunker_params(archiver, "test") == list(CHUNKER_PARAMS)


def test_repo_create_rejects_invalid_compression(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION, "--compression=zstd,99", exit_code=2)
    assert not os.path.exists(archiver.repository_path)


def test_default_compression_tampered(archivers, request):
    # the repository defaults are authenticated: changing them without the key is detected.
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION, "--compression=obfuscate,110,zstd,3")
    with open_repository(archiver) as repository:
        envelope = bytearray(repository.store_load("config/defaults"))
        envelope[-1] ^= 1
        repository.store_store("config/defaults", bytes(envelope))
    if archiver.FORK_DEFAULT:
        cmd(archiver, "create", "test", "input", exit_code=IntegrityError("x").exit_code)
    else:
        with pytest.raises(IntegrityError):
            cmd(archiver, "create", "test", "input")


def test_default_compression_invalid(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    with open_repository(archiver) as repository:
        repository.save_defaults({"compression": "nosuchcompression"})
    if archiver.FORK_DEFAULT:
        exit_code = Repository.InvalidRepositoryConfig("x", "y").exit_code
        cmd(archiver, "create", "test", "input", exit_code=exit_code)
    else:
        with pytest.raises(Repository.InvalidRepositoryConfig):
            cmd(archiver, "create", "test", "input")


def archive_chunker_params(archiver, name):
    return json.loads(cmd(archiver, "info", "--json", name))["archives"][0]["chunker_params"]


def test_repo_create_default_chunker_params(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION, "--chunker-params=fixed,4096")
    assert "Default chunker params: fixed,4096,0" + os.linesep in cmd(archiver, "repo-info")
    assert json.loads(cmd(archiver, "repo-info", "--json"))["defaults"]["chunker_params"] == "fixed,4096,0"
    # without --chunker-params (or with "default"), create uses the repository default.
    cmd(archiver, "create", "test1", "input")
    assert archive_chunker_params(archiver, "test1") == ["fixed", 4096, 0]
    cmd(archiver, "create", "--chunker-params=default", "test2", "input")
    assert archive_chunker_params(archiver, "test2") == ["fixed", 4096, 0]
    # given chunker params win over the repository default, also when given via the environment.
    cmd(archiver, "create", "--chunker-params=fixed,8192", "test3", "input")
    assert archive_chunker_params(archiver, "test3") == ["fixed", 8192, 0]
    monkeypatch.setenv("BORG_CREATE__CHUNKER_PARAMS", "fixed,16384")
    cmd(archiver, "create", "test4", "input")
    assert archive_chunker_params(archiver, "test4") == ["fixed", 16384, 0]
    # recreate only rechunks if asked to, "default" rechunks to the repository default.
    cmd(archiver, "recreate", "-a", "test3")
    assert archive_chunker_params(archiver, "test3") == ["fixed", 8192, 0]
    cmd(archiver, "recreate", "-a", "test3", "--chunker-params=default")
    assert archive_chunker_params(archiver, "test3") == ["fixed", 4096, 0]


def test_repo_create_chunker_params_default_is_no_repository_default(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION, "--chunker-params=default")
    with open_repository(archiver) as repository:
        assert repository.load_defaults() == {}


def test_default_chunker_params_invalid(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    with open_repository(archiver) as repository:
        repository.save_defaults({"chunker_params": "fixed,1"})
    if archiver.FORK_DEFAULT:
        exit_code = Repository.InvalidRepositoryConfig("x", "y").exit_code
        cmd(archiver, "create", "test", "input", exit_code=exit_code)
    else:
        with pytest.raises(Repository.InvalidRepositoryConfig):
            cmd(archiver, "create", "test", "input")


def test_defaults_missing(archivers, request):
    # repo-create always writes config/defaults, so a missing object was removed: the commands that use
    # the defaults refuse to run, unless every default is given explicitly (see check for the repair).
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", size=1024 * 80)
    cmd(archiver, "repo-create", RK_ENCRYPTION, "--compression=zstd,5")
    with open_repository(archiver) as repository:
        repository.store_delete("config/defaults")
    for args in (("create", "test", "input"), ("repo-info",)):
        if archiver.FORK_DEFAULT:
            output = cmd(archiver, *args, exit_code=Repository.DefaultsMissing("x").exit_code)
            assert "borg check --repair" in output
        else:
            with pytest.raises(Repository.DefaultsMissing):
                cmd(archiver, *args)
    cmd(archiver, "create", "--compression=lz4", "--chunker-params=fixed,4096", "test", "input")
    assert stored_compression(archiver) == {(LZ4.ID, 255)}

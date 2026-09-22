import io

import pytest

from ...cache import REFERENCED_BY_ARCHIVE, archive_reference_cache_name, load_archive_references
from ...constants import *  # NOQA
from ...crypto.key import store_hash
from ...hashindex import ChunkIndex
from ...helpers import bin_to_hex, hex_to_bin
from ...manifest import Manifest
from . import cmd, create_regular_file, create_test_files, generate_archiver_tests, open_repository

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def raw_store_objects(repository, namespace):
    """Return {name: stored bytes} of the objects in namespace, as the store sees them."""
    return {info.name: repository.store_load(f"{namespace}/{info.name}") for info in repository.store_list(namespace)}


@pytest.mark.parametrize("encryption", ["aes256-ocb", "authenticated-sha256"])
def test_index_and_cache_in_the_key_envelope(archivers, request, encryption):
    # the index/ fragments and the cache/ objects are protected like the objects in the packs: encrypted
    # and authenticated in the encrypting modes, authenticated only in the authenticated-* modes.
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path)
    cmd(archiver, "repo-create", f"--encryption={encryption}")
    cmd(archiver, "create", "test", "input")
    cmd(archiver, "check")
    cmd(archiver, "compact")
    cmd(archiver, "check")
    assert "test" in cmd(archiver, "repo-list")

    with open_repository(archiver) as repository:
        ids = [id for id, _ in repository.chunks.iteritems()]
        pack_ids = [hex_to_bin(info.name) for info in repository.store_list("packs")]
        fragments = raw_store_objects(repository, "index")
        caches = raw_store_objects(repository, "cache")
    assert ids and fragments
    references = [data for name, data in caches.items() if name.startswith(REFERENCED_BY_ARCHIVE)]
    checked_packs = caches["checked-packs"]
    assert len(references) == 1  # one archive
    for name, data in fragments.items():
        assert store_hash(data).hexdigest() == name  # borg check verifies the fragments by name
    if encryption == "aes256-ocb":
        assert not any(id in data for data in fragments.values() for id in ids)
        assert not any(id in references[0] for id in ids)
        assert not any(pack_id in checked_packs for pack_id in pack_ids)
    else:
        assert all(any(id in data for data in fragments.values()) for id in ids)
        assert any(id in references[0] for id in ids)
        assert all(pack_id in checked_packs for pack_id in pack_ids)


def test_references_cache_of_another_archive(archivers, request):
    # a references cache copied to another archive's name is ignored and rebuilt by a scan of that
    # archive, so compact does not drop objects the archive uses.
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", "--encryption=aes256-ocb")
    create_regular_file(archiver.input_path, "file1", contents=b"1" * 1000)
    cmd(archiver, "create", "archive1", "input")
    create_regular_file(archiver.input_path, "file2", contents=b"2" * 1000)
    cmd(archiver, "create", "archive2", "input")
    cmd(archiver, "compact")
    with open_repository(archiver) as repository:
        manifest = Manifest.load(repository)
        id1, id2 = (manifest.archives.get(name).id for name in ("archive1", "archive2"))
        data = repository.store_load(archive_reference_cache_name(id1))
        repository.store_store(archive_reference_cache_name(id2), data)

    output = cmd(archiver, "compact", "-v")
    assert f"Ignoring corrupted references cache of archive {bin_to_hex(id2)}." in output
    cmd(archiver, "check", "--verify-data")
    with open_repository(archiver) as repository:
        references1 = load_archive_references(repository, id1)
        references2 = load_archive_references(repository, id2)
    assert references2 is not None
    assert references2.file_count == references1.file_count + 1  # rebuilt from archive2, which has file2, too


def test_plaintext_index_fragment_of_an_older_beta(archivers, request):
    # older borg 2 betas stored the serialized chunk index as it is. such a fragment fails the
    # authentication: check still passes (without the index cross-check), a create rebuilds the index
    # from the packs, and afterwards the fragment is gone.
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path)
    cmd(archiver, "repo-create", "--encryption=aes256-ocb")
    cmd(archiver, "create", "test", "input")
    with open_repository(archiver) as repository:
        chunks = ChunkIndex()
        for id, entry in repository.chunks.iteritems():
            chunks[id] = entry._replace(flags=ChunkIndex.F_NONE, size=0)
        with io.BytesIO() as f:
            chunks.write(f)
            data = f.getvalue()
        for name in raw_store_objects(repository, "index"):
            repository.store_delete(f"index/{name}")
        plaintext_name = store_hash(data).hexdigest()
        repository.store_store(f"index/{plaintext_name}", data)

    output = cmd(archiver, "check")
    assert "Cannot cross-check packs against the chunk index" in output

    output = cmd(archiver, "create", "test2", "input")
    assert "is corrupt, rebuilding the chunk index from the packs" in output

    cmd(archiver, "compact")
    with open_repository(archiver) as repository:
        assert plaintext_name not in raw_store_objects(repository, "index")
    output = cmd(archiver, "check")
    assert "Cannot cross-check" not in output
    assert "is corrupt" not in output

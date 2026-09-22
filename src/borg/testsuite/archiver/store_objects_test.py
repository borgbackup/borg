import io

import pytest

from ...constants import *  # NOQA
from ...crypto.key import store_hash
from ...hashindex import ChunkIndex
from . import cmd, create_test_files, generate_archiver_tests, open_repository

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def raw_store_objects(repository, namespace):
    """Return {name: stored bytes} of the objects in namespace, as the store sees them."""
    return {info.name: repository.store_load(f"{namespace}/{info.name}") for info in repository.store_list(namespace)}


@pytest.mark.parametrize("encryption", ["aes256-ocb", "authenticated-sha256"])
def test_index_in_the_key_envelope(archivers, request, encryption):
    # the index/ fragments are protected like the objects in the packs: encrypted and authenticated in
    # the encrypting modes, authenticated only in the authenticated-* modes.
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
        fragments = raw_store_objects(repository, "index")
    assert ids and fragments
    for name, data in fragments.items():
        assert store_hash(data).hexdigest() == name  # borg check verifies the fragments by name
        if encryption == "aes256-ocb":
            assert not any(id in data for id in ids)
    if encryption != "aes256-ocb":
        assert all(any(id in data for data in fragments.values()) for id in ids)


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

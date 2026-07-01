import pytest

from ...constants import *  # NOQA
from ..repository_test import corrupt_chunk_on_disk
from . import cmd, src_file, open_archive, generate_archiver_tests
from .check_cmd_test import check_cmd_setup

# Repository.check() verifies packs via store.hash(name) == name. The REST backend overrides
# hash() to compute it server-side (nothing downloaded), unlike every other check_cmd scenario,
# which just exercises the generic store list/load/delete calls already covered by other
# archiver tests under "remote" (create, extract, compact, ...). So this is the one check_cmd
# path worth its own "remote" coverage; see generate_archiver_tests() for the full policy.
pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote")  # NOQA


def test_repository_check_detects_corrupted_pack(archivers, request):
    archiver = request.getfixturevalue(archivers)
    check_cmd_setup(archiver)
    archive, repository = open_archive(archiver.repository_path, "archive1")
    with repository:
        for item in archive.iter_items():
            if item.path.endswith(src_file):
                corrupt_chunk_on_disk(repository, item.chunks[-1].id)
                break
        else:
            pytest.fail("should not happen")

    output = cmd(archiver, "check", "--repository-only", exit_code=1)
    assert "is corrupted" in output

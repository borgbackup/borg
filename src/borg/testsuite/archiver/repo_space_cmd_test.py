from ...constants import *  # NOQA

from . import cmd, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote")  # NOQA


def test_repo_space_basics(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    # Initially, no space should be reserved.
    output = cmd(archiver, "repo-space")
    assert "There is 0 B reserved space in this repository." in output

    # Test reserving some space.
    output = cmd(archiver, "repo-space", "--reserve", "100M")
    # The actual size will be rounded up to a multiple of 64MiB blocks.
    # For 100MB, it should be 128MiB (2 blocks) == 134.22MB.
    assert "There is 134.22 MB reserved space in this repository now." in output

    # Check that space is reserved.
    output = cmd(archiver, "repo-space")
    assert "There is 134.22 MB reserved space in this repository." in output

    # Test freeing the space.
    output = cmd(archiver, "repo-space", "--free")
    assert "Freed 134.22 MB in repository." in output

    # Check that no space is reserved.
    output = cmd(archiver, "repo-space")
    assert "There is 0 B reserved space in this repository." in output


def test_repo_space_modify_reservation(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    # Reserve some space.
    output = cmd(archiver, "repo-space", "--reserve", "50M")
    assert "There is 67.11 MB reserved space in this repository now." in output

    # Check that space is reserved.
    output = cmd(archiver, "repo-space")
    assert "There is 67.11 MB reserved space in this repository." in output

    # Reserve more space.
    output = cmd(archiver, "repo-space", "--reserve", "100M")
    assert "There is 134.22 MB reserved space in this repository now." in output

    # Check that space is reserved.
    output = cmd(archiver, "repo-space")
    assert "There is 134.22 MB reserved space in this repository." in output

    # note: --reserve can only INCREASE the amount of reserved space.

    cmd(archiver, "repo-space", "--free")  # save space on TMPDIR


def test_repo_space_edge_cases(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    # Test reserving 0 space (should not create any reservation).
    output = cmd(archiver, "repo-space", "--reserve", "0")

    # Check that no space is reserved.
    output = cmd(archiver, "repo-space")
    assert "There is 0 B reserved space in this repository." in output

    # Test freeing when no space is reserved.
    output = cmd(archiver, "repo-space", "--free")
    assert "Freed 0 B in repository." in output

    # Test reserving a very small amount of space (1KB).
    # This should round up to at least one 64MiB block.
    output = cmd(archiver, "repo-space", "--reserve", "1K")
    assert "There is 67.11 MB reserved space in this repository now." in output

    # Check that space is reserved (should be 64MiB).
    output = cmd(archiver, "repo-space")
    assert "There is 67.11 MB reserved space in this repository." in output

    cmd(archiver, "repo-space", "--free")  # save space on TMPDIR

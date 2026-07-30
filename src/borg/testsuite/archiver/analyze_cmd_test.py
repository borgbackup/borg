import pathlib
import re

import pytest

from ...constants import *  # NOQA
from ...helpers import Error
from . import cmd, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local")  # NOQA


def test_analyze(archivers, request):
    def create_archive():
        cmd(archiver, "create", "archive", archiver.input_path)

    def analyze_archives():
        return cmd(archiver, "analyze", "-a", "archive")

    archiver = request.getfixturevalue(archivers)

    cmd(archiver, "repo-create", RK_ENCRYPTION)
    input_path = pathlib.Path(archiver.input_path)

    # 1st archive
    (input_path / "file1").write_text("1")
    create_archive()

    # 2nd archive
    (input_path / "file2").write_text("22")
    create_archive()

    assert "/input: 2" in analyze_archives()  # 2nd archive added 1 chunk for input path

    # 3rd archive
    (input_path / "file3").write_text("333")
    create_archive()

    assert "/input: 5" in analyze_archives()  # 2nd/3rd archives added 2 chunks for input path

    # 4th archive
    (input_path / "file2").unlink()
    create_archive()

    assert "/input: 7" in analyze_archives()  # 2nd/3rd archives added 2, 4th archive removed 1


def test_analyze_dedup_size(archivers, request):
    """borg analyze reports the deduplicated and exclusive size of a considered set of archives (#5741)."""
    archiver = request.getfixturevalue(archivers)

    cmd(archiver, "repo-create", RK_ENCRYPTION)
    input_path = pathlib.Path(archiver.input_path)

    # each small file becomes a single chunk of exactly its plaintext size (1000 bytes).
    # "shared" is identical in the userA and userB archives, so it deduplicates across the sets.
    (input_path / "shared").write_text("s" * 1000)
    (input_path / "a_only").write_text("a" * 1000)
    cmd(archiver, "create", "userA-1", archiver.input_path)
    cmd(archiver, "create", "userA-2", archiver.input_path)  # same content as userA-1

    (input_path / "a_only").unlink()
    (input_path / "b_only").write_text("b" * 1000)
    cmd(archiver, "create", "userB-1", archiver.input_path)

    # set = the two userA archives; rest = userB-1.
    # union of userA chunks = {shared, a_only} -> 2000 B deduplicated size of the set.
    # exclusive = chunks only in the set = {a_only} -> 1000 B (shared is also in userB-1).
    output = cmd(archiver, "analyze", "-a", "sh:userA-*")
    assert "Considered archives: 2 (of 3 in the repository)" in output
    assert re.search(r"Deduplicated size of set:\s*2\.00 kB", output)
    assert re.search(r"Exclusive size of set:\s*1\.00 kB", output)
    # every chunk is referenced by one of the three archives
    assert re.search(r"Unreferenced: 0 of \d+ chunks", output)

    # after deleting userB-1, the userA archives are all archives there are: nothing is left over
    # to compare against, so this is reported as the whole repository, without the (then trivially
    # equal) exclusive size.
    cmd(archiver, "delete", "-a", "sh:userB-*")
    output = cmd(archiver, "analyze", "-a", "sh:userA-*")
    assert "Deduplicated size of the whole repository" in output
    assert "Archives: 2 (all archives in the repository)" in output
    assert re.search(r"Deduplicated size:\s*2\.00 kB", output)
    assert "Exclusive size" not in output
    # userB-1 is soft-deleted now, so the chunks only it referenced (b_only and its
    # metadata objects) are referenced by no non-deleted archive anymore.
    assert re.search(r"Unreferenced: [1-9]\d* of \d+ chunks", output)


def test_analyze_whole_repository(archivers, request):
    """Without an archive filter, all archives are considered: report the repository as a whole."""
    archiver = request.getfixturevalue(archivers)

    cmd(archiver, "repo-create", RK_ENCRYPTION)
    input_path = pathlib.Path(archiver.input_path)
    (input_path / "file1").write_text("x" * 1000)
    cmd(archiver, "create", "one", archiver.input_path)
    (input_path / "file2").write_text("y" * 1000)
    cmd(archiver, "create", "two", archiver.input_path)

    output = cmd(archiver, "analyze")
    assert "Deduplicated size of the whole repository" in output
    assert "Archives: 2 (all archives in the repository)" in output
    assert re.search(r"Deduplicated size:\s*2\.00 kB", output)
    # every chunk is trivially exclusive to "all archives", so that line is suppressed
    assert "Exclusive size" not in output


def test_analyze_by_name(archivers, request):
    """--by-name decomposes the repository into per-name exclusive, shared and unreferenced."""
    archiver = request.getfixturevalue(archivers)

    cmd(archiver, "repo-create", RK_ENCRYPTION)
    input_path = pathlib.Path(archiver.input_path)

    # name "alpha" (2 archives, a series) and name "beta" (1 archive) share "shared";
    # each has one unique file.
    (input_path / "shared").write_text("s" * 1000)
    (input_path / "a_only").write_text("a" * 1000)
    cmd(archiver, "create", "alpha", archiver.input_path)
    cmd(archiver, "create", "alpha", archiver.input_path)  # same name = same series

    (input_path / "a_only").unlink()
    (input_path / "b_only").write_text("b" * 1000)
    cmd(archiver, "create", "beta", archiver.input_path)

    output = cmd(archiver, "analyze", "--by-name")
    assert "3 archive(s) with 2 distinct name(s)" in output
    # exclusive to each name is its own 1000 B file; "shared" is used by archives of both names
    assert re.search(r"^alpha\s+2\s+1\.00 kB", output, re.MULTILINE)
    assert re.search(r"^beta\s+1\s+1\.00 kB", output, re.MULTILINE)
    assert re.search(r"\(shared by 2\+ names\)\s+1\.00 kB", output)
    # the rows add up: 1000 (alpha) + 1000 (beta) + 1000 (shared) = 3000 B
    assert re.search(r"total \(deduplicated\)\s+3\s+3\.00 kB", output)


def test_analyze_by_name_rejects_filters(archivers, request):
    """--by-name is repository-wide, so combining it with an archive filter is an error."""
    archiver = request.getfixturevalue(archivers)

    cmd(archiver, "repo-create", RK_ENCRYPTION)
    input_path = pathlib.Path(archiver.input_path)
    (input_path / "file1").write_text("x" * 1000)
    cmd(archiver, "create", "one", archiver.input_path)

    with pytest.raises(Error, match="cannot be combined with archive filters"):
        cmd(archiver, "analyze", "--by-name", "-a", "sh:one")


def test_analyze_unreferenced_chunks(archivers, request):
    """analyze reports chunks referenced by no non-deleted archive - what compact could free."""
    archiver = request.getfixturevalue(archivers)

    cmd(archiver, "repo-create", RK_ENCRYPTION)
    input_path = pathlib.Path(archiver.input_path)
    (input_path / "keep").write_text("k" * 1000)
    cmd(archiver, "create", "keeper", archiver.input_path)
    (input_path / "gone").write_text("g" * 1000)
    cmd(archiver, "create", "goner", archiver.input_path)

    # nothing deleted yet: all chunks are referenced
    output = cmd(archiver, "analyze", "-a", "sh:keeper")
    assert re.search(r"Unreferenced chunks:\s*n/a\s*0 B", output)
    assert re.search(r"Unreferenced: 0 of \d+ chunks", output)

    # deleting "goner" orphans its chunks; compact has not run yet, so they are still there
    cmd(archiver, "delete", "-a", "sh:goner")
    output = cmd(archiver, "analyze", "-a", "sh:keeper")
    match = re.search(r"Unreferenced: (\d+) of \d+ chunks", output)
    assert match and int(match.group(1)) > 0

    # compact frees exactly those chunks, so afterwards nothing is unreferenced anymore
    cmd(archiver, "compact")
    output = cmd(archiver, "analyze", "-a", "sh:keeper")
    assert re.search(r"Unreferenced: 0 of \d+ chunks", output)


def test_analyze_dedup_size_single_archive(archivers, request):
    """A single matching archive still reports dedup sizes and skips the >=2-archive hot-spot report."""
    archiver = request.getfixturevalue(archivers)

    cmd(archiver, "repo-create", RK_ENCRYPTION)
    input_path = pathlib.Path(archiver.input_path)
    (input_path / "file1").write_text("x" * 1000)
    cmd(archiver, "create", "only-1", archiver.input_path)
    # a second archive that is not selected, so the selection is a real subset
    (input_path / "file2").write_text("y" * 1000)
    cmd(archiver, "create", "other-1", archiver.input_path)

    output = cmd(archiver, "analyze", "-a", "sh:only-*")
    assert "Considered archives: 1 (of 2 in the repository)" in output
    assert re.search(r"Deduplicated size of set:\s*1\.00 kB", output)
    # file1 is also in other-1, so nothing is exclusive to only-1
    assert re.search(r"Exclusive size of set:\s*0 B", output)

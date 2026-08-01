import json
import pathlib
import re

import pytest

from ...constants import *  # NOQA
from ...helpers import Error, format_file_size
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


def test_analyze_json(archivers, request):
    """--json reports the same numbers as the text report, as raw byte values."""
    archiver = request.getfixturevalue(archivers)

    cmd(archiver, "repo-create", RK_ENCRYPTION)
    input_path = pathlib.Path(archiver.input_path)

    # same layout as test_analyze_dedup_size: each file is one 1000 byte chunk.
    (input_path / "shared").write_text("s" * 1000)
    (input_path / "a_only").write_text("a" * 1000)
    cmd(archiver, "create", "userA-1", archiver.input_path)
    cmd(archiver, "create", "userA-2", archiver.input_path)

    (input_path / "a_only").unlink()
    (input_path / "b_only").write_text("b" * 1000)
    cmd(archiver, "create", "userB-1", archiver.input_path)

    json_output = cmd(archiver, "analyze", "-a", "sh:userA-*", "--json")
    dedup_size = json.loads(json_output)["dedup_size"]
    assert dedup_size["considered_archives"] == 2
    assert dedup_size["total_archives"] == 3
    assert dedup_size["whole_repository"] is False
    assert dedup_size["deduplicated"]["source_size"] == 2000  # {shared, a_only}
    assert dedup_size["exclusive"]["source_size"] == 1000  # {a_only}, "shared" is also in userB-1
    assert dedup_size["unreferenced"] == {"stored_size": 0, "chunks": 0}
    assert dedup_size["missing_chunks"] == 0
    assert dedup_size["total_chunks"] > 0

    # the stored sizes are compression dependent, so relate them to the text report instead of
    # hardcoding them: both columns of a row are what the text report formats from these values.
    text = cmd(archiver, "analyze", "-a", "sh:userA-*")
    for key, label in [("deduplicated", "Deduplicated size of set:"), ("exclusive", "Exclusive size of set:")]:
        source, stored = dedup_size[key]["source_size"], dedup_size[key]["stored_size"]
        assert stored > 0
        row = rf"^{re.escape(label)}\s+{re.escape(format_file_size(source))}\s+{re.escape(format_file_size(stored))}\s"
        assert re.search(row, text, re.MULTILINE)

    # the text report itself is not printed in JSON mode
    assert "Deduplicated size of set:" not in json_output


def test_analyze_json_whole_repository(archivers, request):
    """Without an archive filter every chunk is trivially exclusive, so no exclusive size is given."""
    archiver = request.getfixturevalue(archivers)

    cmd(archiver, "repo-create", RK_ENCRYPTION)
    input_path = pathlib.Path(archiver.input_path)
    (input_path / "file1").write_text("x" * 1000)
    cmd(archiver, "create", "one", archiver.input_path)
    (input_path / "file2").write_text("y" * 1000)
    cmd(archiver, "create", "two", archiver.input_path)

    dedup_size = json.loads(cmd(archiver, "analyze", "--json"))["dedup_size"]
    assert dedup_size["whole_repository"] is True
    assert dedup_size["considered_archives"] == 2
    assert dedup_size["total_archives"] == 2
    assert dedup_size["deduplicated"]["source_size"] == 2000
    assert "exclusive" not in dedup_size


def test_analyze_json_hotspots(archivers, request):
    """The hot spots are a list of path/size objects, busiest first; null if they were not computed."""
    archiver = request.getfixturevalue(archivers)

    cmd(archiver, "repo-create", RK_ENCRYPTION)
    input_path = pathlib.Path(archiver.input_path)

    (input_path / "file1").write_text("1")
    cmd(archiver, "create", "archive", archiver.input_path)

    # only one matching archive: nothing to compare against, so hot spots are not computed
    assert json.loads(cmd(archiver, "analyze", "-a", "archive", "--json"))["hotspots"] is None

    (input_path / "file2").write_text("22")
    cmd(archiver, "create", "archive", archiver.input_path)

    # the 2nd archive added one chunk of 2 bytes below the input directory
    hotspots = json.loads(cmd(archiver, "analyze", "-a", "archive", "--json"))["hotspots"]
    assert [hotspot for hotspot in hotspots if hotspot["path"].endswith("/input")] == [
        {"path": str(input_path).removeprefix("/"), "size": 2}
    ]
    # busiest directory first, as in the text report
    assert [hotspot["size"] for hotspot in hotspots] == sorted((hotspot["size"] for hotspot in hotspots), reverse=True)


def test_analyze_json_by_name(archivers, request):
    """--by-name --json decomposes the repository into per-name exclusive, shared and unreferenced."""
    archiver = request.getfixturevalue(archivers)

    cmd(archiver, "repo-create", RK_ENCRYPTION)
    input_path = pathlib.Path(archiver.input_path)

    # same layout as test_analyze_by_name
    (input_path / "shared").write_text("s" * 1000)
    (input_path / "a_only").write_text("a" * 1000)
    cmd(archiver, "create", "alpha", archiver.input_path)
    cmd(archiver, "create", "alpha", archiver.input_path)

    (input_path / "a_only").unlink()
    (input_path / "b_only").write_text("b" * 1000)
    cmd(archiver, "create", "beta", archiver.input_path)

    result = json.loads(cmd(archiver, "analyze", "--by-name", "--json"))
    assert "dedup_size" not in result and "hotspots" not in result
    by_name = result["by_name"]

    assert by_name["archives"] == 3
    assert {entry["name"]: entry["archives"] for entry in by_name["names"]} == {"alpha": 2, "beta": 1}
    assert {entry["name"]: entry["source_size"] for entry in by_name["names"]} == {"alpha": 1000, "beta": 1000}
    assert by_name["shared"]["source_size"] == 1000
    assert by_name["total"]["archives"] == 3
    assert by_name["total"]["source_size"] == 3000  # 1000 alpha + 1000 beta + 1000 shared
    assert by_name["total"]["stored_size"] > 0
    assert by_name["missing_chunks"] == 0

    # every chunk is counted in exactly one row, so the rows add up to the total
    for size in ("source_size", "stored_size"):
        assert sum(entry[size] for entry in by_name["names"]) + by_name["shared"][size] == by_name["total"][size]
    # biggest exclusive consumer first
    assert [entry["stored_size"] for entry in by_name["names"]] == sorted(
        (entry["stored_size"] for entry in by_name["names"]), reverse=True
    )

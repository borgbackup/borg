import json

from ...constants import *  # NOQA
from . import cmd, create_regular_file, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,binary")  # NOQA

# terse format for tests that only care about which archives/items matched
FMT = "{archiveid:.8} {archivename} {path}{NL}"


def short_ids(archiver):
    """map archive name -> short (8 hex digits) archive id, as printed by the default find output"""
    output = cmd(archiver, "repo-list", "--json")
    return {archive["name"]: archive["id"][:8] for archive in json.loads(output)["archives"]}


def test_find_basic(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_regular_file(archiver.input_path, "file1", size=1024)
    cmd(archiver, "create", "archive1", "input")
    create_regular_file(archiver.input_path, "file2", size=1024)
    cmd(archiver, "create", "archive2", "input")
    ids = short_ids(archiver)

    # file1 is in both archives, output ordered from newest to oldest archive.
    output = cmd(archiver, "find", "input/file1", "--format", FMT)
    assert output.splitlines() == [f"{ids['archive2']} archive2 input/file1", f"{ids['archive1']} archive1 input/file1"]

    # file2 is only in the second archive.
    output = cmd(archiver, "find", "input/file2", "--format", FMT)
    assert output.splitlines() == [f"{ids['archive2']} archive2 input/file2"]

    # a path matches itself and everything below it.
    output = cmd(archiver, "find", "input", "--format", FMT)
    lines = output.splitlines()
    # ordered by archive; within one archive, the items come in the order stored in the archive.
    assert lines[0] == f"{ids['archive2']} archive2 input"
    assert set(lines[1:3]) == {f"{ids['archive2']} archive2 input/file1", f"{ids['archive2']} archive2 input/file2"}
    assert lines[3:] == [f"{ids['archive1']} archive1 input", f"{ids['archive1']} archive1 input/file1"]

    # without any PATH, all items of all archives match.
    assert cmd(archiver, "find", "--format", FMT) == output

    # no match: no output.
    output = cmd(archiver, "find", "input/does-not-exist", "--format", FMT)
    assert output == ""


def test_find_patterns(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_regular_file(archiver.input_path, "dir1/file.jpg", size=1)
    create_regular_file(archiver.input_path, "dir2/file.txt", size=1)
    cmd(archiver, "create", "archive1", "input")
    ids = short_ids(archiver)

    output = cmd(archiver, "find", "sh:**/*.jpg", "--format", FMT)
    assert output.splitlines() == [f"{ids['archive1']} archive1 input/dir1/file.jpg"]

    output = cmd(archiver, "find", "fm:*.txt", "--format", FMT)
    assert output.splitlines() == [f"{ids['archive1']} archive1 input/dir2/file.txt"]

    output = cmd(archiver, "find", "input", "--exclude", "sh:**/*.jpg", "--format", FMT)
    assert "file.jpg" not in output
    assert f"{ids['archive1']} archive1 input/dir2/file.txt" in output

    output = cmd(archiver, "find", "--pattern", "+ re:\\.jpg$", "--pattern", "- re:^.*$", "--format", FMT)
    assert output.splitlines() == [f"{ids['archive1']} archive1 input/dir1/file.jpg"]


def test_find_archive_filters(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_regular_file(archiver.input_path, "file1", size=1024)
    cmd(archiver, "create", "archive1", "input")
    cmd(archiver, "create", "archive2", "input")
    ids = short_ids(archiver)

    output = cmd(archiver, "find", "input/file1", "--last", "1", "--format", FMT)
    assert output.splitlines() == [f"{ids['archive2']} archive2 input/file1"]

    output = cmd(archiver, "find", "input/file1", "--first", "1", "--format", FMT)
    assert output.splitlines() == [f"{ids['archive1']} archive1 input/file1"]

    output = cmd(archiver, "find", "input/file1", "-a", "archive1", "--format", FMT)
    assert output.splitlines() == [f"{ids['archive1']} archive1 input/file1"]


def test_find_default_format(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_regular_file(archiver.input_path, "file1", size=1024)
    cmd(archiver, "create", "archive1", "input")
    cmd(archiver, "create", "archive2", "input")
    ids = short_ids(archiver)

    # the default format is the borg list default format with "{archiveid:.8} {archivename} " prepended.
    find_output = cmd(archiver, "find", "input/file1")
    expected = []
    for name in ("archive2", "archive1"):  # newest to oldest
        for line in cmd(archiver, "list", name, "input/file1").splitlines():
            expected.append(f"{ids[name]} {name} {line}")
    assert find_output.splitlines() == expected


def test_find_format(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_regular_file(archiver.input_path, "file1", size=1024)
    cmd(archiver, "create", "archive1", "input")

    output = cmd(archiver, "find", "input/file1", "--format", "{size} {path}{NL}")
    assert output.splitlines() == ["1024 input/file1"]


def test_find_json_lines(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_regular_file(archiver.input_path, "file1", size=1024)
    cmd(archiver, "create", "archive1", "input")
    cmd(archiver, "create", "archive2", "input")
    ids = short_ids(archiver)

    output = cmd(archiver, "find", "input/file1", "--json-lines")
    rows = [json.loads(line) for line in output.splitlines()]
    # the default format contains {archiveid} and {archivename}, so they are present in the JSON output.
    assert [(row["archiveid"][:8], row["archivename"], row["path"]) for row in rows] == [
        (ids["archive2"], "archive2", "input/file1"),
        (ids["archive1"], "archive1", "input/file1"),
    ]

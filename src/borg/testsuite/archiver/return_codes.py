from ...constants import *  # NOQA
from . import cmd_fixture, changedir  # NOQA


def test_return_codes(cmd_fixture, tmpdir):
    repo = tmpdir.mkdir("repo")
    input = tmpdir.mkdir("input")
    output = tmpdir.mkdir("output")
    input.join("test_file").write("content")
    rc, out = cmd_fixture("--repo=%s" % str(repo), "rcreate", "--encryption=none")
    assert rc == EXIT_SUCCESS
    rc, out = cmd_fixture("--repo=%s" % repo, "create", "archive", str(input))
    assert rc == EXIT_SUCCESS
    with changedir(str(output)):
        rc, out = cmd_fixture("--repo=%s" % repo, "extract", "archive")
        assert rc == EXIT_SUCCESS
    rc, out = cmd_fixture("--repo=%s" % repo, "extract", "archive", "does/not/match")
    assert rc == EXIT_WARNING  # pattern did not match
    rc, out = cmd_fixture("--repo=%s" % repo, "create", "archive", str(input))
    assert rc == EXIT_ERROR  # duplicate archive name

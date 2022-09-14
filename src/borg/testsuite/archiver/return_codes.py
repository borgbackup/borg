from ...constants import *  # NOQA
from . import cmd, changedir


def test_return_codes(cmd, tmpdir):
    repo = tmpdir.mkdir("repo")
    input = tmpdir.mkdir("input")
    output = tmpdir.mkdir("output")
    input.join("test_file").write("content")
    rc, out = cmd("--repo=%s" % str(repo), "rcreate", "--encryption=none")
    assert rc == EXIT_SUCCESS
    rc, out = cmd("--repo=%s" % repo, "create", "archive", str(input))
    assert rc == EXIT_SUCCESS
    with changedir(str(output)):
        rc, out = cmd("--repo=%s" % repo, "extract", "archive")
        assert rc == EXIT_SUCCESS
    rc, out = cmd("--repo=%s" % repo, "extract", "archive", "does/not/match")
    assert rc == EXIT_WARNING  # pattern did not match
    rc, out = cmd("--repo=%s" % repo, "create", "archive", str(input))
    assert rc == EXIT_ERROR  # duplicate archive name

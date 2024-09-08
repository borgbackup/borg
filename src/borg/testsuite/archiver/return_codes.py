from ...archive import Archive
from ...constants import *  # NOQA
from ...helpers import IncludePatternNeverMatchedWarning
from . import cmd_fixture, changedir  # NOQA


def test_return_codes(cmd_fixture, tmpdir):
    repo = tmpdir / "repo"  # borg creates the directory
    input = tmpdir.mkdir("input")
    output = tmpdir.mkdir("output")
    input.join("test_file").write("content")
    rc, out = cmd_fixture("--repo=%s" % str(repo), "repo-create", "--encryption=none")
    assert rc == EXIT_SUCCESS
    rc, out = cmd_fixture("--repo=%s" % repo, "create", "archive", str(input))
    assert rc == EXIT_SUCCESS
    with changedir(str(output)):
        rc, out = cmd_fixture("--repo=%s" % repo, "extract", "archive")
        assert rc == EXIT_SUCCESS
    rc, out = cmd_fixture("--repo=%s" % repo, "extract", "archive", "does/not/match")
    assert rc == IncludePatternNeverMatchedWarning().exit_code
    rc, out = cmd_fixture("--repo=%s" % repo, "create", "archive", str(input))
    assert rc == Archive.AlreadyExists().exit_code

import os

from ...constants import *  # NOQA
from ...helpers import IncludePatternNeverMatchedWarning
from ...repository import Repository
from . import cmd, cmd_fixture, changedir, generate_archiver_tests  # NOQA

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


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


def test_exit_codes(archivers, request, tmpdir, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    # we create the repo path, but do NOT initialize the borg repo,
    # so the borg create commands are expected to fail with DoesNotExist (was: InvalidRepository in borg 1.4).
    os.makedirs(archiver.repository_path)
    monkeypatch.setenv("BORG_EXIT_CODES", "classic")
    cmd(archiver, "create", "archive", "input", fork=True, exit_code=EXIT_ERROR)
    monkeypatch.setenv("BORG_EXIT_CODES", "modern")
    cmd(archiver, "create", "archive", "input", fork=True, exit_code=Repository.DoesNotExist.exit_mcode)

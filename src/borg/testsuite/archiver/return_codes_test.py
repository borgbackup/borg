import os

from ...constants import *  # NOQA
from ...helpers import IncludePatternNeverMatchedWarning
from ...repository import Repository
from . import cmd, changedir, generate_archiver_tests  # NOQA

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def test_return_codes(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", "--encryption=none")
    cmd(archiver, "create", "archive", "input")
    with changedir("output"):
        cmd(archiver, "extract", "archive")
    cmd(
        archiver,
        "extract",
        "archive",
        "does/not/match",
        fork=True,
        exit_code=IncludePatternNeverMatchedWarning().exit_code,
    )


def test_exit_codes(archivers, request, monkeypatch):
    archiver = request.getfixturevalue(archivers)
    # we create the repo path, but do NOT initialize the borg repo,
    # so the borg create commands are expected to fail with DoesNotExist (was: InvalidRepository in borg 1.4).
    os.makedirs(archiver.repository_path)
    monkeypatch.setenv("BORG_EXIT_CODES", "classic")
    cmd(archiver, "create", "archive", "input", fork=True, exit_code=EXIT_ERROR)
    monkeypatch.setenv("BORG_EXIT_CODES", "modern")
    cmd(archiver, "create", "archive", "input", fork=True, exit_code=Repository.DoesNotExist.exit_mcode)

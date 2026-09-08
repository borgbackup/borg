import errno
import gc
import os
import weakref

from ...archiver import Archiver
from ...constants import *  # NOQA
from ...helpers import IncludePatternNeverMatchedWarning, BackupError, BackupOSError, BackupWarning
from ...helpers import get_reset_ec, init_ec_warnings, modern_ec
from ...logger import setup_logging
from ...repository import Repository
from . import cmd, changedir, generate_archiver_tests  # NOQA

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,binary")  # NOQA


def test_return_codes(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", "--encryption=none-sha256")
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


def test_print_warning_instance_does_not_retain_exception():
    """The warnings bookkeeping for the final exit code must not keep the wrapped exception alive.

    An exception references its traceback and thus the frames (with all their locals, e.g. the chunk
    data that was being written) of the code that failed - keeping that per warning would leak memory.
    """
    setup_logging()
    init_ec_warnings()
    archiver = Archiver()
    try:
        raise BackupOSError("write", OSError(errno.ENOSPC, "No space left on device"))
    except BackupError as exc:
        exc_ref = weakref.ref(exc)
        archiver.print_warning_instance(BackupWarning("input/file", exc))
    # "except ... as exc" unbinds exc when its block ends, so the exception is only still alive if the
    # warnings bookkeeping references it. CPython frees it right away (refcounting), PyPy only when
    # its GC runs, so collect explicitly before looking at the weakref.
    gc.collect()
    assert exc_ref() is None
    # the warning was recorded for the exit code, though.
    assert get_reset_ec() == (BackupOSError.exit_mcode if modern_ec else EXIT_WARNING)

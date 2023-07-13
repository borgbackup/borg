import pytest

from ...constants import *  # NOQA
from ...helpers import EXIT_ERROR
from ...locking import LockFailed
from ...remote import RemoteRepository
from .. import llfuse
from . import cmd, create_src_archive, RK_ENCRYPTION, read_only, fuse_mount


def test_readonly_check(archiver):
    repo_location, repo_path = archiver.repository_location, archiver.repository_path
    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    create_src_archive(archiver, "test")

    with read_only(repo_path):
        # verify that command normally doesn't work with read-only repo
        if archiver.FORK_DEFAULT:
            cmd(archiver, f"--repo={repo_location}", "check", "--verify-data", exit_code=EXIT_ERROR)
        else:
            with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                cmd(archiver, f"--repo={repo_location}", "check", "--verify-data")
            if isinstance(excinfo.value, RemoteRepository.RPCError):
                assert excinfo.value.exception_class == "LockFailed"
        # verify that command works with read-only repo when using --bypass-lock
        cmd(archiver, f"--repo={repo_location}", "check", "--verify-data", "--bypass-lock")


def test_readonly_diff(archiver):
    repo_location, repo_path = archiver.repository_location, archiver.repository_path
    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    create_src_archive(archiver, "a")
    create_src_archive(archiver, "b")

    with read_only(repo_path):
        # verify that command normally doesn't work with read-only repo
        if archiver.FORK_DEFAULT:
            cmd(archiver, f"--repo={repo_location}", "diff", "a", "b", exit_code=EXIT_ERROR)
        else:
            with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                cmd(archiver, f"--repo={repo_location}", "diff", "a", "b")
            if isinstance(excinfo.value, RemoteRepository.RPCError):
                assert excinfo.value.exception_class == "LockFailed"
        # verify that command works with read-only repo when using --bypass-lock
        cmd(archiver, f"--repo={repo_location}", "diff", "a", "b", "--bypass-lock")


def test_readonly_export_tar(archiver):
    repo_location, repo_path = archiver.repository_location, archiver.repository_path
    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    create_src_archive(archiver, "test")

    with read_only(repo_path):
        # verify that command normally doesn't work with read-only repo
        if archiver.FORK_DEFAULT:
            cmd(archiver, f"--repo={repo_location}", "export-tar", "test", "test.tar", exit_code=EXIT_ERROR)
        else:
            with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                cmd(archiver, f"--repo={repo_location}", "export-tar", "test", "test.tar")
            if isinstance(excinfo.value, RemoteRepository.RPCError):
                assert excinfo.value.exception_class == "LockFailed"
        # verify that command works with read-only repo when using --bypass-lock
        cmd(archiver, f"--repo={repo_location}", "export-tar", "test", "test.tar", "--bypass-lock")


def test_readonly_extract(archiver):
    repo_location, repo_path = archiver.repository_location, archiver.repository_path
    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    create_src_archive(archiver, "test")

    with read_only(repo_path):
        # verify that command normally doesn't work with read-only repo
        if archiver.FORK_DEFAULT:
            cmd(archiver, f"--repo={repo_location}", "extract", "test", exit_code=EXIT_ERROR)
        else:
            with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                cmd(archiver, f"--repo={repo_location}", "extract", "test")
            if isinstance(excinfo.value, RemoteRepository.RPCError):
                assert excinfo.value.exception_class == "LockFailed"
        # verify that command works with read-only repo when using --bypass-lock
        cmd(archiver, f"--repo={repo_location}", "extract", "test", "--bypass-lock")


def test_readonly_info(archiver):
    repo_location, repo_path = archiver.repository_location, archiver.repository_path
    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    create_src_archive(archiver, "test")

    with read_only(repo_path):
        # verify that command normally doesn't work with read-only repo
        if archiver.FORK_DEFAULT:
            cmd(archiver, f"--repo={repo_location}", "rinfo", exit_code=EXIT_ERROR)
        else:
            with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                cmd(archiver, f"--repo={repo_location}", "rinfo")
            if isinstance(excinfo.value, RemoteRepository.RPCError):
                assert excinfo.value.exception_class == "LockFailed"
        # verify that command works with read-only repo when using --bypass-lock
        cmd(archiver, f"--repo={repo_location}", "rinfo", "--bypass-lock")


def test_readonly_list(archiver):
    repo_location, repo_path = archiver.repository_location, archiver.repository_path
    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    create_src_archive(archiver, "test")

    with read_only(repo_path):
        # verify that command normally doesn't work with read-only repo
        if archiver.FORK_DEFAULT:
            cmd(archiver, f"--repo={repo_location}", "rlist", exit_code=EXIT_ERROR)
        else:
            with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                cmd(archiver, f"--repo={repo_location}", "rlist")
            if isinstance(excinfo.value, RemoteRepository.RPCError):
                assert excinfo.value.exception_class == "LockFailed"
        # verify that command works with read-only repo when using --bypass-lock
        cmd(archiver, f"--repo={repo_location}", "rlist", "--bypass-lock")


@pytest.mark.skipif(not llfuse, reason="llfuse not installed")
def test_readonly_mount(archiver):
    repo_location, repo_path = archiver.repository_location, archiver.repository_path
    cmd(archiver, f"--repo={repo_location}", "rcreate", RK_ENCRYPTION)
    create_src_archive(archiver, "test")

    with read_only(repo_path):
        # verify that command normally doesn't work with read-only repo
        if archiver.FORK_DEFAULT:
            with fuse_mount(archiver, repo_location, exit_code=EXIT_ERROR):
                pass
        else:
            with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                # self.fuse_mount always assumes fork=True, so for this test we have to set fork=False manually
                with fuse_mount(archiver, repo_location, fork=False):
                    pass
            if isinstance(excinfo.value, RemoteRepository.RPCError):
                assert excinfo.value.exception_class == "LockFailed"
        # verify that command works with read-only repo when using --bypass-lock
        with fuse_mount(archiver, repo_location, None, "--bypass-lock"):
            pass

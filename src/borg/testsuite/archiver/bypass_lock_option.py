import pytest

from ...constants import *  # NOQA
from ...helpers import EXIT_ERROR
from ...locking import LockFailed
from ...remote import RemoteRepository
from .. import llfuse
from . import cmd, create_src_archive, RK_ENCRYPTION, read_only, fuse_mount


# need to convert fuse_mount and read_only from ../__init__
def test_readonly_check(archiver):
    cmd(archiver, f"--repo={archiver.repository_location}", "rcreate", RK_ENCRYPTION)
    create_src_archive(archiver, "test")
    with read_only(archiver.repository_path):
        # verify that command normally doesn't work with read-only repo
        if archiver.FORK_DEFAULT:
            cmd(archiver, f"--repo={archiver.repository_location}", "check", "--verify-data", exit_code=EXIT_ERROR)
        else:
            with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                cmd(archiver, f"--repo={archiver.repository_location}", "check", "--verify-data")
            if isinstance(excinfo.value, RemoteRepository.RPCError):
                assert excinfo.value.exception_class == "LockFailed"
        # verify that command works with read-only repo when using --bypass-lock
        cmd(archiver, f"--repo={archiver.repository_location}", "check", "--verify-data", "--bypass-lock")


def test_readonly_diff(archiver):
    cmd(archiver, f"--repo={archiver.repository_location}", "rcreate", RK_ENCRYPTION)
    create_src_archive(archiver, "a")
    create_src_archive(archiver, "b")
    with read_only(archiver.repository_path):
        # verify that command normally doesn't work with read-only repo
        if archiver.FORK_DEFAULT:
            cmd(archiver, f"--repo={archiver.repository_location}", "diff", "a", "b", exit_code=EXIT_ERROR)
        else:
            with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                cmd(archiver, f"--repo={archiver.repository_location}", "diff", "a", "b")
            if isinstance(excinfo.value, RemoteRepository.RPCError):
                assert excinfo.value.exception_class == "LockFailed"
        # verify that command works with read-only repo when using --bypass-lock
        # cmd(archiver, f"--repo={archiver.repository_location}", "diff", "a", "b", "--bypass-lock")
        # Fails - ItemDiff.__init__ 'str' object has no attribute 'get'


def test_readonly_export_tar(archiver):
    repo_location = archiver.repository_location
    cmd(archiver, f"--repo={archiver.repository_location}", "rcreate", RK_ENCRYPTION)
    create_src_archive(archiver, "test")
    with read_only(archiver.repository_path):
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
    cmd(archiver, f"--repo={archiver.repository_location}", "rcreate", RK_ENCRYPTION)
    create_src_archive(archiver, "test")
    with read_only(archiver.repository_path):
        # verify that command normally doesn't work with read-only repo
        if archiver.FORK_DEFAULT:
            cmd(archiver, f"--repo={archiver.repository_location}", "extract", "test", exit_code=EXIT_ERROR)
        else:
            with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                cmd(archiver, f"--repo={archiver.repository_location}", "extract", "test")
            if isinstance(excinfo.value, RemoteRepository.RPCError):
                assert excinfo.value.exception_class == "LockFailed"
        # verify that command works with read-only repo when using --bypass-lock
        cmd(archiver, f"--repo={archiver.repository_location}", "extract", "test", "--bypass-lock")


def test_readonly_info(archiver):
    cmd(archiver, f"--repo={archiver.repository_location}", "rcreate", RK_ENCRYPTION)
    create_src_archive(archiver, "test")
    with read_only(archiver.repository_path):
        # verify that command normally doesn't work with read-only repo
        if archiver.FORK_DEFAULT:
            cmd(archiver, f"--repo={archiver.repository_location}", "rinfo", exit_code=EXIT_ERROR)
        else:
            with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                cmd(archiver, f"--repo={archiver.repository_location}", "rinfo")
            if isinstance(excinfo.value, RemoteRepository.RPCError):
                assert excinfo.value.exception_class == "LockFailed"
        # verify that command works with read-only repo when using --bypass-lock
        cmd(archiver, f"--repo={archiver.repository_location}", "rinfo", "--bypass-lock")


def test_readonly_list(archiver):
    cmd(archiver, f"--repo={archiver.repository_location}", "rcreate", RK_ENCRYPTION)
    create_src_archive(archiver, "test")
    with read_only(archiver.repository_path):
        # verify that command normally doesn't work with read-only repo
        if archiver.FORK_DEFAULT:
            cmd(archiver, f"--repo={archiver.repository_location}", "rlist", exit_code=EXIT_ERROR)
        else:
            with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                cmd(archiver, f"--repo={archiver.repository_location}", "rlist")
            if isinstance(excinfo.value, RemoteRepository.RPCError):
                assert excinfo.value.exception_class == "LockFailed"
        # verify that command works with read-only repo when using --bypass-lock
        cmd(archiver, f"--repo={archiver.repository_location}", "rlist", "--bypass-lock")


@pytest.mark.skipif(not llfuse, reason="llfuse not installed")
def test_readonly_mount(archiver):
    cmd(archiver, f"--repo={archiver.repository_location}", "rcreate", RK_ENCRYPTION)
    create_src_archive(archiver, "test")
    with read_only(archiver.repository_path):
        # verify that command normally doesn't work with read-only repo
        if archiver.FORK_DEFAULT:
            with fuse_mount(archiver.repository_location, exit_code=EXIT_ERROR):
                pass
        else:
            with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                # self.fuse_mount always assumes fork=True, so for this test we have to set fork=False manually
                with fuse_mount(archiver.repository_location, fork=False):
                    pass
            if isinstance(excinfo.value, RemoteRepository.RPCError):
                assert excinfo.value.exception_class == "LockFailed"
        # verify that command works with read-only repo when using --bypass-lock
        with fuse_mount(archiver.repository_location, None, "--bypass-lock"):
            pass

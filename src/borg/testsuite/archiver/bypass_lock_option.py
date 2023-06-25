import unittest

import pytest

from ...constants import *  # NOQA
from ...helpers import EXIT_ERROR
from ...locking import LockFailed
from ...remote import RemoteRepository
from .. import llfuse


# need to convert fuse_mount and read_only from ../__init__
def test_readonly_check(archiver_setup, cmd_fixture, create_src_archive):
    cmd_fixture(f"--repo={archiver_setup.repository_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
    create_src_archive("test")
    with read_only(archiver_setup.repository_path):
        # verify that command normally doesn't work with read-only repo
        if archiver_setup.FORK_DEFAULT:
            cmd_fixture(f"--repo={archiver_setup.repository_location}", "check", "--verify-data", exit_code=EXIT_ERROR)
        else:
            with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                cmd_fixture(f"--repo={archiver_setup.repository_location}", "check", "--verify-data")
            if isinstance(excinfo.value, RemoteRepository.RPCError):
                assert excinfo.value.exception_class == "LockFailed"
        # verify that command works with read-only repo when using --bypass-lock
        cmd_fixture(f"--repo={archiver_setup.repository_location}", "check", "--verify-data", "--bypass-lock")


def test_readonly_diff(archiver_setup, cmd_fixture, create_src_archive):
    cmd_fixture(f"--repo={archiver_setup.repository_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
    create_src_archive("a")
    create_src_archive("b")
    with read_only(archiver_setup.repository_path):
        # verify that command normally doesn't work with read-only repo
        if archiver_setup.FORK_DEFAULT:
            cmd_fixture(f"--repo={archiver_setup.repository_location}", "diff", "a", "b", exit_code=EXIT_ERROR)
        else:
            with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                cmd_fixture(f"--repo={archiver_setup.repository_location}", "diff", "a", "b")
            if isinstance(excinfo.value, RemoteRepository.RPCError):
                assert excinfo.value.exception_class == "LockFailed"
        # verify that command works with read-only repo when using --bypass-lock
        cmd_fixture(f"--repo={archiver_setup.repository_location}", "diff", "a", "b", "--bypass-lock")


def test_readonly_export_tar(archiver_setup, cmd_fixture, create_src_archive):
    repo_location = archiver_setup.repository_location
    cmd_fixture(f"--repo={archiver_setup.repository_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
    create_src_archive("test")
    with read_only(archiver_setup.repository_path):
        # verify that command normally doesn't work with read-only repo
        if archiver_setup.FORK_DEFAULT:
            cmd_fixture(f"--repo={repo_location}", "export-tar", "test", "test.tar", exit_code=EXIT_ERROR)
        else:
            with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                cmd_fixture(f"--repo={repo_location}", "export-tar", "test", "test.tar")
            if isinstance(excinfo.value, RemoteRepository.RPCError):
                assert excinfo.value.exception_class == "LockFailed"
        # verify that command works with read-only repo when using --bypass-lock
        cmd_fixture(f"--repo={repo_location}", "export-tar", "test", "test.tar", "--bypass-lock")


def test_readonly_extract(archiver_setup, cmd_fixture, create_src_archive):
    cmd_fixture(f"--repo={archiver_setup.repository_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
    create_src_archive("test")
    with read_only(archiver_setup.repository_path):
        # verify that command normally doesn't work with read-only repo
        if archiver_setup.FORK_DEFAULT:
            cmd_fixture(f"--repo={archiver_setup.repository_location}", "extract", "test", exit_code=EXIT_ERROR)
        else:
            with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                cmd_fixture(f"--repo={archiver_setup.repository_location}", "extract", "test")
            if isinstance(excinfo.value, RemoteRepository.RPCError):
                assert excinfo.value.exception_class == "LockFailed"
        # verify that command works with read-only repo when using --bypass-lock
        cmd_fixture(f"--repo={archiver_setup.repository_location}", "extract", "test", "--bypass-lock")


def test_readonly_info(archiver_setup, cmd_fixture, create_src_archive):
    cmd_fixture(f"--repo={archiver_setup.repository_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
    create_src_archive("test")
    with read_only(archiver_setup.repository_path):
        # verify that command normally doesn't work with read-only repo
        if archiver_setup.FORK_DEFAULT:
            cmd_fixture(f"--repo={archiver_setup.repository_location}", "rinfo", exit_code=EXIT_ERROR)
        else:
            with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                cmd_fixture(f"--repo={archiver_setup.repository_location}", "rinfo")
            if isinstance(excinfo.value, RemoteRepository.RPCError):
                assert excinfo.value.exception_class == "LockFailed"
        # verify that command works with read-only repo when using --bypass-lock
        cmd_fixture(f"--repo={archiver_setup.repository_location}", "rinfo", "--bypass-lock")


def test_readonly_list(archiver_setup, cmd_fixture, create_src_archive):
    cmd_fixture(f"--repo={archiver_setup.repository_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
    create_src_archive("test")
    with read_only(archiver_setup.repository_path):
        # verify that command normally doesn't work with read-only repo
        if archiver_setup.FORK_DEFAULT:
            cmd_fixture(f"--repo={archiver_setup.repository_location}", "rlist", exit_code=EXIT_ERROR)
        else:
            with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                cmd_fixture(f"--repo={archiver_setup.repository_location}", "rlist")
            if isinstance(excinfo.value, RemoteRepository.RPCError):
                assert excinfo.value.exception_class == "LockFailed"
        # verify that command works with read-only repo when using --bypass-lock
        cmd_fixture(f"--repo={archiver_setup.repository_location}", "rlist", "--bypass-lock")


@unittest.skipUnless(llfuse, "llfuse not installed")
def test_readonly_mount(archiver_setup, cmd_fixture, create_src_archive):
    cmd_fixture(f"--repo={archiver_setup.repository_location}", "rcreate", archiver_setup.RK_ENCRYPTION)
    create_src_archive("test")
    with read_only(archiver_setup.repository_path):
        # verify that command normally doesn't work with read-only repo
        if archiver_setup.FORK_DEFAULT:
            with fuse_mount(archiver_setup.repository_location, exit_code=EXIT_ERROR):
                pass
        else:
            with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                # self.fuse_mount always assumes fork=True, so for this test we have to set fork=False manually
                with fuse_mount(archiver_setup.repository_location, fork=False):
                    pass
            if isinstance(excinfo.value, RemoteRepository.RPCError):
                assert excinfo.value.exception_class == "LockFailed"
        # verify that command works with read-only repo when using --bypass-lock
        with fuse_mount(archiver_setup.repository_location, None, "--bypass-lock"):
            pass


def read_only(path):
    pass


def fuse_mount(path, fork, s="", exit_code=EXIT_ERROR):
    pass

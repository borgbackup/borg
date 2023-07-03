import unittest

import pytest

from ...constants import *  # NOQA
from ...helpers import EXIT_ERROR
from ...locking import LockFailed
from ...remote import RemoteRepository
from .. import llfuse
from . import ArchiverTestCaseBase, RK_ENCRYPTION


class ArchiverTestCase(ArchiverTestCaseBase):
    def test_readonly_check(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_src_archive("test")
        with self.read_only(self.repository_path):
            # verify that command normally doesn't work with read-only repo
            if self.FORK_DEFAULT:
                self.cmd(f"--repo={self.repository_location}", "check", "--verify-data", exit_code=EXIT_ERROR)
            else:
                with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                    self.cmd(f"--repo={self.repository_location}", "check", "--verify-data")
                if isinstance(excinfo.value, RemoteRepository.RPCError):
                    assert excinfo.value.exception_class == "LockFailed"
            # verify that command works with read-only repo when using --bypass-lock
            self.cmd(f"--repo={self.repository_location}", "check", "--verify-data", "--bypass-lock")

    def test_readonly_diff(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_src_archive("a")
        self.create_src_archive("b")
        with self.read_only(self.repository_path):
            # verify that command normally doesn't work with read-only repo
            if self.FORK_DEFAULT:
                self.cmd(f"--repo={self.repository_location}", "diff", "a", "b", exit_code=EXIT_ERROR)
            else:
                with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                    self.cmd(f"--repo={self.repository_location}", "diff", "a", "b")
                if isinstance(excinfo.value, RemoteRepository.RPCError):
                    assert excinfo.value.exception_class == "LockFailed"
            # verify that command works with read-only repo when using --bypass-lock
            self.cmd(f"--repo={self.repository_location}", "diff", "a", "b", "--bypass-lock")

    def test_readonly_export_tar(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_src_archive("test")
        with self.read_only(self.repository_path):
            # verify that command normally doesn't work with read-only repo
            if self.FORK_DEFAULT:
                self.cmd(f"--repo={self.repository_location}", "export-tar", "test", "test.tar", exit_code=EXIT_ERROR)
            else:
                with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                    self.cmd(f"--repo={self.repository_location}", "export-tar", "test", "test.tar")
                if isinstance(excinfo.value, RemoteRepository.RPCError):
                    assert excinfo.value.exception_class == "LockFailed"
            # verify that command works with read-only repo when using --bypass-lock
            self.cmd(f"--repo={self.repository_location}", "export-tar", "test", "test.tar", "--bypass-lock")

    def test_readonly_extract(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_src_archive("test")
        with self.read_only(self.repository_path):
            # verify that command normally doesn't work with read-only repo
            if self.FORK_DEFAULT:
                self.cmd(f"--repo={self.repository_location}", "extract", "test", exit_code=EXIT_ERROR)
            else:
                with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                    self.cmd(f"--repo={self.repository_location}", "extract", "test")
                if isinstance(excinfo.value, RemoteRepository.RPCError):
                    assert excinfo.value.exception_class == "LockFailed"
            # verify that command works with read-only repo when using --bypass-lock
            self.cmd(f"--repo={self.repository_location}", "extract", "test", "--bypass-lock")

    def test_readonly_info(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_src_archive("test")
        with self.read_only(self.repository_path):
            # verify that command normally doesn't work with read-only repo
            if self.FORK_DEFAULT:
                self.cmd(f"--repo={self.repository_location}", "rinfo", exit_code=EXIT_ERROR)
            else:
                with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                    self.cmd(f"--repo={self.repository_location}", "rinfo")
                if isinstance(excinfo.value, RemoteRepository.RPCError):
                    assert excinfo.value.exception_class == "LockFailed"
            # verify that command works with read-only repo when using --bypass-lock
            self.cmd(f"--repo={self.repository_location}", "rinfo", "--bypass-lock")

    def test_readonly_list(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_src_archive("test")
        with self.read_only(self.repository_path):
            # verify that command normally doesn't work with read-only repo
            if self.FORK_DEFAULT:
                self.cmd(f"--repo={self.repository_location}", "rlist", exit_code=EXIT_ERROR)
            else:
                with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                    self.cmd(f"--repo={self.repository_location}", "rlist")
                if isinstance(excinfo.value, RemoteRepository.RPCError):
                    assert excinfo.value.exception_class == "LockFailed"
            # verify that command works with read-only repo when using --bypass-lock
            self.cmd(f"--repo={self.repository_location}", "rlist", "--bypass-lock")

    @unittest.skipUnless(llfuse, "llfuse not installed")
    def test_readonly_mount(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.create_src_archive("test")
        with self.read_only(self.repository_path):
            # verify that command normally doesn't work with read-only repo
            if self.FORK_DEFAULT:
                with self.fuse_mount(self.repository_location, exit_code=EXIT_ERROR):
                    pass
            else:
                with pytest.raises((LockFailed, RemoteRepository.RPCError)) as excinfo:
                    # self.fuse_mount always assumes fork=True, so for this test we have to set fork=False manually
                    with self.fuse_mount(self.repository_location, fork=False):
                        pass
                if isinstance(excinfo.value, RemoteRepository.RPCError):
                    assert excinfo.value.exception_class == "LockFailed"
            # verify that command works with read-only repo when using --bypass-lock
            with self.fuse_mount(self.repository_location, None, "--bypass-lock"):
                pass

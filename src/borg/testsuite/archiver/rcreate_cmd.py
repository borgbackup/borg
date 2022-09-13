import os
import unittest
from unittest.mock import patch

import pytest

from ...helpers.errors import Error
from ...constants import *  # NOQA
from ...crypto.key import FlexiKey
from ...repository import Repository
from .. import environment_variable
from . import ArchiverTestCaseBase, ArchiverTestCaseBinaryBase, RK_ENCRYPTION, KF_ENCRYPTION, BORG_EXES


class ArchiverTestCase(ArchiverTestCaseBase):
    def test_rcreate_parent_dirs(self):
        parent_path = os.path.join(self.tmpdir, "parent1", "parent2")
        repository_path = os.path.join(parent_path, "repository")
        repository_location = self.prefix + repository_path
        with pytest.raises(Repository.ParentPathDoesNotExist):
            # normal borg rcreate does NOT create missing parent dirs
            self.cmd(f"--repo={repository_location}", "rcreate", "--encryption=none")
        # but if told so, it does:
        self.cmd(f"--repo={repository_location}", "rcreate", "--encryption=none", "--make-parent-dirs")
        assert os.path.exists(parent_path)

    def test_rcreate_interrupt(self):
        def raise_eof(*args, **kwargs):
            raise EOFError

        with patch.object(FlexiKey, "create", raise_eof):
            self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION, exit_code=1)
        assert not os.path.exists(self.repository_location)

    def test_rcreate_requires_encryption_option(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", exit_code=2)

    def test_rcreate_nested_repositories(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        if self.FORK_DEFAULT:
            self.cmd(f"--repo={self.repository_location}/nested", "rcreate", RK_ENCRYPTION, exit_code=2)
        else:
            with pytest.raises(Repository.AlreadyExists):
                self.cmd(f"--repo={self.repository_location}/nested", "rcreate", RK_ENCRYPTION)

    def test_rcreate_refuse_to_overwrite_keyfile(self):
        """BORG_KEY_FILE=something borg rcreate should quit if "something" already exists.

        See https://github.com/borgbackup/borg/pull/6046"""
        keyfile = os.path.join(self.tmpdir, "keyfile")
        with environment_variable(BORG_KEY_FILE=keyfile):
            self.cmd(f"--repo={self.repository_location}0", "rcreate", KF_ENCRYPTION)
            with open(keyfile) as file:
                before = file.read()
            arg = (f"--repo={self.repository_location}1", "rcreate", KF_ENCRYPTION)
            if self.FORK_DEFAULT:
                self.cmd(*arg, exit_code=2)
            else:
                with pytest.raises(Error):
                    self.cmd(*arg)
            with open(keyfile) as file:
                after = file.read()
            assert before == after


@unittest.skipUnless("binary" in BORG_EXES, "no borg.exe available")
class ArchiverTestCaseBinary(ArchiverTestCaseBinaryBase, ArchiverTestCase):
    @unittest.skip("does not raise Exception, but sets rc==2")
    def test_rcreate_parent_dirs(self):
        pass

    @unittest.skip("patches objects")
    def test_rcreate_interrupt(self):
        pass

from ...constants import *  # NOQA
from . import ArchiverTestCaseBase


class ArchiverTestCase(ArchiverTestCaseBase):
    def test_usage(self):
        self.cmd()
        self.cmd("-h")

    def test_help(self):
        assert "Borg" in self.cmd("help")
        assert "patterns" in self.cmd("help", "patterns")
        assert "creates a new, empty repository" in self.cmd("help", "rcreate")
        assert "positional arguments" not in self.cmd("help", "rcreate", "--epilog-only")
        assert "creates a new, empty repository" not in self.cmd("help", "rcreate", "--usage-only")

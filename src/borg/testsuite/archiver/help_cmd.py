import pytest

from ...constants import *  # NOQA
from ...helpers.nanorst import RstToTextLazy, rst_to_terminal
from . import ArchiverTestCaseBase, Archiver


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


def get_all_parsers():
    """
    Return dict mapping command to parser.
    """
    parser = Archiver(prog="borg").build_parser()
    borgfs_parser = Archiver(prog="borgfs").build_parser()
    parsers = {}

    def discover_level(prefix, parser, Archiver, extra_choices=None):
        choices = {}
        for action in parser._actions:
            if action.choices is not None and "SubParsersAction" in str(action.__class__):
                for cmd, parser in action.choices.items():
                    choices[prefix + cmd] = parser
        if extra_choices is not None:
            choices.update(extra_choices)
        if prefix and not choices:
            return

        for command, parser in sorted(choices.items()):
            discover_level(command + " ", parser, Archiver)
            parsers[command] = parser

    discover_level("", parser, Archiver, {"borgfs": borgfs_parser})
    return parsers


@pytest.mark.parametrize("command, parser", list(get_all_parsers().items()))
def test_help_formatting(command, parser):
    if isinstance(parser.epilog, RstToTextLazy):
        assert parser.epilog.rst


@pytest.mark.parametrize("topic, helptext", list(Archiver.helptext.items()))
def test_help_formatting_helptexts(topic, helptext):
    assert str(rst_to_terminal(helptext))

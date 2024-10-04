import pytest

from ...constants import *  # NOQA
from ...helpers.nanorst import RstToTextLazy, rst_to_terminal
from . import Archiver, cmd


def get_all_parsers():
    # Return dict mapping command to parser.
    parser = Archiver(prog="borg").build_parser()
    borgfs_parser = Archiver(prog="borgfs").build_parser()
    parsers = {}

    def discover_level(prefix, parser, Archiver, extra_choices=None):
        choices = {}
        for action in parser._actions:
            if action.choices is not None and "SubParsersAction" in str(action.__class__):
                for command, parser in action.choices.items():
                    choices[prefix + command] = parser
        if extra_choices is not None:
            choices.update(extra_choices)
        if prefix and not choices:
            return

        for command, parser in sorted(choices.items()):
            discover_level(command + " ", parser, Archiver)
            parsers[command] = parser

    discover_level("", parser, Archiver, {"borgfs": borgfs_parser})
    return parsers


def test_usage(archiver):
    cmd(archiver)
    cmd(archiver, "-h")


def test_help(archiver):
    assert "Borg" in cmd(archiver, "help")
    assert "patterns" in cmd(archiver, "help", "patterns")
    assert "creates a new, empty repository" in cmd(archiver, "help", "repo-create")
    assert "positional arguments" not in cmd(archiver, "help", "repo-create", "--epilog-only")
    assert "creates a new, empty repository" not in cmd(archiver, "help", "repo-create", "--usage-only")


@pytest.mark.parametrize("command, parser", list(get_all_parsers().items()))
def test_help_formatting(command, parser):
    if isinstance(parser.epilog, RstToTextLazy):
        assert parser.epilog.rst


@pytest.mark.parametrize("topic", list(Archiver.helptext.keys()))
def test_help_formatting_helptexts(topic):
    helptext = Archiver.helptext[topic]
    assert str(rst_to_terminal(helptext))

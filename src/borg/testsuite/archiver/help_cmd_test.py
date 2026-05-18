import pytest

from ...constants import *  # NOQA
from ...helpers.nanorst import RstToTextLazy, rst_to_terminal
from . import Archiver, cmd, exec_cmd


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


def test_borg1_init_shows_repo_create_hint(archiver):
    ret, output = exec_cmd(
        "--repo",
        archiver.repository_location,
        "init",
        "-e",
        "repokey-aes-ocb",
        archiver=archiver.archiver,
        fork=archiver.FORK_DEFAULT,
        exe=archiver.EXE,
    )

    assert ret == 2
    assert "init is not a borg2 command; use repo-create." in output
    assert "Corrected command:" in output
    assert f"borg --repo {archiver.repository_location} repo-create -e repokey-aes-ocb" in output
    assert "Use `borg help` to see the list of valid commands." in output


def test_borg1_glob_archives_shows_match_archives_hint(archiver):
    ret, output = exec_cmd(
        "--repo",
        archiver.repository_location,
        "list",
        "--glob-archives",
        "my*",
        archiver=archiver.archiver,
        fork=archiver.FORK_DEFAULT,
        exe=archiver.EXE,
    )

    assert ret == 2
    assert "--glob-archives is a borg1 option and is not used in borg2." in output
    assert (
        "Use --match-archives in borg2. It defaults to exact `id:` matching, "
        "so use `sh:` for borg1-style globbing." in output
    )
    assert "Example:" in output
    assert "borg list ARCHIVE --match-archives 'sh:my*'" in output
    assert "tip: For details of accepted options run: borg list --help" in output


def test_borg1_repo_archive_in_repo_shows_borg2_forms(archiver):
    ret, output = exec_cmd(
        "--repo",
        f"{archiver.repository_location}::test1",
        "list",
        archiver=archiver.archiver,
        fork=archiver.FORK_DEFAULT,
        exe=archiver.EXE,
    )

    assert ret == 2
    assert "Borg2 does not accept repo::archive in --repo." in output
    assert "Use one of these borg2 forms instead:" in output
    assert f"borg --repo {archiver.repository_location} list ::test1" in output
    assert f"export BORG_REPO={archiver.repository_location}" in output
    assert "borg list ::test1" in output
    assert "tip: For details of accepted options run: borg list --help" in output


def test_borg1_repo_archive_in_repo_shows_borg2_forms_when_repo_is_after_command(archiver):
    ret, output = exec_cmd(
        "list",
        "--repo",
        f"{archiver.repository_location}::test1",
        archiver=archiver.archiver,
        fork=archiver.FORK_DEFAULT,
        exe=archiver.EXE,
    )

    assert ret == 2
    assert "Borg2 does not accept repo::archive in --repo." in output
    assert f"borg --repo {archiver.repository_location} list ::test1" in output
    assert f"export BORG_REPO={archiver.repository_location}" in output
    assert "borg list ::test1" in output


def test_list_without_name_suggests_repo_list(archiver):
    ret, output = exec_cmd("list", archiver=archiver.archiver, fork=archiver.FORK_DEFAULT, exe=archiver.EXE)

    assert ret == 2
    assert "borg list NAME lists contents of an archive and needs an archive NAME." in output
    assert "If you meant to list archives in a repository, use repo-list:" in output
    assert "borg -r REPO repo-list" in output
    assert "tip: For details of accepted options run: borg list --help" in output


def test_list_without_name_with_repo_suggests_repo_list(archiver):
    ret, output = exec_cmd(
        "--repo",
        archiver.repository_location,
        "list",
        archiver=archiver.archiver,
        fork=archiver.FORK_DEFAULT,
        exe=archiver.EXE,
    )

    assert ret == 2
    assert "borg list NAME lists contents of an archive and needs an archive NAME." in output
    assert "If you meant to list archives in a repository, use repo-list:" in output
    assert f"borg -r {archiver.repository_location} repo-list" in output
    assert "tip: For details of accepted options run: borg list --help" in output


@pytest.mark.parametrize("command, parser", list(get_all_parsers().items()))
def test_help_formatting(command, parser):
    if isinstance(parser.epilog, RstToTextLazy):
        assert parser.epilog.rst


@pytest.mark.parametrize("topic", list(Archiver.helptext.keys()))
def test_help_formatting_helptexts(topic):
    helptext = Archiver.helptext[topic]
    assert str(rst_to_terminal(helptext))

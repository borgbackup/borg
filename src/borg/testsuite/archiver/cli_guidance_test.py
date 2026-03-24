import os
import sys

import pytest

from ...helpers.argparsing import ArgumentParser
from ...repository import Repository
from . import exec_cmd


def test_unknown_command_typo_suggests_fuzzy_match(cmd_fixture):
    exit_code, output = cmd_fixture("repo-creat")
    assert exit_code == 2
    assert "Maybe you meant `repo-create` not `repo-creat`:" in output
    assert "\tborg repo-create" in output


def test_unknown_command_typo_list(cmd_fixture):
    exit_code, output = cmd_fixture("lst")
    assert exit_code == 2
    assert "Maybe you meant `list` not `lst`:" in output
    assert "\tborg list" in output


def test_fuzzy_typo_preserves_following_args(cmd_fixture):
    exit_code, output = cmd_fixture("creat", "foo", "--stats")
    assert exit_code == 2
    assert "Maybe you meant `create` not `creat`:" in output
    assert "\tborg create foo --stats" in output


def test_legacy_rm_synonym(cmd_fixture):
    exit_code, output = cmd_fixture("rm")
    assert exit_code == 2
    assert "Maybe you meant `delete` not `rm`:" in output
    assert "\tborg delete" in output


def test_legacy_rm_synonym_preserves_trailing_tokens_in_delete_example(cmd_fixture, tmp_path):
    """Tokens after 'rm' must appear in the suggested delete line (not a generic placeholder)."""
    repo = os.fspath(tmp_path / "repo")
    exit_code, output = cmd_fixture("-r", repo, "rm", "dsfasdfsdfsdf")
    assert exit_code == 2
    assert "Maybe you meant `delete` not `rm`:" in output
    assert "ARCHIVE_OR_AID" not in output
    assert f"\tborg -r {repo} delete dsfasdfsdfsdf" in output


def test_rm_synonym_example_includes_argv_tail(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["python", "-m", "borg", "-r", "/tmp/borg/outC", "rm", "dsfasdfsdfsdf"])
    parser = ArgumentParser(prog="borg")
    message = "error: argument <command>: invalid choice: 'rm' (choose from 'delete', 'list')"
    hint = parser._top_command_choice_hint(message)
    assert hint is not None
    assert "Maybe you meant `delete` not `rm`:" in hint
    assert "ARCHIVE_OR_AID" not in hint
    assert "\tborg -r /tmp/borg/outC delete dsfasdfsdfsdf" in hint


def test_lst_typo_example_includes_argv_tail(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["python", "-m", "borg", "-r", "/r", "lst", "my-archive"])
    parser = ArgumentParser(prog="borg")
    message = "error: argument <command>: invalid choice: 'lst' (choose from 'list', 'delete')"
    hint = parser._top_command_choice_hint(message)
    assert hint is not None
    assert "Maybe you meant `list` not `lst`:" in hint
    assert "ARCHIVE" not in hint
    assert "\tborg -r /r list my-archive" in hint


def test_restore_synonym_example_includes_argv_tail(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["python", "-m", "borg", "-r", "/r", "restore", "arch1"])
    parser = ArgumentParser(prog="borg")
    message = "error: argument <command>: invalid choice: 'restore' (choose from 'undelete', 'list')"
    hint = parser._top_command_choice_hint(message)
    assert hint is not None
    assert "Maybe you meant `undelete` not `restore`:" in hint
    assert "…" not in hint
    assert "\tborg -r REPO undelete arch1" in hint


def test_maybe_you_meant_rm_is_common_fix_bullet(cmd_fixture):
    """Invalid-command hint must appear under Common fixes with a '- ' bullet."""
    exit_code, output = cmd_fixture("rm")
    assert exit_code == 2
    assert "Common fixes:" in output
    assert "- Maybe you meant `delete` not `rm`:" in output


def test_maybe_you_meant_line_has_dash_prefix_before_maybe(cmd_fixture):
    """Regression: '- ' must prefix the Maybe-you-meant line (not a bare paragraph before Common fixes)."""
    exit_code, output = cmd_fixture("rm")
    assert exit_code == 2
    assert "Common fixes:\n- Maybe you meant `delete` not `rm`:" in output


def test_legacy_clean_synonym(cmd_fixture):
    exit_code, output = cmd_fixture("clean")
    assert exit_code == 2
    assert "Maybe you meant `compact` not `clean`:" in output
    assert "\tborg compact" in output


def test_legacy_restore_synonym(cmd_fixture):
    exit_code, output = cmd_fixture("restore")
    assert exit_code == 2
    assert "Maybe you meant `undelete` not `restore`:" in output
    assert "\tborg undelete" in output


def test_legacy_init_synonym(cmd_fixture, tmp_path):
    repo = os.fspath(tmp_path / "repo")
    exit_code, output = cmd_fixture("--repo", repo, "init", "-e", "none")
    assert exit_code == 2
    assert "Maybe you meant `repo-create` not `init`:" in output
    assert f"\tborg --repo {repo} repo-create -e none" in output


def test_legacy_rcreate_synonym(cmd_fixture, tmp_path):
    repo = os.fspath(tmp_path / "repo")
    exit_code, output = cmd_fixture("--repo", repo, "rcreate", "-e", "none")
    assert exit_code == 2
    assert "Maybe you meant `repo-create` not `rcreate`:" in output
    assert f"\tborg --repo {repo} repo-create -e none" in output


def test_legacy_repocreate_synonym(cmd_fixture, tmp_path):
    repo = os.fspath(tmp_path / "repo")
    exit_code, output = cmd_fixture("--repo", repo, "repocreate", "-e", "none")
    assert exit_code == 2
    assert "Maybe you meant `repo-create` not `repocreate`:" in output
    assert f"\tborg --repo {repo} repo-create -e none" in output


def test_repo_create_missing_encryption_shows_available_modes(cmd_fixture, tmp_path):
    repo = os.fspath(tmp_path / "repo")
    exit_code, output = cmd_fixture("--repo", repo, "repo-create")
    assert exit_code == 2
    assert "Use -e/--encryption to choose a mode" in output
    assert "Available encryption modes:" in output


def test_repo_double_colon_syntax_shows_migration_hint(cmd_fixture, tmp_path):
    repo = os.fspath(tmp_path / "repo::archive")
    exit_code, output = cmd_fixture("--repo", repo, "repo-info")
    assert exit_code == 2
    assert "does not accept repo::archive syntax" in output
    assert "borg -r" in output
    assert "borg list archive" in output
    assert "borg repo-info" in output
    assert "export BORG_REPO=" in output


def test_missing_repository_error_shows_create_example(cmd_fixture, tmp_path):
    repo = os.fspath(tmp_path / "missing-repo")
    exit_code, output = cmd_fixture("--repo", repo, "repo-info")
    assert exit_code == 2
    assert "does not exist." in output
    assert "Common fixes:" in output
    assert f'Specify Correct Path ("{repo}" does not exist).' in output
    assert "borg repo-info -r" not in output
    assert "Create repository (-r): borg repo-create" in output
    assert "Create repository (BORG_REPO):" in output
    assert "Available -e modes:" in output


def test_repository_does_not_exist_common_fix_explains_missing_path():
    msg = Repository.DoesNotExist("/tmp/foo").get_message()
    assert 'Specify Correct Path ("/tmp/foo" does not exist).' in msg
    assert "borg repo-info -r" not in msg


def test_repository_invalid_common_fix_explains_not_a_borg_repo():
    msg = Repository.InvalidRepository("/tmp/foo").get_message()
    assert 'Specify Correct Path ("/tmp/foo" is not a Borg repository).' in msg
    assert "borg repo-info -r" not in msg


def test_list_name_none_common_fix_hint():
    parser = ArgumentParser(prog="borg")
    hints = parser._common_fix_hints("Validation failed: list.name is None")
    assert "For 'borg list', set repository via -r/--repo or BORG_REPO and pass an archive name." in hints


def test_list_paths_required_shows_path_and_repo_creation_hints(cmd_fixture, tmp_path):
    repo = os.fspath(tmp_path / "does-not-exist")
    exit_code, output = cmd_fixture("--repo", repo, "list")
    assert exit_code == 2
    assert "Option 'list.paths' is required but not provided" in output
    assert "borg list requires an archive NAME to list contents." in output
    assert "- Provide archive name: borg list NAME" in output
    assert "- To list archives in a repository, use: borg -r REPO repo-list" in output


def test_argument_parser_error_accepts_jsonargparse_extra_arg():
    parser = ArgumentParser(prog="borg")
    with pytest.raises(SystemExit):
        parser.error("bad message", ValueError("wrapped"))


def test_unrecognized_args_before_subcommand_shows_reordered_example(cmd_fixture):
    exit_code, output = cmd_fixture("--stats", "create", "foo")
    assert exit_code == 2
    assert "Unrecognized arguments" in output
    assert "Common fixes:" in output
    assert "Put subcommand-specific options after `<command>`:" in output
    assert "create" in output and "--stats" in output


def test_preprocess_prints_glob_archives_migration_hint(tmp_path):
    repo = os.fspath(tmp_path / "repo")
    exit_code, output = exec_cmd("--repo", repo, "list", "dummy-archive", "--glob-archives", "sh:old", fork=False)
    assert exit_code == 2
    assert "Common fixes:" in output
    assert '- borg1 option "--glob-archives" is not used in borg2.' in output
    assert "--match-archives 'sh:PATTERN'" in output
    assert "- Example: borg list ARCHIVE --match-archives 'sh:old-*'" in output

import pytest

from . import Archiver
from ...helpers.argparsing import ArgumentParser


def test_first_positional_index_double_dash_cases():
    arch = Archiver()
    parser = arch.build_parser()

    # '--' followed by another token -> should point to that next token
    assert Archiver._first_positional_index(["--", "positional"], parser) == 1

    # '--' as the last token -> should return len(args)
    assert Archiver._first_positional_index(["--"], parser) == 1


def test_first_positional_index_unknown_option_returns_none():
    arch = Archiver()
    parser = arch.build_parser()

    # an unrecognized option should make the scanner give up (None)
    assert Archiver._first_positional_index(["--this-option-does-not-exist"], parser) is None


def test_first_positional_index_nargs_question_mark_consumption():
    parser = ArgumentParser(prog="test")
    parser.add_argument("--opt-ques", dest="opt_ques", nargs="?")
    parser.add_argument("--another", dest="another", action="store_true")

    # next token is a value -> the option consumes it (i += 2)
    assert Archiver._first_positional_index(["--opt-ques", "value", "pos"], parser) == 2

    # next token starts with '-' -> option does not consume a value (i += 1)
    assert Archiver._first_positional_index(["--opt-ques", "--another", "pos"], parser) == 2


def test_first_positional_index_nargs_integer_and_star():
    parser = ArgumentParser(prog="test")
    parser.add_argument("--opt-int", dest="opt_int", nargs=2)
    parser.add_argument("--opt-star", dest="opt_star", nargs="*")

    # integer nargs should skip the right number of following args
    assert Archiver._first_positional_index(["--opt-int", "a", "b", "pos"], parser) == 3

    # fallback branch for non-int/non-'?' nargs (like '*') should increment by 2
    assert Archiver._first_positional_index(["--opt-star", "val", "pos"], parser) == 2


def test_first_toplevel_command_index_none_cases():
    arch = Archiver()
    parser = arch.build_parser()

    # unknown option -> _first_positional_index returns None -> top-level returns None
    assert arch._first_toplevel_command_index(["--nope"], parser) is None

    # argument-list that results in index == len(args) should return None
    # '--socket' is a known option with nargs='?' in common options
    assert arch._first_toplevel_command_index(["--socket"], parser) is None


def test_legacy_repo_archive_hint_repo_or_archive_empty_returns_none():
    arch = Archiver()
    parser = arch.build_parser()

    # repo value contains '::' but repo part is empty -> should return None
    assert arch._legacy_repo_archive_hint(["list", "--repo=::archive"], parser) is None

    # repo value contains '::' but archive part is empty -> should return None
    assert arch._legacy_repo_archive_hint(["list", "--repo=repo::"], parser) is None


def test_missing_list_name_hint_list_parser_none_returns_none():
    arch = Archiver()
    # create a parser without subcommands so there is no 'list' subparser
    parser = ArgumentParser(prog="test")

    # command 'list' present in args, but parser has no subcommands -> list_parser is None
    assert arch._missing_list_name_hint(["list"], parser) is None

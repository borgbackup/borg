import sys

import pytest

from ...helpers.argparsing import _suggest_move_options_after_subcommand


def test_suggest_reorder_unrecognized_args_before_subcommand(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["borg", "--stats", "create", "foo"])
    s = _suggest_move_options_after_subcommand("error: Unrecognized arguments: --stats")
    assert s is not None
    assert "create" in s and "--stats" in s
    assert s.index("create") < s.index("--stats")

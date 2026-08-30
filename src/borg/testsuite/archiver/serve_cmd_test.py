"""Tests for "borg serve" error reporting.

"borg serve" startup errors must be printed to stderr: the client only ever sees the server's
stderr (SSH forwards it; the borgstore rest backend surfaces its tail as BackendError detail),
so a silently exiting server makes e.g. misconfigured sshd forced commands very hard to diagnose.
These tests run a real borg process (fork=True), so that main()'s error reporting is exercised.
"""

from ...helpers.errors import Error, PathNotAllowed
from . import exec_cmd


def test_serve_rest_missing_backend_prints_error():
    ret, output = exec_cmd("serve", "--rest", fork=True)
    assert ret == Error.exit_mcode
    assert "borg serve --rest requires --backend FILE:<path>." in output


def test_serve_rest_restriction_violation_prints_error(tmp_path, monkeypatch):
    # like an sshd forced command scenario: the client asks for a repository path
    # that the forced command's --restrict-to-repository does not allow.
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", f"borg serve --rest --backend FILE:{tmp_path / 'forbidden'}")
    ret, output = exec_cmd("serve", "--rest", f"--restrict-to-repository={tmp_path / 'allowed'}", fork=True)
    assert ret == PathNotAllowed.exit_mcode
    assert "Repository path not allowed" in output
    assert "forbidden" in output

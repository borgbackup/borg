import json
import os
import subprocess
import sys

import pytest

from borg import __version__
from borg.helpers import EXIT_ERROR
from borg.version import format_version, parse_version
from borg.testsuite.archiver import Archiver, cmd

EXPECTED_VERSION = format_version(parse_version(__version__))


def test_default_version(archiver):
    result = cmd(archiver, "version")
    assert result.splitlines() == [f"{EXPECTED_VERSION} / {EXPECTED_VERSION}"]


def test_json_version(archiver):
    result = cmd(archiver, "version", "--json")
    version_info = json.loads(result)
    assert version_info == {"client": EXPECTED_VERSION, "server": EXPECTED_VERSION}


def test_from_borg1_option():
    """--from-borg1 is accepted and enables the legacy (borg 1.x) remote code path."""
    archiver = Archiver()
    args = archiver.parse_args(["-r", "ssh://borg@borgbackup/repo", "version", "--from-borg1"])
    assert args.func == archiver.do_version
    assert args.location.proto == "ssh"
    assert args.v1_legacy is True


def test_from_borg1_default_off():
    archiver = Archiver()
    args = archiver.parse_args(["-r", "/mnt/backup", "version"])
    assert args.func == archiver.do_version
    assert args.v1_legacy is False


@pytest.mark.parametrize(
    "python_opts, pythonoptimize", [(["-O"], None), ([], "1")], ids=["option-O", "env-PYTHONOPTIMIZE"]
)
def test_refuses_to_run_without_assertions(python_opts, pythonoptimize):
    """borg must not run with assertions disabled (see the guard at the top of borg.archiver)."""
    env = os.environ.copy()
    env.pop("PYTHONOPTIMIZE", None)
    if pythonoptimize is not None:
        env["PYTHONOPTIMIZE"] = pythonoptimize
    python = sys.executable or "python3"
    result = subprocess.run(
        [python, *python_opts, "-m", "borg", "--version"], env=env, capture_output=True, text=True, timeout=60
    )
    assert result.returncode == EXIT_ERROR
    assert "Borg requires working assertions" in result.stderr
    assert result.stdout == ""

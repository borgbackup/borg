import json
from borg import __version__
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

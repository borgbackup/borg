import json
from borg import __version__
from borg.version import format_version, parse_version
from borg.testsuite.archiver import cmd

EXPECTED_VERSION = format_version(parse_version(__version__))


def test_default_version(archiver):
    result = cmd(archiver, "version")
    assert result.splitlines() == [f"{EXPECTED_VERSION} / {EXPECTED_VERSION}"]


def test_json_version(archiver):
    result = cmd(archiver, "version", "--json")
    version_info = json.loads(result)
    assert version_info == {"client": EXPECTED_VERSION, "server": EXPECTED_VERSION}

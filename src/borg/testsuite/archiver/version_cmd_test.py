import json

from ... import __version__
from ...version import format_version, parse_version
from . import cmd


EXPECTED_VERSION = format_version(parse_version(__version__))


def test_version(archiver):
    output = cmd(archiver, "version")

    assert output == f"{EXPECTED_VERSION} / {EXPECTED_VERSION}\n"


def test_version_json(archiver):
    output = cmd(archiver, "version", "--json")
    version_info = json.loads(output)

    assert version_info == {"client": EXPECTED_VERSION, "server": EXPECTED_VERSION}

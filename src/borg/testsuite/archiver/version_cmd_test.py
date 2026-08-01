import json
from types import SimpleNamespace

from ...archiver.version_cmd import VersionMixIn
from ... import __version__
from ...version import format_version, parse_version


def test_version_json(capsys):
    args = SimpleNamespace(location=SimpleNamespace(proto="file"), json=True)

    VersionMixIn().do_version(args)

    assert json.loads(capsys.readouterr().out) == {
        "client": format_version(parse_version(__version__)),
        "server": format_version(parse_version(__version__)),
    }


def test_version_text_is_unchanged(capsys):
    args = SimpleNamespace(location=SimpleNamespace(proto="file"), json=False)

    VersionMixIn().do_version(args)

    version = format_version(parse_version(__version__))
    assert capsys.readouterr().out == f"{version} / {version}\n"

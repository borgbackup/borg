import pytest

from ..version import parse_version, format_version


@pytest.mark.parametrize("version_str, version_tuple", [
    # setuptools < 8.0 uses "-"
    ('1.0.0a1.dev204-g8866961.d20170606', (1, 0, 0, -4, 1)),
    ('1.0.0a1.dev204-g8866961', (1, 0, 0, -4, 1)),
    ('1.0.0-d20170606', (1, 0, 0, -1)),
    # setuptools >= 8.0 uses "+"
    ('1.0.0a1.dev204+g8866961.d20170606', (1, 0, 0, -4, 1)),
    ('1.0.0a1.dev204+g8866961', (1, 0, 0, -4, 1)),
    ('1.0.0+d20170606', (1, 0, 0, -1)),
    # pre-release versions:
    ('1.0.0a1', (1, 0, 0, -4, 1)),
    ('1.0.0a2', (1, 0, 0, -4, 2)),
    ('1.0.0b3', (1, 0, 0, -3, 3)),
    ('1.0.0rc4', (1, 0, 0, -2, 4)),
    # release versions:
    ('0.0.0', (0, 0, 0, -1)),
    ('0.0.11', (0, 0, 11, -1)),
    ('0.11.0', (0, 11, 0, -1)),
    ('11.0.0', (11, 0, 0, -1)),
])
def test_parse_version(version_str, version_tuple):
    assert parse_version(version_str) == version_tuple


def test_parse_version_invalid():
    with pytest.raises(ValueError):
        assert parse_version('')  # we require x.y.z versions
    with pytest.raises(ValueError):
        assert parse_version('1')  # we require x.y.z versions
    with pytest.raises(ValueError):
        assert parse_version('1.2')  # we require x.y.z versions
    with pytest.raises(ValueError):
        assert parse_version('crap')


@pytest.mark.parametrize("version_str, version_tuple", [
    ('1.0.0a1', (1, 0, 0, -4, 1)),
    ('1.0.0', (1, 0, 0, -1)),
    ('1.0.0a2', (1, 0, 0, -4, 2)),
    ('1.0.0b3', (1, 0, 0, -3, 3)),
    ('1.0.0rc4', (1, 0, 0, -2, 4)),
    ('0.0.0', (0, 0, 0, -1)),
    ('0.0.11', (0, 0, 11, -1)),
    ('0.11.0', (0, 11, 0, -1)),
    ('11.0.0', (11, 0, 0, -1)),
])
def test_format_version(version_str, version_tuple):
    assert format_version(version_tuple) == version_str

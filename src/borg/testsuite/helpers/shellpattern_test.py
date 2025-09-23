import re

import pytest

from ...helpers import shellpattern


def check(path, pattern):
    compiled = re.compile(shellpattern.translate(pattern))

    return bool(compiled.match(path))


@pytest.mark.parametrize(
    "path, patterns",
    [
        # Literal string
        ("foo/bar", ["foo/bar"]),
        ("foo\\bar", ["foo\\bar"]),
        # Non-ASCII
        ("foo/c/\u0152/e/bar", ["foo/*/\u0152/*/bar", "*/*/\u0152/*/*", "**/\u0152/*/*"]),
        ("\u00e4\u00f6\u00dc", ["???", "*", "\u00e4\u00f6\u00dc", "[\u00e4][\u00f6][\u00dc]"]),
        # Question mark
        ("foo", ["fo?"]),
        ("foo", ["f?o"]),
        ("foo", ["f??"]),
        ("foo", ["?oo"]),
        ("foo", ["?o?"]),
        ("foo", ["??o"]),
        ("foo", ["???"]),
        # Single asterisk
        ("", ["*"]),
        ("foo", ["*", "**", "***"]),
        ("foo", ["foo*"]),
        ("foobar", ["foo*"]),
        ("foobar", ["foo*bar"]),
        ("foobarbaz", ["foo*baz"]),
        ("bar", ["*bar"]),
        ("foobar", ["*bar"]),
        ("foo/bar", ["foo/*bar"]),
        ("foo/bar", ["foo/*ar"]),
        ("foo/bar", ["foo/*r"]),
        ("foo/bar", ["foo/*"]),
        ("foo/bar", ["foo*/bar"]),
        ("foo/bar", ["fo*/bar"]),
        ("foo/bar", ["f*/bar"]),
        ("foo/bar", ["*/bar"]),
        # Double asterisk (matches 0 to n directory layers)
        ("foo/bar", ["foo/**/bar"]),
        ("foo/1/bar", ["foo/**/bar"]),
        ("foo/1/22/333/bar", ["foo/**/bar"]),
        ("foo/", ["foo/**/"]),
        ("foo/1/", ["foo/**/"]),
        ("foo/1/22/333/", ["foo/**/"]),
        ("bar", ["**/bar"]),
        ("1/bar", ["**/bar"]),
        ("1/22/333/bar", ["**/bar"]),
        ("foo/bar/baz", ["foo/**/*"]),
        # Set
        ("foo1", ["foo[12]"]),
        ("foo2", ["foo[12]"]),
        ("foo2/bar", ["foo[12]/*"]),
        ("f??f", ["f??f", "f[?][?]f"]),
        ("foo]", ["foo[]]"]),
        # Inverted set
        ("foo3", ["foo[!12]"]),
        ("foo^", ["foo[^!]"]),
        ("foo!", ["foo[^!]"]),
        # Group
        ("foo1", ["{foo1,foo2}"]),
        ("foo2", ["foo{1,2}"]),
        ("foo", ["foo{,1,2}"]),
        ("foo1", ["{foo{1,2},bar}"]),
        ("bar", ["{foo{1,2},bar}"]),
        ("{foo", ["{foo{,bar}"]),
        ("{foobar", ["{foo{,bar}"]),
        ("{foo},bar}", ["{foo},bar}"]),
        ("bar/foobar", ["**/foo{ba[!z]*,[0-9]}"]),
    ],
)
def test_match(path, patterns):
    for p in patterns:
        assert check(path, p)


@pytest.mark.parametrize(
    "path, patterns",
    [
        ("", ["?", "[]"]),
        ("foo", ["foo?"]),
        ("foo", ["?foo"]),
        ("foo", ["f?oo"]),
        # Do not match the path separator.
        ("foo/ar", ["foo?ar"]),
        # Do not match or cross the path separator (os.path.sep).
        ("foo/bar", ["*"]),
        ("foo/bar", ["foo*bar"]),
        ("foo/bar", ["foo*ar"]),
        ("foo/bar", ["fo*bar"]),
        ("foo/bar", ["fo*ar"]),
        # Double asterisk
        ("foobar", ["foo/**/bar"]),
        # Two asterisks without a slash do not match the directory separator.
        ("foo/bar", ["**"]),
        # Double asterisk does not match a filename.
        ("foo/bar", ["**/"]),
        # Set
        ("foo3", ["foo[12]"]),
        # Inverted set
        ("foo1", ["foo[!12]"]),
        ("foo2", ["foo[!12]"]),
        # Group
        ("foo", ["{foo1,foo2}"]),
        ("foo", ["foo{1,2}"]),
        ("foo{1,2}", ["foo{1,2}"]),
        ("bar/foobaz", ["**/foo{ba[!z]*,[0-9]}"]),
    ],
)
def test_mismatch(path, patterns):
    for p in patterns:
        assert not check(path, p)


def test_match_end():
    regex = shellpattern.translate("*-home")  # The default is match_end == end of string.
    assert re.match(regex, "2017-07-03-home")
    assert not re.match(regex, "2017-07-03-home.xxx")

    match_end = r"(\.xxx)?\Z"  # With or without a .xxx suffix.
    regex = shellpattern.translate("*-home", match_end=match_end)
    assert re.match(regex, "2017-07-03-home")
    assert re.match(regex, "2017-07-03-home.xxx")

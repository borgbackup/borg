import argparse
import io
import os.path
import sys

import pytest

from ..patterns import PathFullPattern, PathPrefixPattern, FnmatchPattern, ShellPattern, RegexPattern
from ..patterns import load_exclude_file, load_pattern_file
from ..patterns import parse_pattern, PatternMatcher


def check_patterns(files, pattern, expected):
    """Utility for testing patterns.
    """
    assert all([f == os.path.normpath(f) for f in files]), "Pattern matchers expect normalized input paths"

    matched = [f for f in files if pattern.match(f)]

    assert matched == (files if expected is None else expected)


@pytest.mark.parametrize("pattern, expected", [
    # "None" means all files, i.e. all match the given pattern
    ("/", []),
    ("/home", ["/home"]),
    ("/home///", ["/home"]),
    ("/./home", ["/home"]),
    ("/home/user", ["/home/user"]),
    ("/home/user2", ["/home/user2"]),
    ("/home/user/.bashrc", ["/home/user/.bashrc"]),
    ])
def test_patterns_full(pattern, expected):
    files = ["/home", "/home/user", "/home/user2", "/home/user/.bashrc", ]

    check_patterns(files, PathFullPattern(pattern), expected)


@pytest.mark.parametrize("pattern, expected", [
    # "None" means all files, i.e. all match the given pattern
    ("", []),
    ("relative", []),
    ("relative/path/", ["relative/path"]),
    ("relative/path", ["relative/path"]),
    ])
def test_patterns_full_relative(pattern, expected):
    files = ["relative/path", "relative/path2", ]

    check_patterns(files, PathFullPattern(pattern), expected)


@pytest.mark.parametrize("pattern, expected", [
    # "None" means all files, i.e. all match the given pattern
    ("/", None),
    ("/./", None),
    ("", []),
    ("/home/u", []),
    ("/home/user", ["/home/user/.profile", "/home/user/.bashrc"]),
    ("/etc", ["/etc/server/config", "/etc/server/hosts"]),
    ("///etc//////", ["/etc/server/config", "/etc/server/hosts"]),
    ("/./home//..//home/user2", ["/home/user2/.profile", "/home/user2/public_html/index.html"]),
    ("/srv", ["/srv/messages", "/srv/dmesg"]),
    ])
def test_patterns_prefix(pattern, expected):
    files = [
        "/etc/server/config", "/etc/server/hosts", "/home", "/home/user/.profile", "/home/user/.bashrc",
        "/home/user2/.profile", "/home/user2/public_html/index.html", "/srv/messages", "/srv/dmesg",
    ]

    check_patterns(files, PathPrefixPattern(pattern), expected)


@pytest.mark.parametrize("pattern, expected", [
    # "None" means all files, i.e. all match the given pattern
    ("", []),
    ("foo", []),
    ("relative", ["relative/path1", "relative/two"]),
    ("more", ["more/relative"]),
    ])
def test_patterns_prefix_relative(pattern, expected):
    files = ["relative/path1", "relative/two", "more/relative"]

    check_patterns(files, PathPrefixPattern(pattern), expected)


@pytest.mark.parametrize("pattern, expected", [
    # "None" means all files, i.e. all match the given pattern
    ("/*", None),
    ("/./*", None),
    ("*", None),
    ("*/*", None),
    ("*///*", None),
    ("/home/u", []),
    ("/home/*",
     ["/home/user/.profile", "/home/user/.bashrc", "/home/user2/.profile", "/home/user2/public_html/index.html",
      "/home/foo/.thumbnails", "/home/foo/bar/.thumbnails"]),
    ("/home/user/*", ["/home/user/.profile", "/home/user/.bashrc"]),
    ("/etc/*", ["/etc/server/config", "/etc/server/hosts"]),
    ("*/.pr????e", ["/home/user/.profile", "/home/user2/.profile"]),
    ("///etc//////*", ["/etc/server/config", "/etc/server/hosts"]),
    ("/./home//..//home/user2/*", ["/home/user2/.profile", "/home/user2/public_html/index.html"]),
    ("/srv*", ["/srv/messages", "/srv/dmesg"]),
    ("/home/*/.thumbnails", ["/home/foo/.thumbnails", "/home/foo/bar/.thumbnails"]),
    ])
def test_patterns_fnmatch(pattern, expected):
    files = [
        "/etc/server/config", "/etc/server/hosts", "/home", "/home/user/.profile", "/home/user/.bashrc",
        "/home/user2/.profile", "/home/user2/public_html/index.html", "/srv/messages", "/srv/dmesg",
        "/home/foo/.thumbnails", "/home/foo/bar/.thumbnails",
    ]

    check_patterns(files, FnmatchPattern(pattern), expected)


@pytest.mark.parametrize("pattern, expected", [
    # "None" means all files, i.e. all match the given pattern
    ("*", None),
    ("**/*", None),
    ("/**/*", None),
    ("/./*", None),
    ("*/*", None),
    ("*///*", None),
    ("/home/u", []),
    ("/home/*",
     ["/home/user/.profile", "/home/user/.bashrc", "/home/user2/.profile", "/home/user2/public_html/index.html",
      "/home/foo/.thumbnails", "/home/foo/bar/.thumbnails"]),
    ("/home/user/*", ["/home/user/.profile", "/home/user/.bashrc"]),
    ("/etc/*/*", ["/etc/server/config", "/etc/server/hosts"]),
    ("/etc/**/*", ["/etc/server/config", "/etc/server/hosts"]),
    ("/etc/**/*/*", ["/etc/server/config", "/etc/server/hosts"]),
    ("*/.pr????e", []),
    ("**/.pr????e", ["/home/user/.profile", "/home/user2/.profile"]),
    ("///etc//////*", ["/etc/server/config", "/etc/server/hosts"]),
    ("/./home//..//home/user2/", ["/home/user2/.profile", "/home/user2/public_html/index.html"]),
    ("/./home//..//home/user2/**/*", ["/home/user2/.profile", "/home/user2/public_html/index.html"]),
    ("/srv*/", ["/srv/messages", "/srv/dmesg", "/srv2/blafasel"]),
    ("/srv*", ["/srv", "/srv/messages", "/srv/dmesg", "/srv2", "/srv2/blafasel"]),
    ("/srv/*", ["/srv/messages", "/srv/dmesg"]),
    ("/srv2/**", ["/srv2", "/srv2/blafasel"]),
    ("/srv2/**/", ["/srv2/blafasel"]),
    ("/home/*/.thumbnails", ["/home/foo/.thumbnails"]),
    ("/home/*/*/.thumbnails", ["/home/foo/bar/.thumbnails"]),
    ])
def test_patterns_shell(pattern, expected):
    files = [
        "/etc/server/config", "/etc/server/hosts", "/home", "/home/user/.profile", "/home/user/.bashrc",
        "/home/user2/.profile", "/home/user2/public_html/index.html", "/srv", "/srv/messages", "/srv/dmesg",
        "/srv2", "/srv2/blafasel", "/home/foo/.thumbnails", "/home/foo/bar/.thumbnails",
    ]

    check_patterns(files, ShellPattern(pattern), expected)


@pytest.mark.parametrize("pattern, expected", [
    # "None" means all files, i.e. all match the given pattern
    ("", None),
    (".*", None),
    ("^/", None),
    ("^abc$", []),
    ("^[^/]", []),
    ("^(?!/srv|/foo|/opt)",
     ["/home", "/home/user/.profile", "/home/user/.bashrc", "/home/user2/.profile",
      "/home/user2/public_html/index.html", "/home/foo/.thumbnails", "/home/foo/bar/.thumbnails", ]),
    ])
def test_patterns_regex(pattern, expected):
    files = [
        '/srv/data', '/foo/bar', '/home',
        '/home/user/.profile', '/home/user/.bashrc',
        '/home/user2/.profile', '/home/user2/public_html/index.html',
        '/opt/log/messages.txt', '/opt/log/dmesg.txt',
        "/home/foo/.thumbnails", "/home/foo/bar/.thumbnails",
    ]

    obj = RegexPattern(pattern)
    assert str(obj) == pattern
    assert obj.pattern == pattern

    check_patterns(files, obj, expected)


def test_regex_pattern():
    # The forward slash must match the platform-specific path separator
    assert RegexPattern("^/$").match("/")
    assert RegexPattern("^/$").match(os.path.sep)
    assert not RegexPattern(r"^\\$").match("/")


def use_normalized_unicode():
    return sys.platform in ("darwin",)


def _make_test_patterns(pattern):
    return [PathPrefixPattern(pattern),
            FnmatchPattern(pattern),
            RegexPattern("^{}/foo$".format(pattern)),
            ShellPattern(pattern),
            ]


@pytest.mark.parametrize("pattern", _make_test_patterns("b\N{LATIN SMALL LETTER A WITH ACUTE}"))
def test_composed_unicode_pattern(pattern):
    assert pattern.match("b\N{LATIN SMALL LETTER A WITH ACUTE}/foo")
    assert pattern.match("ba\N{COMBINING ACUTE ACCENT}/foo") == use_normalized_unicode()


@pytest.mark.parametrize("pattern", _make_test_patterns("ba\N{COMBINING ACUTE ACCENT}"))
def test_decomposed_unicode_pattern(pattern):
    assert pattern.match("b\N{LATIN SMALL LETTER A WITH ACUTE}/foo") == use_normalized_unicode()
    assert pattern.match("ba\N{COMBINING ACUTE ACCENT}/foo")


@pytest.mark.parametrize("pattern", _make_test_patterns(str(b"ba\x80", "latin1")))
def test_invalid_unicode_pattern(pattern):
    assert not pattern.match("ba/foo")
    assert pattern.match(str(b"ba\x80/foo", "latin1"))


@pytest.mark.parametrize("lines, expected", [
    # "None" means all files, i.e. none excluded
    ([], None),
    (["# Comment only"], None),
    (["*"], []),
    (["# Comment",
      "*/something00.txt",
      "  *whitespace*  ",
      # Whitespace before comment
      " #/ws*",
      # Empty line
      "",
      "# EOF"],
     ["/more/data", "/home", " #/wsfoobar"]),
    (["re:.*"], []),
    (["re:\s"], ["/data/something00.txt", "/more/data", "/home"]),
    ([r"re:(.)(\1)"], ["/more/data", "/home", "\tstart/whitespace", "/whitespace/end\t"]),
    (["", "", "",
      "# This is a test with mixed pattern styles",
      # Case-insensitive pattern
      "re:(?i)BAR|ME$",
      "",
      "*whitespace*",
      "fm:*/something00*"],
     ["/more/data"]),
    ([r"  re:^\s  "], ["/data/something00.txt", "/more/data", "/home", "/whitespace/end\t"]),
    ([r"  re:\s$  "], ["/data/something00.txt", "/more/data", "/home", " #/wsfoobar", "\tstart/whitespace"]),
    (["pp:./"], None),
    (["pp:/"], [" #/wsfoobar", "\tstart/whitespace"]),
    (["pp:aaabbb"], None),
    (["pp:/data", "pp: #/", "pp:\tstart", "pp:/whitespace"], ["/more/data", "/home"]),
    (["/nomatch", "/more/*"],
     ['/data/something00.txt', '/home', ' #/wsfoobar', '\tstart/whitespace', '/whitespace/end\t']),
    # the order of exclude patterns shouldn't matter
    (["/more/*", "/nomatch"],
     ['/data/something00.txt', '/home', ' #/wsfoobar', '\tstart/whitespace', '/whitespace/end\t']),
    ])
def test_exclude_patterns_from_file(tmpdir, lines, expected):
    files = [
        '/data/something00.txt', '/more/data', '/home',
        ' #/wsfoobar',
        '\tstart/whitespace',
        '/whitespace/end\t',
    ]

    def evaluate(filename):
        patterns = []
        load_exclude_file(open(filename, "rt"), patterns)
        matcher = PatternMatcher(fallback=True)
        matcher.add_inclexcl(patterns)
        return [path for path in files if matcher.match(path)]

    exclfile = tmpdir.join("exclude.txt")

    with exclfile.open("wt") as fh:
        fh.write("\n".join(lines))

    assert evaluate(str(exclfile)) == (files if expected is None else expected)


@pytest.mark.parametrize("lines, expected_roots, expected_numpatterns", [
    # "None" means all files, i.e. none excluded
    ([], [], 0),
    (["# Comment only"], [], 0),
    (["- *"], [], 1),
    (["+fm:*/something00.txt",
      "-/data"], [], 2),
    (["R /"], ["/"], 0),
    (["R /",
      "# comment"], ["/"], 0),
    (["# comment",
      "- /data",
      "R /home"], ["/home"], 1),
])
def test_load_patterns_from_file(tmpdir, lines, expected_roots, expected_numpatterns):
    def evaluate(filename):
        roots = []
        inclexclpatterns = []
        load_pattern_file(open(filename, "rt"), roots, inclexclpatterns)
        return roots, len(inclexclpatterns)
    patternfile = tmpdir.join("patterns.txt")

    with patternfile.open("wt") as fh:
        fh.write("\n".join(lines))

    roots, numpatterns = evaluate(str(patternfile))
    assert roots == expected_roots
    assert numpatterns == expected_numpatterns


def test_switch_patterns_style():
    patterns = """\
        +0_initial_default_is_shell
        p fm
        +1_fnmatch
        P re
        +2_regex
        +3_more_regex
        P pp
        +4_pathprefix
        p fm
        p sh
        +5_shell
    """
    pattern_file = io.StringIO(patterns)
    roots, patterns = [], []
    load_pattern_file(pattern_file, roots, patterns)
    assert len(patterns) == 6
    assert isinstance(patterns[0].val, ShellPattern)
    assert isinstance(patterns[1].val, FnmatchPattern)
    assert isinstance(patterns[2].val, RegexPattern)
    assert isinstance(patterns[3].val, RegexPattern)
    assert isinstance(patterns[4].val, PathPrefixPattern)
    assert isinstance(patterns[5].val, ShellPattern)


@pytest.mark.parametrize("lines", [
    (["X /data"]),  # illegal pattern type prefix
    (["/data"]),    # need a pattern type prefix
])
def test_load_invalid_patterns_from_file(tmpdir, lines):
    patternfile = tmpdir.join("patterns.txt")
    with patternfile.open("wt") as fh:
        fh.write("\n".join(lines))
    filename = str(patternfile)
    with pytest.raises(argparse.ArgumentTypeError):
        roots = []
        inclexclpatterns = []
        load_pattern_file(open(filename, "rt"), roots, inclexclpatterns)


@pytest.mark.parametrize("lines, expected", [
    # "None" means all files, i.e. none excluded
    ([], None),
    (["# Comment only"], None),
    (["- *"], []),
    # default match type is sh: for patterns -> * doesn't match a /
    (["-*/something0?.txt"],
     ['/data', '/data/something00.txt', '/data/subdir/something01.txt',
      '/home', '/home/leo', '/home/leo/t', '/home/other']),
    (["-fm:*/something00.txt"],
     ['/data', '/data/subdir/something01.txt', '/home', '/home/leo', '/home/leo/t', '/home/other']),
    (["-fm:*/something0?.txt"],
     ["/data", '/home', '/home/leo', '/home/leo/t', '/home/other']),
    (["+/*/something0?.txt",
      "-/data"],
     ["/data/something00.txt", '/home', '/home/leo', '/home/leo/t', '/home/other']),
    (["+fm:*/something00.txt",
      "-/data"],
     ["/data/something00.txt", '/home', '/home/leo', '/home/leo/t', '/home/other']),
    # include /home/leo and exclude the rest of /home:
    (["+/home/leo",
      "-/home/*"],
     ['/data', '/data/something00.txt', '/data/subdir/something01.txt', '/home', '/home/leo', '/home/leo/t']),
    # wrong order, /home/leo is already excluded by -/home/*:
    (["-/home/*",
      "+/home/leo"],
     ['/data', '/data/something00.txt', '/data/subdir/something01.txt', '/home']),
    (["+fm:/home/leo",
      "-/home/"],
     ['/data', '/data/something00.txt', '/data/subdir/something01.txt', '/home', '/home/leo', '/home/leo/t']),
])
def test_inclexcl_patterns_from_file(tmpdir, lines, expected):
    files = [
        '/data', '/data/something00.txt', '/data/subdir/something01.txt',
        '/home', '/home/leo', '/home/leo/t', '/home/other'
    ]

    def evaluate(filename):
        matcher = PatternMatcher(fallback=True)
        roots = []
        inclexclpatterns = []
        load_pattern_file(open(filename, "rt"), roots, inclexclpatterns)
        matcher.add_inclexcl(inclexclpatterns)
        return [path for path in files if matcher.match(path)]

    patternfile = tmpdir.join("patterns.txt")

    with patternfile.open("wt") as fh:
        fh.write("\n".join(lines))

    assert evaluate(str(patternfile)) == (files if expected is None else expected)


@pytest.mark.parametrize("pattern, cls", [
    ("", FnmatchPattern),

    # Default style
    ("*", FnmatchPattern),
    ("/data/*", FnmatchPattern),

    # fnmatch style
    ("fm:", FnmatchPattern),
    ("fm:*", FnmatchPattern),
    ("fm:/data/*", FnmatchPattern),
    ("fm:fm:/data/*", FnmatchPattern),

    # Regular expression
    ("re:", RegexPattern),
    ("re:.*", RegexPattern),
    ("re:^/something/", RegexPattern),
    ("re:re:^/something/", RegexPattern),

    # Path prefix
    ("pp:", PathPrefixPattern),
    ("pp:/", PathPrefixPattern),
    ("pp:/data/", PathPrefixPattern),
    ("pp:pp:/data/", PathPrefixPattern),

    # Shell-pattern style
    ("sh:", ShellPattern),
    ("sh:*", ShellPattern),
    ("sh:/data/*", ShellPattern),
    ("sh:sh:/data/*", ShellPattern),
    ])
def test_parse_pattern(pattern, cls):
    assert isinstance(parse_pattern(pattern), cls)


@pytest.mark.parametrize("pattern", ["aa:", "fo:*", "00:", "x1:abc"])
def test_parse_pattern_error(pattern):
    with pytest.raises(ValueError):
        parse_pattern(pattern)


def test_pattern_matcher():
    pm = PatternMatcher()

    assert pm.fallback is None

    for i in ["", "foo", "bar"]:
        assert pm.match(i) is None

    # add extra entries to aid in testing
    for target in ["A", "B", "Empty", "FileNotFound"]:
        pm.is_include_cmd[target] = target

    pm.add([RegexPattern("^a")], "A")
    pm.add([RegexPattern("^b"), RegexPattern("^z")], "B")
    pm.add([RegexPattern("^$")], "Empty")
    pm.fallback = "FileNotFound"

    assert pm.match("") == "Empty"
    assert pm.match("aaa") == "A"
    assert pm.match("bbb") == "B"
    assert pm.match("ccc") == "FileNotFound"
    assert pm.match("xyz") == "FileNotFound"
    assert pm.match("z") == "B"

    assert PatternMatcher(fallback="hey!").fallback == "hey!"

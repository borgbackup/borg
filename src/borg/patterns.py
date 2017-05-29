import argparse
import fnmatch
import os.path
import re
import sys
import unicodedata
from collections import namedtuple
from enum import Enum

from . import shellpattern
from .helpers import clean_lines


def parse_patternfile_line(line, roots, ie_commands, fallback):
    """Parse a pattern-file line and act depending on which command it represents."""
    ie_command = parse_inclexcl_command(line, fallback=fallback)
    if ie_command.cmd is IECommand.RootPath:
        roots.append(ie_command.val)
    elif ie_command.cmd is IECommand.PatternStyle:
        fallback = ie_command.val
    else:
        # it is some kind of include/exclude command
        ie_commands.append(ie_command)
    return fallback


def load_pattern_file(fileobj, roots, ie_commands, fallback=None):
    if fallback is None:
        fallback = ShellPattern  # ShellPattern is defined later in this module
    for line in clean_lines(fileobj):
        fallback = parse_patternfile_line(line, roots, ie_commands, fallback)


def load_exclude_file(fileobj, patterns):
    for patternstr in clean_lines(fileobj):
        patterns.append(parse_exclude_pattern(patternstr))


class ArgparsePatternAction(argparse.Action):
    def __init__(self, nargs=1, **kw):
        super().__init__(nargs=nargs, **kw)

    def __call__(self, parser, args, values, option_string=None):
        parse_patternfile_line(values[0], args.paths, args.patterns, ShellPattern)


class ArgparsePatternFileAction(argparse.Action):
    def __init__(self, nargs=1, **kw):
        super().__init__(nargs=nargs, **kw)

    def __call__(self, parser, args, values, option_string=None):
        """Load and parse patterns from a file.
        Lines empty or starting with '#' after stripping whitespace on both line ends are ignored.
        """
        filename = values[0]
        with open(filename) as f:
            self.parse(f, args)

    def parse(self, fobj, args):
        load_pattern_file(fobj, args.paths, args.patterns)


class ArgparseExcludeFileAction(ArgparsePatternFileAction):
    def parse(self, fobj, args):
        load_exclude_file(fobj, args.patterns)


class PatternMatcher:
    """Represents a collection of pattern objects to match paths against.

    *fallback* is a boolean value that *match()* returns if no matching patterns are found.

    """
    def __init__(self, fallback=None):
        self._items = []

        # Value to return from match function when none of the patterns match.
        self.fallback = fallback

        # optimizations
        self._path_full_patterns = {}  # full path -> return value

        # indicates whether the last match() call ended on a pattern for which
        # we should recurse into any matching folder.  Will be set to True or
        # False when calling match().
        self.recurse_dir = None

        # whether to recurse into directories when no match is found
        # TODO: allow modification as a config option?
        self.recurse_dir_default = True

        self.include_patterns = []

        # TODO: move this info to parse_inclexcl_command and store in PatternBase subclass?
        self.is_include_cmd = {
            IECommand.Exclude: False,
            IECommand.ExcludeNoRecurse: False,
            IECommand.Include: True
        }

    def empty(self):
        return not len(self._items) and not len(self._path_full_patterns)

    def _add(self, pattern, cmd):
        """*cmd* is an IECommand value.
        """
        if isinstance(pattern, PathFullPattern):
            key = pattern.pattern  # full, normalized path
            self._path_full_patterns[key] = cmd
        else:
            self._items.append((pattern, cmd))

    def add(self, patterns, cmd):
        """Add list of patterns to internal list. *cmd* indicates whether the
        pattern is an include/exclude pattern, and whether recursion should be
        done on excluded folders.
        """
        for pattern in patterns:
            self._add(pattern, cmd)

    def add_includepaths(self, include_paths):
        """Used to add inclusion-paths from args.paths (from commandline).
        """
        include_patterns = [parse_pattern(p, PathPrefixPattern) for p in include_paths]
        self.add(include_patterns, IECommand.Include)
        self.fallback = not include_patterns
        self.include_patterns = include_patterns

    def get_unmatched_include_patterns(self):
        "Note that this only returns patterns added via *add_includepaths*."
        return [p for p in self.include_patterns if p.match_count == 0]

    def add_inclexcl(self, patterns):
        """Add list of patterns (of type CmdTuple) to internal list.
        """
        for pattern, cmd in patterns:
            self._add(pattern, cmd)

    def match(self, path):
        """Return True or False depending on whether *path* is matched.

        If no match is found among the patterns in this matcher, then the value
        in self.fallback is returned (defaults to None).

        """
        path = normalize_path(path)
        # do a fast lookup for full path matches (note: we do not count such matches):
        non_existent = object()
        value = self._path_full_patterns.get(path, non_existent)

        if value is not non_existent:
            # we have a full path match!
            self.recurse_dir = command_recurses_dir(value)
            return self.is_include_cmd[value]

        # this is the slow way, if we have many patterns in self._items:
        for (pattern, cmd) in self._items:
            if pattern.match(path, normalize=False):
                self.recurse_dir = pattern.recurse_dir
                return self.is_include_cmd[cmd]

        # by default we will recurse if there is no match
        self.recurse_dir = self.recurse_dir_default
        return self.fallback


def normalize_path(path):
    """normalize paths for MacOS (but do nothing on other platforms)"""
    # HFS+ converts paths to a canonical form, so users shouldn't be required to enter an exact match.
    # Windows and Unix filesystems allow different forms, so users always have to enter an exact match.
    return unicodedata.normalize('NFD', path) if sys.platform == 'darwin' else path


class PatternBase:
    """Shared logic for inclusion/exclusion patterns.
    """
    PREFIX = NotImplemented

    def __init__(self, pattern, recurse_dir=False):
        self.pattern_orig = pattern
        self.match_count = 0
        pattern = normalize_path(pattern)
        self._prepare(pattern)
        self.recurse_dir = recurse_dir

    def match(self, path, normalize=True):
        """Return a boolean indicating whether *path* is matched by this pattern.

        If normalize is True (default), the path will get normalized using normalize_path(),
        otherwise it is assumed that it already is normalized using that function.
        """
        if normalize:
            path = normalize_path(path)
        matches = self._match(path)
        if matches:
            self.match_count += 1
        return matches

    def __repr__(self):
        return '%s(%s)' % (type(self), self.pattern)

    def __str__(self):
        return self.pattern_orig

    def _prepare(self, pattern):
        "Should set the value of self.pattern"
        raise NotImplementedError

    def _match(self, path):
        raise NotImplementedError


class PathFullPattern(PatternBase):
    """Full match of a path."""
    PREFIX = "pf"

    def _prepare(self, pattern):
        self.pattern = os.path.normpath(pattern)

    def _match(self, path):
        return path == self.pattern


# For PathPrefixPattern, FnmatchPattern and ShellPattern, we require that the pattern either match the whole path
# or an initial segment of the path up to but not including a path separator. To unify the two cases, we add a path
# separator to the end of the path before matching.


class PathPrefixPattern(PatternBase):
    """Literal files or directories listed on the command line
    for some operations (e.g. extract, but not create).
    If a directory is specified, all paths that start with that
    path match as well.  A trailing slash makes no difference.
    """
    PREFIX = "pp"

    def _prepare(self, pattern):
        self.pattern = os.path.normpath(pattern).rstrip(os.path.sep) + os.path.sep

    def _match(self, path):
        return (path + os.path.sep).startswith(self.pattern)


class FnmatchPattern(PatternBase):
    """Shell glob patterns to exclude.  A trailing slash means to
    exclude the contents of a directory, but not the directory itself.
    """
    PREFIX = "fm"

    def _prepare(self, pattern):
        if pattern.endswith(os.path.sep):
            pattern = os.path.normpath(pattern).rstrip(os.path.sep) + os.path.sep + '*' + os.path.sep
        else:
            pattern = os.path.normpath(pattern) + os.path.sep + '*'

        self.pattern = pattern

        # fnmatch and re.match both cache compiled regular expressions.
        # Nevertheless, this is about 10 times faster.
        self.regex = re.compile(fnmatch.translate(self.pattern))

    def _match(self, path):
        return (self.regex.match(path + os.path.sep) is not None)


class ShellPattern(PatternBase):
    """Shell glob patterns to exclude.  A trailing slash means to
    exclude the contents of a directory, but not the directory itself.
    """
    PREFIX = "sh"

    def _prepare(self, pattern):
        sep = os.path.sep

        if pattern.endswith(sep):
            pattern = os.path.normpath(pattern).rstrip(sep) + sep + "**" + sep + "*" + sep
        else:
            pattern = os.path.normpath(pattern) + sep + "**" + sep + "*"

        self.pattern = pattern
        self.regex = re.compile(shellpattern.translate(self.pattern))

    def _match(self, path):
        return (self.regex.match(path + os.path.sep) is not None)


class RegexPattern(PatternBase):
    """Regular expression to exclude.
    """
    PREFIX = "re"

    def _prepare(self, pattern):
        self.pattern = pattern
        self.regex = re.compile(pattern)

    def _match(self, path):
        # Normalize path separators
        if os.path.sep != '/':
            path = path.replace(os.path.sep, '/')

        return (self.regex.search(path) is not None)


_PATTERN_CLASSES = {
    FnmatchPattern,
    PathFullPattern,
    PathPrefixPattern,
    RegexPattern,
    ShellPattern,
}

_PATTERN_CLASS_BY_PREFIX = dict((i.PREFIX, i) for i in _PATTERN_CLASSES)

CmdTuple = namedtuple('CmdTuple', 'val cmd')


class IECommand(Enum):
    """A command that an InclExcl file line can represent.
    """
    RootPath = 1
    PatternStyle = 2
    Include = 3
    Exclude = 4
    ExcludeNoRecurse = 5


def command_recurses_dir(cmd):
    # TODO?: raise error or return None if *cmd* is RootPath or PatternStyle
    return cmd not in [IECommand.ExcludeNoRecurse]


def get_pattern_class(prefix):
    try:
        return _PATTERN_CLASS_BY_PREFIX[prefix]
    except KeyError:
        raise ValueError("Unknown pattern style: {}".format(prefix)) from None


def parse_pattern(pattern, fallback=FnmatchPattern, recurse_dir=True):
    """Read pattern from string and return an instance of the appropriate implementation class.

    """
    if len(pattern) > 2 and pattern[2] == ":" and pattern[:2].isalnum():
        (style, pattern) = (pattern[:2], pattern[3:])
        cls = get_pattern_class(style)
    else:
        cls = fallback
    return cls(pattern, recurse_dir)


def parse_exclude_pattern(pattern_str, fallback=FnmatchPattern):
    """Read pattern from string and return an instance of the appropriate implementation class.
    """
    epattern_obj = parse_pattern(pattern_str, fallback, recurse_dir=False)
    return CmdTuple(epattern_obj, IECommand.ExcludeNoRecurse)


def parse_inclexcl_command(cmd_line_str, fallback=ShellPattern):
    """Read a --patterns-from command from string and return a CmdTuple object."""

    cmd_prefix_map = {
        '-': IECommand.Exclude,
        '!': IECommand.ExcludeNoRecurse,
        '+': IECommand.Include,
        'R': IECommand.RootPath,
        'r': IECommand.RootPath,
        'P': IECommand.PatternStyle,
        'p': IECommand.PatternStyle,
    }

    try:
        cmd = cmd_prefix_map[cmd_line_str[0]]

        # remaining text on command-line following the command character
        remainder_str = cmd_line_str[1:].lstrip()

        if not remainder_str:
            raise ValueError("Missing pattern/information!")
    except (IndexError, KeyError, ValueError):
        raise argparse.ArgumentTypeError("Unable to parse pattern/command: {}".format(cmd_line_str))

    if cmd is IECommand.RootPath:
        # TODO: validate string?
        val = remainder_str
    elif cmd is IECommand.PatternStyle:
        # then remainder_str is something like 're' or 'sh'
        try:
            val = get_pattern_class(remainder_str)
        except ValueError:
            raise argparse.ArgumentTypeError("Invalid pattern style: {}".format(remainder_str))
    else:
        # determine recurse_dir based on command type
        recurse_dir = command_recurses_dir(cmd)
        val = parse_pattern(remainder_str, fallback, recurse_dir)

    return CmdTuple(val, cmd)

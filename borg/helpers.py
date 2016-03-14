import argparse
from collections import namedtuple
from functools import wraps
import grp
import os
import stat
import textwrap
import pwd
import re
from shutil import get_terminal_size
import sys
import platform
import time
import unicodedata

import logging
from .logger import create_logger
logger = create_logger()

from datetime import datetime, timezone, timedelta
from fnmatch import translate
from operator import attrgetter

from . import __version__ as borg_version
from . import hashindex
from . import chunker
from . import crypto
from . import shellpattern
import msgpack
import msgpack.fallback

import socket

# return codes returned by borg command
# when borg is killed by signal N, rc = 128 + N
EXIT_SUCCESS = 0  # everything done, no problems
EXIT_WARNING = 1  # reached normal end of operation, but there were issues
EXIT_ERROR = 2  # terminated abruptly, did not reach end of operation


class Error(Exception):
    """Error base class"""

    # if we raise such an Error and it is only catched by the uppermost
    # exception handler (that exits short after with the given exit_code),
    # it is always a (fatal and abrupt) EXIT_ERROR, never just a warning.
    exit_code = EXIT_ERROR
    # show a traceback?
    traceback = False

    def get_message(self):
        return type(self).__doc__.format(*self.args)


class ErrorWithTraceback(Error):
    """like Error, but show a traceback also"""
    traceback = True


class IntegrityError(ErrorWithTraceback):
    """Data integrity error"""


class ExtensionModuleError(Error):
    """The Borg binary extension modules do not seem to be properly installed"""


def check_extension_modules():
    from . import platform
    if hashindex.API_VERSION != 2:
        raise ExtensionModuleError
    if chunker.API_VERSION != 2:
        raise ExtensionModuleError
    if crypto.API_VERSION != 2:
        raise ExtensionModuleError
    if platform.API_VERSION != 2:
        raise ExtensionModuleError


class Manifest:

    MANIFEST_ID = b'\0' * 32

    def __init__(self, key, repository):
        self.archives = {}
        self.config = {}
        self.key = key
        self.repository = repository

    @classmethod
    def load(cls, repository, key=None):
        from .key import key_factory
        cdata = repository.get(cls.MANIFEST_ID)
        if not key:
            key = key_factory(repository, cdata)
        manifest = cls(key, repository)
        data = key.decrypt(None, cdata)
        manifest.id = key.id_hash(data)
        m = msgpack.unpackb(data)
        if not m.get(b'version') == 1:
            raise ValueError('Invalid manifest version')
        manifest.archives = dict((k.decode('utf-8'), v) for k, v in m[b'archives'].items())
        manifest.timestamp = m.get(b'timestamp')
        if manifest.timestamp:
            manifest.timestamp = manifest.timestamp.decode('ascii')
        manifest.config = m[b'config']
        return manifest, key

    def write(self):
        self.timestamp = datetime.utcnow().isoformat()
        data = msgpack.packb(StableDict({
            'version': 1,
            'archives': self.archives,
            'timestamp': self.timestamp,
            'config': self.config,
        }))
        self.id = self.key.id_hash(data)
        self.repository.put(self.MANIFEST_ID, self.key.encrypt(data))

    def list_archive_infos(self, sort_by=None, reverse=False):
        # inexpensive Archive.list_archives replacement if we just need .name, .id, .ts
        ArchiveInfo = namedtuple('ArchiveInfo', 'name id ts')
        archives = []
        for name, values in self.archives.items():
            ts = parse_timestamp(values[b'time'].decode('utf-8'))
            id = values[b'id']
            archives.append(ArchiveInfo(name=name, id=id, ts=ts))
        if sort_by is not None:
            archives = sorted(archives, key=attrgetter(sort_by), reverse=reverse)
        return archives


def prune_within(archives, within):
    multiplier = {'H': 1, 'd': 24, 'w': 24 * 7, 'm': 24 * 31, 'y': 24 * 365}
    try:
        hours = int(within[:-1]) * multiplier[within[-1]]
    except (KeyError, ValueError):
        # I don't like how this displays the original exception too:
        raise argparse.ArgumentTypeError('Unable to parse --within option: "%s"' % within)
    if hours <= 0:
        raise argparse.ArgumentTypeError('Number specified using --within option must be positive')
    target = datetime.now(timezone.utc) - timedelta(seconds=hours * 3600)
    return [a for a in archives if a.ts > target]


def prune_split(archives, pattern, n, skip=[]):
    last = None
    keep = []
    if n == 0:
        return keep
    for a in sorted(archives, key=attrgetter('ts'), reverse=True):
        period = to_localtime(a.ts).strftime(pattern)
        if period != last:
            last = period
            if a not in skip:
                keep.append(a)
                if len(keep) == n:
                    break
    return keep


class Statistics:

    def __init__(self):
        self.osize = self.csize = self.usize = self.nfiles = 0
        self.last_progress = 0  # timestamp when last progress was shown

    def update(self, size, csize, unique):
        self.osize += size
        self.csize += csize
        if unique:
            self.usize += csize

    summary = """\
                       Original size      Compressed size    Deduplicated size
{label:15} {stats.osize_fmt:>20s} {stats.csize_fmt:>20s} {stats.usize_fmt:>20s}"""

    def __str__(self):
        return self.summary.format(stats=self, label='This archive:')

    def __repr__(self):
        return "<{cls} object at {hash:#x} ({self.osize}, {self.csize}, {self.usize})>".format(cls=type(self).__name__, hash=id(self), self=self)

    @property
    def osize_fmt(self):
        return format_file_size(self.osize)

    @property
    def usize_fmt(self):
        return format_file_size(self.usize)

    @property
    def csize_fmt(self):
        return format_file_size(self.csize)

    def show_progress(self, item=None, final=False, stream=None, dt=None):
        now = time.time()
        if dt is None or now - self.last_progress > dt:
            self.last_progress = now
            columns, lines = get_terminal_size()
            if not final:
                msg = '{0.osize_fmt} O {0.csize_fmt} C {0.usize_fmt} D {0.nfiles} N '.format(self)
                path = remove_surrogates(item[b'path']) if item else ''
                space = columns - len(msg)
                if space < len('...') + len(path):
                    path = '%s...%s' % (path[:(space // 2) - len('...')], path[-space // 2:])
                msg += "{0:<{space}}".format(path, space=space)
            else:
                msg = ' ' * columns
            print(msg, file=stream or sys.stderr, end="\r", flush=True)


def get_keys_dir():
    """Determine where to repository keys and cache"""
    xdg_config = os.environ.get('XDG_CONFIG_HOME', os.path.join(os.path.expanduser('~'), '.config'))
    keys_dir = os.environ.get('BORG_KEYS_DIR', os.path.join(xdg_config, 'borg', 'keys'))
    if not os.path.exists(keys_dir):
        os.makedirs(keys_dir)
        os.chmod(keys_dir, stat.S_IRWXU)
    return keys_dir


def get_cache_dir():
    """Determine where to repository keys and cache"""
    xdg_cache = os.environ.get('XDG_CACHE_HOME', os.path.join(os.path.expanduser('~'), '.cache'))
    cache_dir = os.environ.get('BORG_CACHE_DIR', os.path.join(xdg_cache, 'borg'))
    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir)
        os.chmod(cache_dir, stat.S_IRWXU)
        with open(os.path.join(cache_dir, 'CACHEDIR.TAG'), 'w') as fd:
            fd.write(textwrap.dedent("""
                Signature: 8a477f597d28d172789f06886806bc55
                # This file is a cache directory tag created by Borg.
                # For information about cache directory tags, see:
                #       http://www.brynosaurus.com/cachedir/
                """).lstrip())
    return cache_dir


def to_localtime(ts):
    """Convert datetime object from UTC to local time zone"""
    return datetime(*time.localtime((ts - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds())[:6])


def parse_timestamp(timestamp):
    """Parse a ISO 8601 timestamp string"""
    if '.' in timestamp:  # microseconds might not be present
        return datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%f').replace(tzinfo=timezone.utc)
    else:
        return datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)


def load_excludes(fh):
    """Load and parse exclude patterns from file object. Lines empty or starting with '#' after stripping whitespace on
    both line ends are ignored.
    """
    patterns = (line for line in (i.strip() for i in fh) if not line.startswith('#'))
    return [parse_pattern(pattern) for pattern in patterns if pattern]


def update_excludes(args):
    """Merge exclude patterns from files with those on command line."""
    if hasattr(args, 'exclude_files') and args.exclude_files:
        if not hasattr(args, 'excludes') or args.excludes is None:
            args.excludes = []
        for file in args.exclude_files:
            args.excludes += load_excludes(file)
            file.close()


class PatternMatcher:
    def __init__(self, fallback=None):
        self._items = []

        # Value to return from match function when none of the patterns match.
        self.fallback = fallback

    def add(self, patterns, value):
        """Add list of patterns to internal list. The given value is returned from the match function when one of the
        given patterns matches.
        """
        self._items.extend((i, value) for i in patterns)

    def match(self, path):
        for (pattern, value) in self._items:
            if pattern.match(path):
                return value

        return self.fallback


def normalized(func):
    """ Decorator for the Pattern match methods, returning a wrapper that
    normalizes OSX paths to match the normalized pattern on OSX, and
    returning the original method on other platforms"""
    @wraps(func)
    def normalize_wrapper(self, path):
        return func(self, unicodedata.normalize("NFD", path))

    if sys.platform in ('darwin',):
        # HFS+ converts paths to a canonical form, so users shouldn't be
        # required to enter an exact match
        return normalize_wrapper
    else:
        # Windows and Unix filesystems allow different forms, so users
        # always have to enter an exact match
        return func


class PatternBase:
    """Shared logic for inclusion/exclusion patterns.
    """
    PREFIX = NotImplemented

    def __init__(self, pattern):
        self.pattern_orig = pattern
        self.match_count = 0

        if sys.platform in ('darwin',):
            pattern = unicodedata.normalize("NFD", pattern)

        self._prepare(pattern)

    @normalized
    def match(self, path):
        matches = self._match(path)

        if matches:
            self.match_count += 1

        return matches

    def __repr__(self):
        return '%s(%s)' % (type(self), self.pattern)

    def __str__(self):
        return self.pattern_orig

    def _prepare(self, pattern):
        raise NotImplementedError

    def _match(self, path):
        raise NotImplementedError


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
        self.regex = re.compile(translate(self.pattern))

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


_PATTERN_STYLES = set([
    FnmatchPattern,
    PathPrefixPattern,
    RegexPattern,
    ShellPattern,
])

_PATTERN_STYLE_BY_PREFIX = dict((i.PREFIX, i) for i in _PATTERN_STYLES)


def parse_pattern(pattern, fallback=FnmatchPattern):
    """Read pattern from string and return an instance of the appropriate implementation class.
    """
    if len(pattern) > 2 and pattern[2] == ":" and pattern[:2].isalnum():
        (style, pattern) = (pattern[:2], pattern[3:])

        cls = _PATTERN_STYLE_BY_PREFIX.get(style, None)

        if cls is None:
            raise ValueError("Unknown pattern style: {}".format(style))
    else:
        cls = fallback

    return cls(pattern)


def timestamp(s):
    """Convert a --timestamp=s argument to a datetime object"""
    try:
        # is it pointing to a file / directory?
        ts = os.stat(s).st_mtime
        return datetime.utcfromtimestamp(ts)
    except OSError:
        # didn't work, try parsing as timestamp. UTC, no TZ, no microsecs support.
        for format in ('%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S+00:00',
                       '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S',
                       '%Y-%m-%dT%H:%M', '%Y-%m-%d %H:%M',
                       '%Y-%m-%d', '%Y-%j',
                       ):
            try:
                return datetime.strptime(s, format)
            except ValueError:
                continue
        raise ValueError


def ChunkerParams(s):
    chunk_min, chunk_max, chunk_mask, window_size = s.split(',')
    if int(chunk_max) > 23:
        # do not go beyond 2**23 (8MB) chunk size now,
        # COMPR_BUFFER can only cope with up to this size
        raise ValueError('max. chunk size exponent must not be more than 23 (2^23 = 8MiB max. chunk size)')
    return int(chunk_min), int(chunk_max), int(chunk_mask), int(window_size)


def CompressionSpec(s):
    values = s.split(',')
    count = len(values)
    if count < 1:
        raise ValueError
    # --compression algo[,level]
    name = values[0]
    if name in ('none', 'lz4', ):
        return dict(name=name)
    if name in ('zlib', 'lzma', ):
        if count < 2:
            level = 6  # default compression level in py stdlib
        elif count == 2:
            level = int(values[1])
            if not 0 <= level <= 9:
                raise ValueError
        else:
            raise ValueError
        return dict(name=name, level=level)
    raise ValueError


def dir_is_cachedir(path):
    """Determines whether the specified path is a cache directory (and
    therefore should potentially be excluded from the backup) according to
    the CACHEDIR.TAG protocol
    (http://www.brynosaurus.com/cachedir/spec.html).
    """

    tag_contents = b'Signature: 8a477f597d28d172789f06886806bc55'
    tag_path = os.path.join(path, 'CACHEDIR.TAG')
    try:
        if os.path.exists(tag_path):
            with open(tag_path, 'rb') as tag_file:
                tag_data = tag_file.read(len(tag_contents))
                if tag_data == tag_contents:
                    return True
    except OSError:
        pass
    return False


def dir_is_tagged(path, exclude_caches, exclude_if_present):
    """Determines whether the specified path is excluded by being a cache
    directory or containing user-specified tag files. Returns a list of the
    paths of the tag files (either CACHEDIR.TAG or the matching
    user-specified files).
    """
    tag_paths = []
    if exclude_caches and dir_is_cachedir(path):
        tag_paths.append(os.path.join(path, 'CACHEDIR.TAG'))
    if exclude_if_present is not None:
        for tag in exclude_if_present:
            tag_path = os.path.join(path, tag)
            if os.path.isfile(tag_path):
                tag_paths.append(tag_path)
    return tag_paths


def format_line(format, data):
    # TODO: Filter out unwanted properties of str.format(), because "format" is user provided.

    try:
        return format.format(**data)
    except (KeyError, ValueError) as e:
        # this should catch format errors
        print('Error in lineformat: "{}" - reason "{}"'.format(format, str(e)))
    except:
        # something unexpected, print error and raise exception
        print('Error in lineformat: "{}" - reason "{}"'.format(format, str(e)))
        raise
    return ''


def safe_timestamp(item_timestamp_ns):
    try:
        return datetime.fromtimestamp(bigint_to_int(item_timestamp_ns) / 1e9)
    except OverflowError:
        # likely a broken file time and datetime did not want to go beyond year 9999
        return datetime(9999, 12, 31, 23, 59, 59)


def format_time(t):
    """use ISO-8601 date and time format
    """
    return t.strftime('%a, %Y-%m-%d %H:%M:%S')


def format_timedelta(td):
    """Format timedelta in a human friendly format
    """
    # Since td.total_seconds() requires python 2.7
    ts = (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10 ** 6) / float(10 ** 6)
    s = ts % 60
    m = int(ts / 60) % 60
    h = int(ts / 3600) % 24
    txt = '%.2f seconds' % s
    if m:
        txt = '%d minutes %s' % (m, txt)
    if h:
        txt = '%d hours %s' % (h, txt)
    if td.days:
        txt = '%d days %s' % (td.days, txt)
    return txt


def format_file_size(v, precision=2):
    """Format file size into a human friendly format
    """
    return sizeof_fmt_decimal(v, suffix='B', sep=' ', precision=precision)


def sizeof_fmt(num, suffix='B', units=None, power=None, sep='', precision=2):
    for unit in units[:-1]:
        if abs(round(num, precision)) < power:
            if isinstance(num, int):
                return "{}{}{}{}".format(num, sep, unit, suffix)
            else:
                return "{:3.{}f}{}{}{}".format(num, precision, sep, unit, suffix)
        num /= float(power)
    return "{:.{}f}{}{}{}".format(num, precision, sep, units[-1], suffix)


def sizeof_fmt_iec(num, suffix='B', sep='', precision=2):
    return sizeof_fmt(num, suffix=suffix, sep=sep, precision=precision, units=['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi', 'Yi'], power=1024)


def sizeof_fmt_decimal(num, suffix='B', sep='', precision=2):
    return sizeof_fmt(num, suffix=suffix, sep=sep, precision=precision, units=['', 'k', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y'], power=1000)


def format_archive(archive):
    return '%-36s %s' % (archive.name, format_time(to_localtime(archive.ts)))


def memoize(function):
    cache = {}

    def decorated_function(*args):
        try:
            return cache[args]
        except KeyError:
            val = function(*args)
            cache[args] = val
            return val
    return decorated_function


@memoize
def uid2user(uid, default=None):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return default


@memoize
def user2uid(user, default=None):
    try:
        return user and pwd.getpwnam(user).pw_uid
    except KeyError:
        return default


@memoize
def gid2group(gid, default=None):
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return default


@memoize
def group2gid(group, default=None):
    try:
        return group and grp.getgrnam(group).gr_gid
    except KeyError:
        return default


def posix_acl_use_stored_uid_gid(acl):
    """Replace the user/group field with the stored uid/gid
    """
    entries = []
    for entry in safe_decode(acl).split('\n'):
        if entry:
            fields = entry.split(':')
            if len(fields) == 4:
                entries.append(':'.join([fields[0], fields[3], fields[2]]))
            else:
                entries.append(entry)
    return safe_encode('\n'.join(entries))


def safe_decode(s, coding='utf-8', errors='surrogateescape'):
    """decode bytes to str, with round-tripping "invalid" bytes"""
    return s.decode(coding, errors)


def safe_encode(s, coding='utf-8', errors='surrogateescape'):
    """encode str to bytes, with round-tripping "invalid" bytes"""
    return s.encode(coding, errors)


class Location:
    """Object representing a repository / archive location
    """
    proto = user = host = port = path = archive = None
    # borg mount's FUSE filesystem creates one level of directories from
    # the archive names. Thus, we must not accept "/" in archive names.
    ssh_re = re.compile(r'(?P<proto>ssh)://(?:(?P<user>[^@]+)@)?'
                        r'(?P<host>[^:/#]+)(?::(?P<port>\d+))?'
                        r'(?P<path>[^:]+)(?:::(?P<archive>[^/]+))?$')
    file_re = re.compile(r'(?P<proto>file)://'
                         r'(?P<path>[^:]+)(?:::(?P<archive>[^/]+))?$')
    scp_re = re.compile(r'((?:(?P<user>[^@]+)@)?(?P<host>[^:/]+):)?'
                        r'(?P<path>[^:]+)(?:::(?P<archive>[^/]+))?$')
    # get the repo from BORG_RE env and the optional archive from param.
    # if the syntax requires giving REPOSITORY (see "borg mount"),
    # use "::" to let it use the env var.
    # if REPOSITORY argument is optional, it'll automatically use the env.
    env_re = re.compile(r'(?:::(?P<archive>[^/]+)?)?$')

    def __init__(self, text=''):
        self.orig = text
        if not self.parse(self.orig):
            raise ValueError

    def preformat_text(self, text):
        """Format repository and archive path with common tags"""
        current_time = datetime.now()
        data = {
            'pid': os.getpid(),
            'fqdn': socket.getfqdn(),
            'hostname': socket.gethostname(),
            'now': current_time.now(),
            'utcnow': current_time.utcnow(),
            'user': uid2user(os.getuid(), os.getuid())
            }
        return format_line(text, data)

    def parse(self, text):
        text = self.preformat_text(text)
        valid = self._parse(text)
        if valid:
            return True
        m = self.env_re.match(text)
        if not m:
            return False
        repo = os.environ.get('BORG_REPO')
        if repo is None:
            return False
        valid = self._parse(repo)
        if not valid:
            return False
        self.archive = m.group('archive')
        return True

    def _parse(self, text):
        m = self.ssh_re.match(text)
        if m:
            self.proto = m.group('proto')
            self.user = m.group('user')
            self.host = m.group('host')
            self.port = m.group('port') and int(m.group('port')) or None
            self.path = os.path.normpath(m.group('path'))
            self.archive = m.group('archive')
            return True
        m = self.file_re.match(text)
        if m:
            self.proto = m.group('proto')
            self.path = os.path.normpath(m.group('path'))
            self.archive = m.group('archive')
            return True
        m = self.scp_re.match(text)
        if m:
            self.user = m.group('user')
            self.host = m.group('host')
            self.path = os.path.normpath(m.group('path'))
            self.archive = m.group('archive')
            self.proto = self.host and 'ssh' or 'file'
            return True
        return False

    def __str__(self):
        items = [
            'proto=%r' % self.proto,
            'user=%r' % self.user,
            'host=%r' % self.host,
            'port=%r' % self.port,
            'path=%r' % self.path,
            'archive=%r' % self.archive,
        ]
        return ', '.join(items)

    def to_key_filename(self):
        name = re.sub('[^\w]', '_', self.path).strip('_')
        if self.proto != 'file':
            name = self.host + '__' + name
        return os.path.join(get_keys_dir(), name)

    def __repr__(self):
        return "Location(%s)" % self

    def canonical_path(self):
        if self.proto == 'file':
            return self.path
        else:
            if self.path and self.path.startswith('~'):
                path = '/' + self.path
            elif self.path and not self.path.startswith('/'):
                path = '/~/' + self.path
            else:
                path = self.path
            return 'ssh://{}{}{}{}'.format('{}@'.format(self.user) if self.user else '',
                                           self.host,
                                           ':{}'.format(self.port) if self.port else '',
                                           path)


def location_validator(archive=None):
    def validator(text):
        try:
            loc = Location(text)
        except ValueError:
            raise argparse.ArgumentTypeError('Invalid location format: "%s"' % text) from None
        if archive is True and not loc.archive:
            raise argparse.ArgumentTypeError('"%s": No archive specified' % text)
        elif archive is False and loc.archive:
            raise argparse.ArgumentTypeError('"%s" No archive can be specified' % text)
        return loc
    return validator


def archivename_validator():
    def validator(text):
        if '/' in text or '::' in text or not text:
            raise argparse.ArgumentTypeError('Invalid repository name: "%s"' % text)
        return text
    return validator


def decode_dict(d, keys, encoding='utf-8', errors='surrogateescape'):
    for key in keys:
        if isinstance(d.get(key), bytes):
            d[key] = d[key].decode(encoding, errors)
    return d


def remove_surrogates(s, errors='replace'):
    """Replace surrogates generated by fsdecode with '?'
    """
    return s.encode('utf-8', errors).decode('utf-8')


_safe_re = re.compile(r'^((\.\.)?/+)+')


def make_path_safe(path):
    """Make path safe by making it relative and local
    """
    return _safe_re.sub('', path) or '.'


def daemonize():
    """Detach process from controlling terminal and run in background
    """
    pid = os.fork()
    if pid:
        os._exit(0)
    os.setsid()
    pid = os.fork()
    if pid:
        os._exit(0)
    os.chdir('/')
    os.close(0)
    os.close(1)
    os.close(2)
    fd = os.open('/dev/null', os.O_RDWR)
    os.dup2(fd, 0)
    os.dup2(fd, 1)
    os.dup2(fd, 2)


class StableDict(dict):
    """A dict subclass with stable items() ordering"""
    def items(self):
        return sorted(super().items())


def bigint_to_int(mtime):
    """Convert bytearray to int
    """
    if isinstance(mtime, bytes):
        return int.from_bytes(mtime, 'little', signed=True)
    return mtime


def int_to_bigint(value):
    """Convert integers larger than 64 bits to bytearray

    Smaller integers are left alone
    """
    if value.bit_length() > 63:
        return value.to_bytes((value.bit_length() + 9) // 8, 'little', signed=True)
    return value


def is_slow_msgpack():
    return msgpack.Packer is msgpack.fallback.Packer


FALSISH = ('No', 'NO', 'no', 'N', 'n', '0', )
TRUISH = ('Yes', 'YES', 'yes', 'Y', 'y', '1', )
DEFAULTISH = ('Default', 'DEFAULT', 'default', 'D', 'd', '', )


def yes(msg=None, false_msg=None, true_msg=None, default_msg=None,
        retry_msg=None, invalid_msg=None, env_msg=None,
        falsish=FALSISH, truish=TRUISH, defaultish=DEFAULTISH,
        default=False, retry=True, env_var_override=None, ofile=None, input=input):
    """
    Output <msg> (usually a question) and let user input an answer.
    Qualifies the answer according to falsish, truish and defaultish as True, False or <default>.
    If it didn't qualify and retry_msg is None (no retries wanted),
    return the default [which defaults to False]. Otherwise let user retry
    answering until answer is qualified.

    If env_var_override is given and this var is present in the environment, do not ask
    the user, but just use the env var contents as answer as if it was typed in.
    Otherwise read input from stdin and proceed as normal.
    If EOF is received instead an input or an invalid input without retry possibility,
    return default.

    :param msg: introducing message to output on ofile, no \n is added [None]
    :param retry_msg: retry message to output on ofile, no \n is added [None]
    :param false_msg: message to output before returning False [None]
    :param true_msg: message to output before returning True [None]
    :param default_msg: message to output before returning a <default> [None]
    :param invalid_msg: message to output after a invalid answer was given [None]
    :param env_msg: message to output when using input from env_var_override [None],
           needs to have 2 placeholders for answer and env var name, e.g.: "{} (from {})"
    :param falsish: sequence of answers qualifying as False
    :param truish: sequence of answers qualifying as True
    :param defaultish: sequence of answers qualifying as <default>
    :param default: default return value (defaultish answer was given or no-answer condition) [False]
    :param retry: if True and input is incorrect, retry. Otherwise return default. [True]
    :param env_var_override: environment variable name [None]
    :param ofile: output stream [sys.stderr]
    :param input: input function [input from builtins]
    :return: boolean answer value, True or False
    """
    # note: we do not assign sys.stderr as default above, so it is
    # really evaluated NOW,  not at function definition time.
    if ofile is None:
        ofile = sys.stderr
    if default not in (True, False):
        raise ValueError("invalid default value, must be True or False")
    if msg:
        print(msg, file=ofile, end='', flush=True)
    while True:
        answer = None
        if env_var_override:
            answer = os.environ.get(env_var_override)
            if answer is not None and env_msg:
                print(env_msg.format(answer, env_var_override), file=ofile)
        if answer is None:
            try:
                answer = input()
            except EOFError:
                # avoid defaultish[0], defaultish could be empty
                answer = truish[0] if default else falsish[0]
        if answer in defaultish:
            if default_msg:
                print(default_msg, file=ofile)
            return default
        if answer in truish:
            if true_msg:
                print(true_msg, file=ofile)
            return True
        if answer in falsish:
            if false_msg:
                print(false_msg, file=ofile)
            return False
        # if we get here, the answer was invalid
        if invalid_msg:
            print(invalid_msg, file=ofile)
        if not retry:
            return default
        if retry_msg:
            print(retry_msg, file=ofile, end='', flush=True)
        # in case we used an environment variable and it gave an invalid answer, do not use it again:
        env_var_override = None


class ProgressIndicatorPercent:
    def __init__(self, total, step=5, start=0, same_line=False, msg="%3.0f%%", file=None):
        """
        Percentage-based progress indicator

        :param total: total amount of items
        :param step: step size in percent
        :param start: at which percent value to start
        :param same_line: if True, emit output always on same line
        :param msg: output message, must contain one %f placeholder for the percentage
        :param file: output file, default: sys.stderr
        """
        self.counter = 0  # 0 .. (total-1)
        self.total = total
        self.trigger_at = start  # output next percentage value when reaching (at least) this
        self.step = step
        if file is None:
            file = sys.stderr
        self.file = file
        self.msg = msg
        self.same_line = same_line

    def progress(self, current=None):
        if current is not None:
            self.counter = current
        pct = self.counter * 100 / self.total
        self.counter += 1
        if pct >= self.trigger_at:
            self.trigger_at += self.step
            return pct

    def show(self, current=None):
        pct = self.progress(current)
        if pct is not None:
            return self.output(pct)

    def output(self, percent):
        print(self.msg % percent, file=self.file, end='\r' if self.same_line else '\n', flush=True)

    def finish(self):
        if self.same_line:
            print(" " * len(self.msg % 100.0), file=self.file, end='\r')


class ProgressIndicatorEndless:
    def __init__(self, step=10, file=None):
        """
        Progress indicator (long row of dots)

        :param step: every Nth call, call the func
        :param file: output file, default: sys.stderr
        """
        self.counter = 0  # call counter
        self.triggered = 0  # increases 1 per trigger event
        self.step = step  # trigger every <step> calls
        if file is None:
            file = sys.stderr
        self.file = file

    def progress(self):
        self.counter += 1
        trigger = self.counter % self.step == 0
        if trigger:
            self.triggered += 1
        return trigger

    def show(self):
        trigger = self.progress()
        if trigger:
            return self.output(self.triggered)

    def output(self, triggered):
        print('.', end='', file=self.file, flush=True)

    def finish(self):
        print(file=self.file)


def sysinfo():
    info = []
    info.append('Platform: %s' % (' '.join(platform.uname()), ))
    if sys.platform.startswith('linux'):
        info.append('Linux: %s %s %s' % platform.linux_distribution())
    info.append('Borg: %s  Python: %s %s' % (borg_version, platform.python_implementation(), platform.python_version()))
    info.append('PID: %d  CWD: %s' % (os.getpid(), os.getcwd()))
    info.append('sys.argv: %r' % sys.argv)
    info.append('SSH_ORIGINAL_COMMAND: %r' % os.environ.get('SSH_ORIGINAL_COMMAND'))
    info.append('')
    return '\n'.join(info)


def log_multi(*msgs, level=logging.INFO):
    """
    log multiple lines of text, each line by a separate logging call for cosmetic reasons

    each positional argument may be a single or multiple lines (separated by \n) of text.
    """
    lines = []
    for msg in msgs:
        lines.extend(msg.splitlines())
    for line in lines:
        logger.log(level, line)

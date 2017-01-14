import argparse
import contextlib
import grp
import hashlib
import logging
import io
import os
import os.path
import platform
import pwd
import re
import signal
import socket
import stat
import sys
import textwrap
import threading
import time
import unicodedata
import uuid
from binascii import hexlify
from collections import namedtuple, deque, abc
from datetime import datetime, timezone, timedelta
from fnmatch import translate
from functools import wraps, partial, lru_cache
from itertools import islice
from operator import attrgetter
from string import Formatter
from shutil import get_terminal_size

import msgpack
import msgpack.fallback

from .logger import create_logger
logger = create_logger()

from . import __version__ as borg_version
from . import __version_tuple__ as borg_version_tuple
from . import chunker
from . import crypto
from . import hashindex
from . import shellpattern
from .constants import *  # NOQA

# meta dict, data bytes
_Chunk = namedtuple('_Chunk', 'meta data')


def Chunk(data, **meta):
    return _Chunk(meta, data)


class Error(Exception):
    """Error base class"""

    # if we raise such an Error and it is only catched by the uppermost
    # exception handler (that exits short after with the given exit_code),
    # it is always a (fatal and abrupt) EXIT_ERROR, never just a warning.
    exit_code = EXIT_ERROR
    # show a traceback?
    traceback = False

    def __init__(self, *args):
        super().__init__(*args)
        self.args = args

    def get_message(self):
        return type(self).__doc__.format(*self.args)

    __str__ = get_message


class ErrorWithTraceback(Error):
    """like Error, but show a traceback also"""
    traceback = True


class IntegrityError(ErrorWithTraceback):
    """Data integrity error: {}"""


class ExtensionModuleError(Error):
    """The Borg binary extension modules do not seem to be properly installed"""


class NoManifestError(Error):
    """Repository has no manifest."""


class PlaceholderError(Error):
    """Formatting Error: "{}".format({}): {}({})"""


def check_extension_modules():
    from . import platform, compress, item
    if hashindex.API_VERSION != '1.1_01':
        raise ExtensionModuleError
    if chunker.API_VERSION != '1.1_01':
        raise ExtensionModuleError
    if compress.API_VERSION != '1.1_01':
        raise ExtensionModuleError
    if crypto.API_VERSION != '1.1_01':
        raise ExtensionModuleError
    if platform.API_VERSION != platform.OS_API_VERSION != '1.1_01':
        raise ExtensionModuleError
    if item.API_VERSION != '1.1_01':
        raise ExtensionModuleError


ArchiveInfo = namedtuple('ArchiveInfo', 'name id ts')


class Archives(abc.MutableMapping):
    """
    Nice wrapper around the archives dict, making sure only valid types/values get in
    and we can deal with str keys (and it internally encodes to byte keys) and eiter
    str timestamps or datetime timestamps.
    """
    def __init__(self):
        # key: encoded archive name, value: dict(b'id': bytes_id, b'time': bytes_iso_ts)
        self._archives = {}

    def __len__(self):
        return len(self._archives)

    def __iter__(self):
        return iter(safe_decode(name) for name in self._archives)

    def __getitem__(self, name):
        assert isinstance(name, str)
        _name = safe_encode(name)
        values = self._archives.get(_name)
        if values is None:
            raise KeyError
        ts = parse_timestamp(values[b'time'].decode('utf-8'))
        return ArchiveInfo(name=name, id=values[b'id'], ts=ts)

    def __setitem__(self, name, info):
        assert isinstance(name, str)
        name = safe_encode(name)
        assert isinstance(info, tuple)
        id, ts = info
        assert isinstance(id, bytes)
        if isinstance(ts, datetime):
            ts = ts.replace(tzinfo=None).isoformat()
        assert isinstance(ts, str)
        ts = ts.encode()
        self._archives[name] = {b'id': id, b'time': ts}

    def __delitem__(self, name):
        assert isinstance(name, str)
        name = safe_encode(name)
        del self._archives[name]

    def list(self, sort_by=(), reverse=False, prefix='', first=None, last=None):
        """
        Inexpensive Archive.list_archives replacement if we just need .name, .id, .ts
        Returns list of borg.helpers.ArchiveInfo instances.
        sort_by can be a list of sort keys, they are applied in reverse order.
        """
        if isinstance(sort_by, (str, bytes)):
            raise TypeError('sort_by must be a sequence of str')
        archives = [x for x in self.values() if x.name.startswith(prefix)]
        for sortkey in reversed(sort_by):
            archives.sort(key=attrgetter(sortkey))
        if reverse or last:
            archives.reverse()
        n = first or last or len(archives)
        return archives[:n]

    def list_considering(self, args):
        """
        get a list of archives, considering --first/last/prefix/sort cmdline args
        """
        if args.location.archive:
            raise Error('The options --first, --last and --prefix can only be used on repository targets.')
        return self.list(sort_by=args.sort_by.split(','), prefix=args.prefix, first=args.first, last=args.last)

    def set_raw_dict(self, d):
        """set the dict we get from the msgpack unpacker"""
        for k, v in d.items():
            assert isinstance(k, bytes)
            assert isinstance(v, dict) and b'id' in v and b'time' in v
            self._archives[k] = v

    def get_raw_dict(self):
        """get the dict we can give to the msgpack packer"""
        return self._archives


class Manifest:

    MANIFEST_ID = b'\0' * 32

    def __init__(self, key, repository, item_keys=None):
        self.archives = Archives()
        self.config = {}
        self.key = key
        self.repository = repository
        self.item_keys = frozenset(item_keys) if item_keys is not None else ITEM_KEYS
        self.tam_verified = False

    @property
    def id_str(self):
        return bin_to_hex(self.id)

    @classmethod
    def load(cls, repository, key=None, force_tam_not_required=False):
        from .item import ManifestItem
        from .key import key_factory, tam_required_file, tam_required
        from .repository import Repository
        try:
            cdata = repository.get(cls.MANIFEST_ID)
        except Repository.ObjectNotFound:
            raise NoManifestError
        if not key:
            key = key_factory(repository, cdata)
        manifest = cls(key, repository)
        data = key.decrypt(None, cdata).data
        manifest_dict, manifest.tam_verified = key.unpack_and_verify_manifest(data, force_tam_not_required=force_tam_not_required)
        m = ManifestItem(internal_dict=manifest_dict)
        manifest.id = key.id_hash(data)
        if m.get('version') != 1:
            raise ValueError('Invalid manifest version')
        manifest.archives.set_raw_dict(m.archives)
        manifest.timestamp = m.get('timestamp')
        manifest.config = m.config
        # valid item keys are whatever is known in the repo or every key we know
        manifest.item_keys = ITEM_KEYS | frozenset(key.decode() for key in m.get('item_keys', []))

        if manifest.tam_verified:
            manifest_required = manifest.config.get(b'tam_required', False)
            security_required = tam_required(repository)
            if manifest_required and not security_required:
                logger.debug('Manifest is TAM verified and says TAM is required, updating security database...')
                file = tam_required_file(repository)
                open(file, 'w').close()
            if not manifest_required and security_required:
                logger.debug('Manifest is TAM verified and says TAM is *not* required, updating security database...')
                os.unlink(tam_required_file(repository))
        return manifest, key

    def write(self):
        from .item import ManifestItem
        if self.key.tam_required:
            self.config[b'tam_required'] = True
        self.timestamp = datetime.utcnow().isoformat()
        manifest = ManifestItem(
            version=1,
            archives=StableDict(self.archives.get_raw_dict()),
            timestamp=self.timestamp,
            config=StableDict(self.config),
            item_keys=tuple(sorted(self.item_keys)),
        )
        self.tam_verified = True
        data = self.key.pack_and_authenticate_metadata(manifest.as_dict())
        self.id = self.key.id_hash(data)
        self.repository.put(self.MANIFEST_ID, self.key.encrypt(Chunk(data, compression={'name': 'none'})))


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


def get_home_dir():
    """Get user's home directory while preferring a possibly set HOME
    environment variable
    """
    # os.path.expanduser() behaves differently for '~' and '~someuser' as
    # parameters: when called with an explicit username, the possibly set
    # environment variable HOME is no longer respected. So we have to check if
    # it is set and only expand the user's home directory if HOME is unset.
    if os.environ.get('HOME', ''):
        return os.environ.get('HOME')
    else:
        return os.path.expanduser('~%s' % os.environ.get('USER', ''))


def get_keys_dir():
    """Determine where to repository keys and cache"""

    xdg_config = os.environ.get('XDG_CONFIG_HOME', os.path.join(get_home_dir(), '.config'))
    keys_dir = os.environ.get('BORG_KEYS_DIR', os.path.join(xdg_config, 'borg', 'keys'))
    if not os.path.exists(keys_dir):
        os.makedirs(keys_dir)
        os.chmod(keys_dir, stat.S_IRWXU)
    return keys_dir


def get_security_dir(repository_id=None):
    """Determine where to store local security information."""
    xdg_config = os.environ.get('XDG_CONFIG_HOME', os.path.join(get_home_dir(), '.config'))
    security_dir = os.environ.get('BORG_SECURITY_DIR', os.path.join(xdg_config, 'borg', 'security'))
    if repository_id:
        security_dir = os.path.join(security_dir, repository_id)
    if not os.path.exists(security_dir):
        os.makedirs(security_dir)
        os.chmod(security_dir, stat.S_IRWXU)
    return security_dir


def get_cache_dir():
    """Determine where to repository keys and cache"""
    xdg_cache = os.environ.get('XDG_CACHE_HOME', os.path.join(get_home_dir(), '.cache'))
    cache_dir = os.environ.get('BORG_CACHE_DIR', os.path.join(xdg_cache, 'borg'))
    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir)
        os.chmod(cache_dir, stat.S_IRWXU)
        with open(os.path.join(cache_dir, CACHE_TAG_NAME), 'wb') as fd:
            fd.write(CACHE_TAG_CONTENTS)
            fd.write(textwrap.dedent("""
                # This file is a cache directory tag created by Borg.
                # For information about cache directory tags, see:
                #       http://www.brynosaurus.com/cachedir/
                """).encode('ascii'))
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
    return [parse_pattern(pattern) for pattern in clean_lines(fh)]


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

    def empty(self):
        return not len(self._items)

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
    if s.strip().lower() == "default":
        return CHUNKER_PARAMS
    chunk_min, chunk_max, chunk_mask, window_size = s.split(',')
    if int(chunk_max) > 23:
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
    if name == 'auto':
        if 2 <= count <= 3:
            compression = ','.join(values[1:])
        else:
            raise ValueError
        return dict(name=name, spec=CompressionSpec(compression))
    raise ValueError


def dir_is_cachedir(path):
    """Determines whether the specified path is a cache directory (and
    therefore should potentially be excluded from the backup) according to
    the CACHEDIR.TAG protocol
    (http://www.brynosaurus.com/cachedir/spec.html).
    """

    tag_path = os.path.join(path, CACHE_TAG_NAME)
    try:
        if os.path.exists(tag_path):
            with open(tag_path, 'rb') as tag_file:
                tag_data = tag_file.read(len(CACHE_TAG_CONTENTS))
                if tag_data == CACHE_TAG_CONTENTS:
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
        tag_paths.append(os.path.join(path, CACHE_TAG_NAME))
    if exclude_if_present is not None:
        for tag in exclude_if_present:
            tag_path = os.path.join(path, tag)
            if os.path.isfile(tag_path):
                tag_paths.append(tag_path)
    return tag_paths


def partial_format(format, mapping):
    """
    Apply format.format_map(mapping) while preserving unknown keys

    Does not support attribute access, indexing and ![rsa] conversions
    """
    for key, value in mapping.items():
        key = re.escape(key)
        format = re.sub(r'(?<!\{)((\{%s\})|(\{%s:[^\}]*\}))' % (key, key),
                        lambda match: match.group(1).format_map(mapping),
                        format)
    return format


class DatetimeWrapper:
    def __init__(self, dt):
        self.dt = dt

    def __format__(self, format_spec):
        if format_spec == '':
            format_spec = '%Y-%m-%dT%H:%M:%S'
        return self.dt.__format__(format_spec)


def format_line(format, data):
    try:
        return format.format(**data)
    except Exception as e:
        raise PlaceholderError(format, data, e.__class__.__name__, str(e))


def replace_placeholders(text):
    """Replace placeholders in text with their values."""
    current_time = datetime.now()
    data = {
        'pid': os.getpid(),
        'fqdn': socket.getfqdn(),
        'hostname': socket.gethostname(),
        'now': DatetimeWrapper(current_time.now()),
        'utcnow': DatetimeWrapper(current_time.utcnow()),
        'user': uid2user(os.getuid(), os.getuid()),
        'uuid4': str(uuid.uuid4()),
        'borgversion': borg_version,
        'borgmajor': '%d' % borg_version_tuple[:1],
        'borgminor': '%d.%d' % borg_version_tuple[:2],
        'borgpatch': '%d.%d.%d' % borg_version_tuple[:3],
    }
    return format_line(text, data)


PrefixSpec = replace_placeholders


HUMAN_SORT_KEYS = ['timestamp'] + list(ArchiveInfo._fields)
HUMAN_SORT_KEYS.remove('ts')


def SortBySpec(text):
    for token in text.split(','):
        if token not in HUMAN_SORT_KEYS:
            raise ValueError('Invalid sort key: %s' % token)
    return text.replace('timestamp', 'ts')


def safe_timestamp(item_timestamp_ns):
    try:
        return datetime.fromtimestamp(item_timestamp_ns / 1e9)
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
    ts = td.total_seconds()
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


def format_file_size(v, precision=2, sign=False):
    """Format file size into a human friendly format
    """
    return sizeof_fmt_decimal(v, suffix='B', sep=' ', precision=precision, sign=sign)


def parse_file_size(s):
    """Return int from file size (1234, 55G, 1.7T)."""
    if not s:
        return int(s)  # will raise
    suffix = s[-1]
    power = 1000
    try:
        factor = {
            'K': power,
            'M': power**2,
            'G': power**3,
            'T': power**4,
            'P': power**5,
        }[suffix]
        s = s[:-1]
    except KeyError:
        factor = 1
    return int(float(s) * factor)


def sizeof_fmt(num, suffix='B', units=None, power=None, sep='', precision=2, sign=False):
    prefix = '+' if sign and num > 0 else ''

    for unit in units[:-1]:
        if abs(round(num, precision)) < power:
            if isinstance(num, int):
                return "{}{}{}{}{}".format(prefix, num, sep, unit, suffix)
            else:
                return "{}{:3.{}f}{}{}{}".format(prefix, num, precision, sep, unit, suffix)
        num /= float(power)
    return "{}{:.{}f}{}{}{}".format(prefix, num, precision, sep, units[-1], suffix)


def sizeof_fmt_iec(num, suffix='B', sep='', precision=2, sign=False):
    return sizeof_fmt(num, suffix=suffix, sep=sep, precision=precision, sign=sign,
                      units=['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi', 'Yi'], power=1024)


def sizeof_fmt_decimal(num, suffix='B', sep='', precision=2, sign=False):
    return sizeof_fmt(num, suffix=suffix, sep=sep, precision=precision, sign=sign,
                      units=['', 'k', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y'], power=1000)


def format_archive(archive):
    return '%-36s %s [%s]' % (
        archive.name,
        format_time(to_localtime(archive.ts)),
        bin_to_hex(archive.id),
    )


class Buffer:
    """
    provide a thread-local buffer
    """

    class MemoryLimitExceeded(Error, OSError):
        """Requested buffer size {} is above the limit of {}."""

    def __init__(self, allocator, size=4096, limit=None):
        """
        Initialize the buffer: use allocator(size) call to allocate a buffer.
        Optionally, set the upper <limit> for the buffer size.
        """
        assert callable(allocator), 'must give alloc(size) function as first param'
        assert limit is None or size <= limit, 'initial size must be <= limit'
        self._thread_local = threading.local()
        self.allocator = allocator
        self.limit = limit
        self.resize(size, init=True)

    def __len__(self):
        return len(self._thread_local.buffer)

    def resize(self, size, init=False):
        """
        resize the buffer - to avoid frequent reallocation, we usually always grow (if needed).
        giving init=True it is possible to first-time initialize or shrink the buffer.
        if a buffer size beyond the limit is requested, raise Buffer.MemoryLimitExceeded (OSError).
        """
        size = int(size)
        if self.limit is not None and size > self.limit:
            raise Buffer.MemoryLimitExceeded(size, self.limit)
        if init or len(self) < size:
            self._thread_local.buffer = self.allocator(size)

    def get(self, size=None, init=False):
        """
        return a buffer of at least the requested size (None: any current size).
        init=True can be given to trigger shrinking of the buffer to the given size.
        """
        if size is not None:
            self.resize(size, init)
        return self._thread_local.buffer


@lru_cache(maxsize=None)
def uid2user(uid, default=None):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return default


@lru_cache(maxsize=None)
def user2uid(user, default=None):
    try:
        return user and pwd.getpwnam(user).pw_uid
    except KeyError:
        return default


@lru_cache(maxsize=None)
def gid2group(gid, default=None):
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return default


@lru_cache(maxsize=None)
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
    if s is None:
        return None
    return s.decode(coding, errors)


def safe_encode(s, coding='utf-8', errors='surrogateescape'):
    """encode str to bytes, with round-tripping "invalid" bytes"""
    if s is None:
        return None
    return s.encode(coding, errors)


def bin_to_hex(binary):
    return hexlify(binary).decode('ascii')


class Location:
    """Object representing a repository / archive location
    """
    proto = user = host = port = path = archive = None

    # user must not contain "@", ":" or "/".
    # Quoting adduser error message:
    # "To avoid problems, the username should consist only of letters, digits,
    # underscores, periods, at signs and dashes, and not start with a dash
    # (as defined by IEEE Std 1003.1-2001)."
    # We use "@" as separator between username and hostname, so we must
    # disallow it within the pure username part.
    optional_user_re = r"""
        (?:(?P<user>[^@:/]+)@)?
    """

    # path must not contain :: (it ends at :: or string end), but may contain single colons.
    # to avoid ambiguities with other regexes, it must also not start with ":".
    path_re = r"""
        (?!:)                                               # not starting with ":"
        (?P<path>([^:]|(:(?!:)))+)                          # any chars, but no "::"
        """
    # optional ::archive_name at the end, archive name must not contain "/".
    # borg mount's FUSE filesystem creates one level of directories from
    # the archive names and of course "/" is not valid in a directory name.
    optional_archive_re = r"""
        (?:
            ::                                              # "::" as separator
            (?P<archive>[^/]+)                              # archive name must not contain "/"
        )?$"""                                              # must match until the end

    # regexes for misc. kinds of supported location specifiers:
    ssh_re = re.compile(r"""
        (?P<proto>ssh)://                                   # ssh://
        """ + optional_user_re + r"""                       # user@  (optional)
        (?P<host>[^:/]+)(?::(?P<port>\d+))?                 # host or host:port
        """ + path_re + optional_archive_re, re.VERBOSE)    # path or path::archive

    file_re = re.compile(r"""
        (?P<proto>file)://                                  # file://
        """ + path_re + optional_archive_re, re.VERBOSE)    # path or path::archive

    # note: scp_re is also use for local pathes
    scp_re = re.compile(r"""
        (
            """ + optional_user_re + r"""                   # user@  (optional)
            (?P<host>[^:/]+):                               # host: (don't match / in host to disambiguate from file:)
        )?                                                  # user@host: part is optional
        """ + path_re + optional_archive_re, re.VERBOSE)    # path with optional archive

    # get the repo from BORG_REPO env and the optional archive from param.
    # if the syntax requires giving REPOSITORY (see "borg mount"),
    # use "::" to let it use the env var.
    # if REPOSITORY argument is optional, it'll automatically use the env.
    env_re = re.compile(r"""                                # the repo part is fetched from BORG_REPO
        (?:::$)                                             # just "::" is ok (when a pos. arg is required, no archive)
        |                                                   # or
        """ + optional_archive_re, re.VERBOSE)              # archive name (optional, may be empty)

    def __init__(self, text=''):
        self.orig = text
        if not self.parse(self.orig):
            raise ValueError

    def parse(self, text):
        text = replace_placeholders(text)
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
        def normpath_special(p):
            # avoid that normpath strips away our relative path hack and even makes p absolute
            relative = p.startswith('/./')
            p = os.path.normpath(p)
            return ('/.' + p) if relative else p

        m = self.ssh_re.match(text)
        if m:
            self.proto = m.group('proto')
            self.user = m.group('user')
            self.host = m.group('host')
            self.port = m.group('port') and int(m.group('port')) or None
            self.path = normpath_special(m.group('path'))
            self.archive = m.group('archive')
            return True
        m = self.file_re.match(text)
        if m:
            self.proto = m.group('proto')
            self.path = normpath_special(m.group('path'))
            self.archive = m.group('archive')
            return True
        m = self.scp_re.match(text)
        if m:
            self.user = m.group('user')
            self.host = m.group('host')
            self.path = normpath_special(m.group('path'))
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
                path = '/' + self.path  # /~/x = path x relative to home dir
            elif self.path and not self.path.startswith('/'):
                path = '/./' + self.path  # /./x = path x relative to cwd
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
    fd = os.open(os.devnull, os.O_RDWR)
    os.dup2(fd, 0)
    os.dup2(fd, 1)
    os.dup2(fd, 2)


class StableDict(dict):
    """A dict subclass with stable items() ordering"""
    def items(self):
        return sorted(super().items())


def is_slow_msgpack():
    return msgpack.Packer is msgpack.fallback.Packer


FALSISH = ('No', 'NO', 'no', 'N', 'n', '0', )
TRUISH = ('Yes', 'YES', 'yes', 'Y', 'y', '1', )
DEFAULTISH = ('Default', 'DEFAULT', 'default', 'D', 'd', '', )


def yes(msg=None, false_msg=None, true_msg=None, default_msg=None,
        retry_msg=None, invalid_msg=None, env_msg='{} (from {})',
        falsish=FALSISH, truish=TRUISH, defaultish=DEFAULTISH,
        default=False, retry=True, env_var_override=None, ofile=None, input=input, prompt=True):
    """Output <msg> (usually a question) and let user input an answer.
    Qualifies the answer according to falsish, truish and defaultish as True, False or <default>.
    If it didn't qualify and retry is False (no retries wanted), return the default [which
    defaults to False]. If retry is True let user retry answering until answer is qualified.

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
    :param env_msg: message to output when using input from env_var_override ['{} (from {})'],
           needs to have 2 placeholders for answer and env var name
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
            if not prompt:
                return default
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


def ellipsis_truncate(msg, space):
    """
    shorten a long string by adding ellipsis between it and return it, example:
    this_is_a_very_long_string -------> this_is..._string
    """
    from .platform import swidth
    ellipsis_width = swidth('...')
    msg_width = swidth(msg)
    if space < 8:
        # if there is very little space, just show ...
        return '...' + ' ' * (space - ellipsis_width)
    if space < ellipsis_width + msg_width:
        return '%s...%s' % (swidth_slice(msg, space // 2 - ellipsis_width),
                            swidth_slice(msg, -space // 2))
    return msg + ' ' * (space - msg_width)


class ProgressIndicatorBase:
    LOGGER = 'borg.output.progress'

    def __init__(self):
        self.handler = None
        self.logger = logging.getLogger(self.LOGGER)

        # If there are no handlers, set one up explicitly because the
        # terminator and propagation needs to be set.  If there are,
        # they must have been set up by BORG_LOGGING_CONF: skip setup.
        if not self.logger.handlers:
            self.handler = logging.StreamHandler(stream=sys.stderr)
            self.handler.setLevel(logging.INFO)
            self.handler.terminator = '\r'

            self.logger.addHandler(self.handler)
            if self.logger.level == logging.NOTSET:
                self.logger.setLevel(logging.WARN)
            self.logger.propagate = False

    def __del__(self):
        if self.handler is not None:
            self.logger.removeHandler(self.handler)
            self.handler.close()


def justify_to_terminal_size(message):
    terminal_space = get_terminal_size(fallback=(-1, -1))[0]
    # justify only if we are outputting to a terminal
    if terminal_space != -1:
        return message.ljust(terminal_space)
    return message


class ProgressIndicatorMessage(ProgressIndicatorBase):
    def output(self, msg):
        self.logger.info(justify_to_terminal_size(msg))

    def finish(self):
        self.output('')


class ProgressIndicatorPercent(ProgressIndicatorBase):
    def __init__(self, total=0, step=5, start=0, msg="%3.0f%%"):
        """
        Percentage-based progress indicator

        :param total: total amount of items
        :param step: step size in percent
        :param start: at which percent value to start
        :param msg: output message, must contain one %f placeholder for the percentage
        """
        self.counter = 0  # 0 .. (total-1)
        self.total = total
        self.trigger_at = start  # output next percentage value when reaching (at least) this
        self.step = step
        self.msg = msg

        super().__init__()

    def progress(self, current=None, increase=1):
        if current is not None:
            self.counter = current
        pct = self.counter * 100 / self.total
        self.counter += increase
        if pct >= self.trigger_at:
            self.trigger_at += self.step
            return pct

    def show(self, current=None, increase=1, info=None):
        """
        Show and output the progress message

        :param current: set the current percentage [None]
        :param increase: increase the current percentage [None]
        :param info: array of strings to be formatted with msg [None]
        """
        pct = self.progress(current, increase)
        if pct is not None:
            # truncate the last argument, if no space is available
            if info is not None:
                # no need to truncate if we're not outputing to a terminal
                terminal_space = get_terminal_size(fallback=(-1, -1))[0]
                if terminal_space != -1:
                    space = terminal_space - len(self.msg % tuple([pct] + info[:-1] + ['']))
                    info[-1] = ellipsis_truncate(info[-1], space)
                return self.output(self.msg % tuple([pct] + info), justify=False)

            return self.output(self.msg % pct)

    def output(self, message, justify=True):
        if justify:
            message = justify_to_terminal_size(message)
        self.logger.info(message)

    def finish(self):
        self.output('')


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


def log_multi(*msgs, level=logging.INFO, logger=logger):
    """
    log multiple lines of text, each line by a separate logging call for cosmetic reasons

    each positional argument may be a single or multiple lines (separated by newlines) of text.
    """
    lines = []
    for msg in msgs:
        lines.extend(msg.splitlines())
    for line in lines:
        logger.log(level, line)


class BaseFormatter:
    FIXED_KEYS = {
        # Formatting aids
        'LF': '\n',
        'SPACE': ' ',
        'TAB': '\t',
        'CR': '\r',
        'NUL': '\0',
        'NEWLINE': os.linesep,
        'NL': os.linesep,
    }

    def get_item_data(self, item):
        raise NotImplementedError

    def format_item(self, item):
        return self.format.format_map(self.get_item_data(item))

    @staticmethod
    def keys_help():
        return " - NEWLINE: OS dependent line separator\n" \
               " - NL: alias of NEWLINE\n" \
               " - NUL: NUL character for creating print0 / xargs -0 like output, see barchive/bpath\n" \
               " - SPACE\n" \
               " - TAB\n" \
               " - CR\n" \
               " - LF"


class ArchiveFormatter(BaseFormatter):

    def __init__(self, format):
        self.format = partial_format(format, self.FIXED_KEYS)

    def get_item_data(self, archive):
        return {
            'barchive': archive.name,
            'archive': remove_surrogates(archive.name),
            'id': bin_to_hex(archive.id),
            'time': format_time(to_localtime(archive.ts)),
        }

    @staticmethod
    def keys_help():
        return " - archive: archive name interpreted as text (might be missing non-text characters, see barchive)\n" \
               " - barchive: verbatim archive name, can contain any character except NUL\n" \
               " - time: time of creation of the archive\n" \
               " - id: internal ID of the archive"


class ItemFormatter(BaseFormatter):
    KEY_DESCRIPTIONS = {
        'bpath': 'verbatim POSIX path, can contain any character except NUL',
        'path': 'path interpreted as text (might be missing non-text characters, see bpath)',
        'source': 'link target for links (identical to linktarget)',
        'extra': 'prepends {source} with " -> " for soft links and " link to " for hard links',
        'csize': 'compressed size',
        'num_chunks': 'number of chunks in this file',
        'unique_chunks': 'number of unique chunks in this file',
        'health': 'either "healthy" (file ok) or "broken" (if file has all-zero replacement chunks)',
    }
    KEY_GROUPS = (
        ('type', 'mode', 'uid', 'gid', 'user', 'group', 'path', 'bpath', 'source', 'linktarget', 'flags'),
        ('size', 'csize', 'num_chunks', 'unique_chunks'),
        ('mtime', 'ctime', 'atime', 'isomtime', 'isoctime', 'isoatime'),
        tuple(sorted(hashlib.algorithms_guaranteed)),
        ('archiveid', 'archivename', 'extra'),
        ('health', )
    )

    @classmethod
    def available_keys(cls):
        class FakeArchive:
            fpr = name = ""

        from .item import Item
        fake_item = Item(mode=0, path='', user='', group='', mtime=0, uid=0, gid=0)
        formatter = cls(FakeArchive, "")
        keys = []
        keys.extend(formatter.call_keys.keys())
        keys.extend(formatter.get_item_data(fake_item).keys())
        return keys

    @classmethod
    def keys_help(cls):
        help = []
        keys = cls.available_keys()
        for key in cls.FIXED_KEYS:
            keys.remove(key)

        for group in cls.KEY_GROUPS:
            for key in group:
                keys.remove(key)
                text = " - " + key
                if key in cls.KEY_DESCRIPTIONS:
                    text += ": " + cls.KEY_DESCRIPTIONS[key]
                help.append(text)
            help.append("")
        assert not keys, str(keys)
        return "\n".join(help)

    def __init__(self, archive, format):
        self.archive = archive
        static_keys = {
            'archivename': archive.name,
            'archiveid': archive.fpr,
        }
        static_keys.update(self.FIXED_KEYS)
        self.format = partial_format(format, static_keys)
        self.format_keys = {f[1] for f in Formatter().parse(format)}
        self.call_keys = {
            'size': self.calculate_size,
            'csize': self.calculate_csize,
            'num_chunks': self.calculate_num_chunks,
            'unique_chunks': self.calculate_unique_chunks,
            'isomtime': partial(self.format_time, 'mtime'),
            'isoctime': partial(self.format_time, 'ctime'),
            'isoatime': partial(self.format_time, 'atime'),
            'mtime': partial(self.time, 'mtime'),
            'ctime': partial(self.time, 'ctime'),
            'atime': partial(self.time, 'atime'),
        }
        for hash_function in hashlib.algorithms_guaranteed:
            self.add_key(hash_function, partial(self.hash_item, hash_function))
        self.used_call_keys = set(self.call_keys) & self.format_keys
        self.item_data = static_keys

    def add_key(self, key, callable_with_item):
        self.call_keys[key] = callable_with_item
        self.used_call_keys = set(self.call_keys) & self.format_keys

    def get_item_data(self, item):
        mode = stat.filemode(item.mode)
        item_type = mode[0]
        item_data = self.item_data

        source = item.get('source', '')
        extra = ''
        if source:
            source = remove_surrogates(source)
            if item_type == 'l':
                extra = ' -> %s' % source
            else:
                mode = 'h' + mode[1:]
                extra = ' link to %s' % source
        item_data['type'] = item_type
        item_data['mode'] = mode
        item_data['user'] = item.user or item.uid
        item_data['group'] = item.group or item.gid
        item_data['uid'] = item.uid
        item_data['gid'] = item.gid
        item_data['path'] = remove_surrogates(item.path)
        item_data['bpath'] = item.path
        item_data['source'] = source
        item_data['linktarget'] = source
        item_data['extra'] = extra
        item_data['flags'] = item.get('bsdflags')
        item_data['health'] = 'broken' if 'chunks_healthy' in item else 'healthy'
        for key in self.used_call_keys:
            item_data[key] = self.call_keys[key](item)
        return item_data

    def calculate_num_chunks(self, item):
        return len(item.get('chunks', []))

    def calculate_unique_chunks(self, item):
        chunk_index = self.archive.cache.chunks
        return sum(1 for c in item.get('chunks', []) if chunk_index[c.id].refcount == 1)

    def calculate_size(self, item):
        return sum(c.size for c in item.get('chunks', []))

    def calculate_csize(self, item):
        return sum(c.csize for c in item.get('chunks', []))

    def hash_item(self, hash_function, item):
        if 'chunks' not in item:
            return ""
        hash = hashlib.new(hash_function)
        for _, data in self.archive.pipeline.fetch_many([c.id for c in item.chunks]):
            hash.update(data)
        return hash.hexdigest()

    def format_time(self, key, item):
        return format_time(safe_timestamp(item.get(key) or item.mtime))

    def time(self, key, item):
        return safe_timestamp(item.get(key) or item.mtime)


class ChunkIteratorFileWrapper:
    """File-like wrapper for chunk iterators"""

    def __init__(self, chunk_iterator):
        self.chunk_iterator = chunk_iterator
        self.chunk_offset = 0
        self.chunk = b''
        self.exhausted = False

    def _refill(self):
        remaining = len(self.chunk) - self.chunk_offset
        if not remaining:
            try:
                chunk = next(self.chunk_iterator)
                self.chunk = memoryview(chunk.data)
            except StopIteration:
                self.exhausted = True
                return 0  # EOF
            self.chunk_offset = 0
            remaining = len(self.chunk)
        return remaining

    def _read(self, nbytes):
        if not nbytes:
            return b''
        remaining = self._refill()
        will_read = min(remaining, nbytes)
        self.chunk_offset += will_read
        return self.chunk[self.chunk_offset - will_read:self.chunk_offset]

    def read(self, nbytes):
        parts = []
        while nbytes and not self.exhausted:
            read_data = self._read(nbytes)
            nbytes -= len(read_data)
            parts.append(read_data)
        return b''.join(parts)


def open_item(archive, item):
    """Return file-like object for archived item (with chunks)."""
    chunk_iterator = archive.pipeline.fetch_many([c.id for c in item.chunks])
    return ChunkIteratorFileWrapper(chunk_iterator)


def file_status(mode):
    if stat.S_ISREG(mode):
        return 'A'
    elif stat.S_ISDIR(mode):
        return 'd'
    elif stat.S_ISBLK(mode):
        return 'b'
    elif stat.S_ISCHR(mode):
        return 'c'
    elif stat.S_ISLNK(mode):
        return 's'
    elif stat.S_ISFIFO(mode):
        return 'f'
    return '?'


def chunkit(it, size):
    """
    Chunk an iterator <it> into pieces of <size>.

    >>> list(chunker('ABCDEFG', 3))
    [['A', 'B', 'C'], ['D', 'E', 'F'], ['G']]
    """
    iterable = iter(it)
    return iter(lambda: list(islice(iterable, size)), [])


def consume(iterator, n=None):
    """Advance the iterator n-steps ahead. If n is none, consume entirely."""
    # Use functions that consume iterators at C speed.
    if n is None:
        # feed the entire iterator into a zero-length deque
        deque(iterator, maxlen=0)
    else:
        # advance to the empty slice starting at position n
        next(islice(iterator, n, n), None)

# GenericDirEntry, scandir_generic (c) 2012 Ben Hoyt
# from the python-scandir package (3-clause BSD license, just like us, so no troubles here)
# note: simplified version


class GenericDirEntry:
    __slots__ = ('name', '_scandir_path', '_path')

    def __init__(self, scandir_path, name):
        self._scandir_path = scandir_path
        self.name = name
        self._path = None

    @property
    def path(self):
        if self._path is None:
            self._path = os.path.join(self._scandir_path, self.name)
        return self._path

    def stat(self, follow_symlinks=True):
        assert not follow_symlinks
        return os.lstat(self.path)

    def _check_type(self, type):
        st = self.stat(False)
        return stat.S_IFMT(st.st_mode) == type

    def is_dir(self, follow_symlinks=True):
        assert not follow_symlinks
        return self._check_type(stat.S_IFDIR)

    def is_file(self, follow_symlinks=True):
        assert not follow_symlinks
        return self._check_type(stat.S_IFREG)

    def is_symlink(self):
        return self._check_type(stat.S_IFLNK)

    def inode(self):
        st = self.stat(False)
        return st.st_ino

    def __repr__(self):
        return '<{0}: {1!r}>'.format(self.__class__.__name__, self.path)


def scandir_generic(path='.'):
    """Like os.listdir(), but yield DirEntry objects instead of returning a list of names."""
    for name in sorted(os.listdir(path)):
        yield GenericDirEntry(path, name)


try:
    from os import scandir
except ImportError:
    try:
        # Try python-scandir on Python 3.4
        from scandir import scandir
    except ImportError:
        # If python-scandir is not installed, then use a version that is just as slow as listdir.
        scandir = scandir_generic


def scandir_inorder(path='.'):
    return sorted(scandir(path), key=lambda dirent: dirent.inode())


def clean_lines(lines, lstrip=None, rstrip=None, remove_empty=True, remove_comments=True):
    """
    clean lines (usually read from a config file):

    1. strip whitespace (left and right), 2. remove empty lines, 3. remove comments.

    note: only "pure comment lines" are supported, no support for "trailing comments".

    :param lines: input line iterator (e.g. list or open text file) that gives unclean input lines
    :param lstrip: lstrip call arguments or False, if lstripping is not desired
    :param rstrip: rstrip call arguments or False, if rstripping is not desired
    :param remove_comments: remove comment lines (lines starting with "#")
    :param remove_empty: remove empty lines
    :return: yields processed lines
    """
    for line in lines:
        if lstrip is not False:
            line = line.lstrip(lstrip)
        if rstrip is not False:
            line = line.rstrip(rstrip)
        if remove_empty and not line:
            continue
        if remove_comments and line.startswith('#'):
            continue
        yield line


class CompressionDecider1:
    def __init__(self, compression, compression_files):
        """
        Initialize a CompressionDecider instance (and read config files, if needed).

        :param compression: default CompressionSpec (e.g. from --compression option)
        :param compression_files: list of compression config files (e.g. from --compression-from) or
                                  a list of other line iterators
        """
        self.compression = compression
        if not compression_files:
            self.matcher = None
        else:
            self.matcher = PatternMatcher(fallback=compression)
            for file in compression_files:
                try:
                    for line in clean_lines(file):
                        try:
                            compr_spec, fn_pattern = line.split(':', 1)
                        except:
                            continue
                        self.matcher.add([parse_pattern(fn_pattern)], CompressionSpec(compr_spec))
                finally:
                    if hasattr(file, 'close'):
                        file.close()

    def decide(self, path):
        if self.matcher is not None:
            return self.matcher.match(path)
        return self.compression


class CompressionDecider2:
    logger = create_logger('borg.debug.file-compression')

    def __init__(self, compression):
        self.compression = compression

    def decide(self, chunk):
        # nothing fancy here yet: we either use what the metadata says or the default
        # later, we can decide based on the chunk data also.
        # if we compress the data here to decide, we can even update the chunk data
        # and modify the metadata as desired.
        compr_spec = chunk.meta.get('compress', self.compression)
        if compr_spec['name'] == 'auto':
            # we did not decide yet, use heuristic:
            compr_spec, chunk = self.heuristic_lz4(compr_spec, chunk)
        return compr_spec, chunk

    def heuristic_lz4(self, compr_args, chunk):
        from .compress import get_compressor
        meta, data = chunk
        lz4 = get_compressor('lz4')
        cdata = lz4.compress(data)
        data_len = len(data)
        cdata_len = len(cdata)
        if cdata_len < data_len:
            compr_spec = compr_args['spec']
        else:
            # uncompressible - we could have a special "uncompressible compressor"
            # that marks such data as uncompressible via compression-type metadata.
            compr_spec = CompressionSpec('none')
        compr_args.update(compr_spec)
        self.logger.debug("len(data) == %d, len(lz4(data)) == %d, choosing %s", data_len, cdata_len, compr_spec)
        return compr_args, Chunk(data, **meta)


class ErrorIgnoringTextIOWrapper(io.TextIOWrapper):
    def read(self, n):
        if not self.closed:
            try:
                return super().read(n)
            except BrokenPipeError:
                try:
                    super().close()
                except OSError:
                    pass
        return ''

    def write(self, s):
        if not self.closed:
            try:
                return super().write(s)
            except BrokenPipeError:
                try:
                    super().close()
                except OSError:
                    pass
        return len(s)


class SignalException(BaseException):
    """base class for all signal-based exceptions"""


class SigHup(SignalException):
    """raised on SIGHUP signal"""


class SigTerm(SignalException):
    """raised on SIGTERM signal"""


@contextlib.contextmanager
def signal_handler(sig, handler):
    """
    when entering context, set up signal handler <handler> for signal <sig>.
    when leaving context, restore original signal handler.

    <sig> can bei either a str when giving a signal.SIGXXX attribute name (it
    won't crash if the attribute name does not exist as some names are platform
    specific) or a int, when giving a signal number.

    <handler> is any handler value as accepted by the signal.signal(sig, handler).
    """
    if isinstance(sig, str):
        sig = getattr(signal, sig, None)
    if sig is not None:
        orig_handler = signal.signal(sig, handler)
    try:
        yield
    finally:
        if sig is not None:
            signal.signal(sig, orig_handler)


def raising_signal_handler(exc_cls):
    def handler(sig_no, frame):
        # setting SIG_IGN avoids that an incoming second signal of this
        # kind would raise a 2nd exception while we still process the
        # exception handler for exc_cls for the 1st signal.
        signal.signal(sig_no, signal.SIG_IGN)
        raise exc_cls

    return handler


def swidth_slice(string, max_width):
    """
    Return a slice of *max_width* cells from *string*.

    Negative *max_width* means from the end of string.

    *max_width* is in units of character cells (or "columns").
    Latin characters are usually one cell wide, many CJK characters are two cells wide.
    """
    from .platform import swidth
    reverse = max_width < 0
    max_width = abs(max_width)
    if reverse:
        string = reversed(string)
    current_swidth = 0
    result = []
    for character in string:
        current_swidth += swidth(character)
        if current_swidth > max_width:
            break
        result.append(character)
    if reverse:
        result.reverse()
    return ''.join(result)

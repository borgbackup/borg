import argparse
from binascii import hexlify
from collections import namedtuple
import contextlib
import enum
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
import signal
import threading
import time
import unicodedata
import io
import errno

import logging
from .logger import create_logger
logger = create_logger()

from datetime import datetime, timezone, timedelta
from fnmatch import translate
from operator import attrgetter

from . import __version__ as borg_version
from . import __version_tuple__ as borg_version_tuple
from . import hashindex
from . import chunker
from . import crypto
from . import shellpattern
import msgpack
import msgpack.fallback

import socket

# 20 MiB minus 41 bytes for a Repository header (because the "size" field in the Repository includes
# the header, and the total size was set to 20 MiB).
MAX_DATA_SIZE = 20971479

# MAX_OBJECT_SIZE = <20 MiB (MAX_DATA_SIZE) + 41 bytes for a Repository PUT header, which consists of
# a 1 byte tag ID, 4 byte CRC, 4 byte size and 32 bytes for the ID.
MAX_OBJECT_SIZE = MAX_DATA_SIZE + 41  # see LoggedIO.put_header_fmt.size assertion in repository module
assert MAX_OBJECT_SIZE == 20971520 == 20 * 1024 * 1024

# borg.remote read() buffer size
BUFSIZE = 10 * 1024 * 1024

# to use a safe, limited unpacker, we need to set a upper limit to the archive count in the manifest.
# this does not mean that you can always really reach that number, because it also needs to be less than
# MAX_DATA_SIZE or it will trigger the check for that.
MAX_ARCHIVES = 400000

# repo.list() / .scan() result count limit the borg client uses
LIST_SCAN_LIMIT = 10000

# return codes returned by borg command
# when borg is killed by signal N, rc = 128 + N
EXIT_SUCCESS = 0  # everything done, no problems
EXIT_WARNING = 1  # reached normal end of operation, but there were issues
EXIT_ERROR = 2  # terminated abruptly, did not reach end of operation


'''
The global exit_code variable is used so that modules other than archiver can increase the program exit code if a
warning or error occured during their operation. This is different from archiver.exit_code, which is only accessible
from the archiver object.
'''
exit_code = EXIT_SUCCESS


def set_ec(ec):
    '''
    Sets the exit code of the program, if an exit code higher or equal than this is set, this does nothing. This
    makes EXIT_ERROR override EXIT_WARNING, etc..

    ec: exit code to set
    '''
    global exit_code
    exit_code = max(exit_code, ec)
    return exit_code


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


class DecompressionError(IntegrityError):
    """Decompression error: {}"""


class ExtensionModuleError(Error):
    """The Borg binary extension modules do not seem to be properly installed"""


class NoManifestError(Error):
    """Repository has no manifest."""


class PlaceholderError(Error):
    """Formatting Error: "{}".format({}): {}({})"""


class MandatoryFeatureUnsupported(Error):
    """Unsupported repository feature(s) {}. A newer version of borg is required to access this repository."""


class PythonLibcTooOld(Error):
    """FATAL: this Python was compiled for a too old (g)libc and misses required functionality."""


def check_python():
    required_funcs = {os.stat, os.utime, os.chown}
    if not os.supports_follow_symlinks.issuperset(required_funcs):
        raise PythonLibcTooOld


def check_extension_modules():
    from . import platform, compress
    if hashindex.API_VERSION != '1.0_01':
        raise ExtensionModuleError
    if chunker.API_VERSION != '1.0_01':
        raise ExtensionModuleError
    if compress.API_VERSION != '1.0_01':
        raise ExtensionModuleError
    if crypto.API_VERSION != '1.0_01':
        raise ExtensionModuleError
    if platform.API_VERSION != '1.0_01':
        raise ExtensionModuleError


def get_limited_unpacker(kind):
    """return a limited Unpacker because we should not trust msgpack data received from remote"""
    args = dict(use_list=False,  # return tuples, not lists
                max_bin_len=0,  # not used
                max_ext_len=0,  # not used
                max_buffer_size=3 * max(BUFSIZE, MAX_OBJECT_SIZE),
                max_str_len=MAX_OBJECT_SIZE,  # a chunk or other repo object
                )
    if kind == 'server':
        args.update(dict(max_array_len=100,  # misc. cmd tuples
                         max_map_len=100,  # misc. cmd dicts
                         ))
    elif kind == 'client':
        args.update(dict(max_array_len=LIST_SCAN_LIMIT,  # result list from repo.list() / .scan()
                         max_map_len=100,  # misc. result dicts
                         ))
    elif kind == 'manifest':
        args.update(dict(use_list=True,  # default value
                         max_array_len=100,  # ITEM_KEYS ~= 22
                         max_map_len=MAX_ARCHIVES,  # list of archives
                         max_str_len=255,  # archive name
                         object_hook=StableDict,
                         unicode_errors='surrogateescape',
                         ))
    elif kind == 'key':
        args.update(dict(use_list=True,  # default value
                         max_array_len=0,  # not used
                         max_map_len=10,  # EncryptedKey dict
                         max_str_len=4000,  # inner key data
                         object_hook=StableDict,
                         unicode_errors='surrogateescape',
                         ))
    else:
        raise ValueError('kind must be "server", "client", "manifest" or "key"')
    return msgpack.Unpacker(**args)


class Manifest:

    @enum.unique
    class Operation(enum.Enum):
        # The comments here only roughly describe the scope of each feature. In the end, additions need to be
        # based on potential problems older clients could produce when accessing newer repositories and the
        # tradeofs of locking version out or still allowing access. As all older versions and their exact
        # behaviours are known when introducing new features sometimes this might not match the general descriptions
        # below.

        # The READ operation describes which features are needed to safely list and extract the archives in the
        # repository.
        READ = 'read'
        # The CHECK operation is for all operations that need either to understand every detail
        # of the repository (for consistency checks and repairs) or are seldom used functions that just
        # should use the most restrictive feature set because more fine grained compatibility tracking is
        # not needed.
        CHECK = 'check'
        # The WRITE operation is for adding archives. Features here ensure that older clients don't add archives
        # in an old format, or is used to lock out clients that for other reasons can no longer safely add new
        # archives.
        WRITE = 'write'
        # The DELETE operation is for all operations (like archive deletion) that need a 100% correct reference
        # count and the need to be able to find all (directly and indirectly) referenced chunks of a given archive.
        DELETE = 'delete'

    NO_OPERATION_CHECK = tuple()

    SUPPORTED_REPO_FEATURES = frozenset([])

    MANIFEST_ID = b'\0' * 32

    def __init__(self, key, repository, item_keys=None):
        from .archive import ITEM_KEYS
        self.archives = {}
        self.config = {}
        self.key = key
        self.repository = repository
        self.item_keys = frozenset(item_keys) if item_keys is not None else ITEM_KEYS
        self.tam_verified = False
        self.timestamp = None

    @classmethod
    def load(cls, repository, operations, key=None, force_tam_not_required=False):
        from .key import key_factory, tam_required_file, tam_required
        from .repository import Repository
        from .archive import ITEM_KEYS
        try:
            cdata = repository.get(cls.MANIFEST_ID)
        except Repository.ObjectNotFound:
            raise NoManifestError
        if not key:
            key = key_factory(repository, cdata)
        manifest = cls(key, repository)
        data = key.decrypt(None, cdata)
        m, manifest.tam_verified = key.unpack_and_verify_manifest(data, force_tam_not_required=force_tam_not_required)
        manifest.id = key.id_hash(data)
        if m.get(b'version') not in (1, 2):
            raise ValueError('Invalid manifest version')
        manifest.archives = dict((k.decode('utf-8'), v) for k, v in m[b'archives'].items())
        manifest.timestamp = m.get(b'timestamp')
        if manifest.timestamp:
            manifest.timestamp = manifest.timestamp.decode('ascii')
        manifest.config = m[b'config']
        # valid item keys are whatever is known in the repo or every key we know
        manifest.item_keys = frozenset(m.get(b'item_keys', [])) | ITEM_KEYS

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
        manifest.check_repository_compatibility(operations)
        return manifest, key

    def check_repository_compatibility(self, operations):
        for operation in operations:
            assert isinstance(operation, self.Operation)
            feature_flags = self.config.get(b'feature_flags', None)
            if feature_flags is None:
                return
            if operation.value.encode() not in feature_flags:
                continue
            requirements = feature_flags[operation.value.encode()]
            if b'mandatory' in requirements:
                unsupported = set(requirements[b'mandatory']) - self.SUPPORTED_REPO_FEATURES
                if unsupported:
                    raise MandatoryFeatureUnsupported([f.decode() for f in unsupported])

    def get_all_mandatory_features(self):
        result = {}
        feature_flags = self.config.get(b'feature_flags', None)
        if feature_flags is None:
            return result

        for operation, requirements in feature_flags.items():
            if b'mandatory' in requirements:
                result[operation.decode()] = set([feature.decode() for feature in requirements[b'mandatory']])
        return result

    def write(self):
        if self.key.tam_required:
            self.config[b'tam_required'] = True
        # self.timestamp needs to be strictly monotonically increasing. Clocks often are not set correctly
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()
        else:
            prev_ts = datetime.strptime(self.timestamp, "%Y-%m-%dT%H:%M:%S.%f")
            incremented = (prev_ts + timedelta(microseconds=1)).isoformat()
            self.timestamp = max(incremented, datetime.utcnow().isoformat())
        # include checks for limits as enforced by limited unpacker (used by load())
        assert len(self.archives) <= MAX_ARCHIVES
        assert all(len(name) <= 255 for name in self.archives)
        assert len(self.item_keys) <= 100
        m = {
            'version': 1,
            'archives': StableDict((name, StableDict(archive)) for name, archive in self.archives.items()),
            'timestamp': self.timestamp,
            'config': StableDict(self.config),
            'item_keys': tuple(sorted(self.item_keys)),
        }
        self.tam_verified = True
        data = self.key.pack_and_authenticate_metadata(m)
        self.id = self.key.id_hash(data)
        self.repository.put(self.MANIFEST_ID, self.key.encrypt(data, none_compression=True))

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


def interval(s):
    """Convert a string representing a valid interval to a number of hours."""
    multiplier = {'H': 1, 'd': 24, 'w': 24 * 7, 'm': 24 * 31, 'y': 24 * 365}

    if s.endswith(tuple(multiplier.keys())):
        number = s[:-1]
        suffix = s[-1]
    else:
        # range suffixes in ascending multiplier order
        ranges = [k for k, v in sorted(multiplier.items(), key=lambda t: t[1])]
        raise argparse.ArgumentTypeError(
            'Unexpected interval time unit "%s": expected one of %r' % (s[-1], ranges))

    try:
        hours = int(number) * multiplier[suffix]
    except ValueError:
        hours = -1

    if hours <= 0:
        raise argparse.ArgumentTypeError(
            'Unexpected interval number "%s": expected an integer greater than 0' % number)

    return hours


def prune_within(archives, hours):
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
        now = time.monotonic()
        if dt is None or now - self.last_progress > dt:
            self.last_progress = now
            columns, lines = get_terminal_size()
            if not final:
                msg = '{0.osize_fmt} O {0.csize_fmt} C {0.usize_fmt} D {0.nfiles} N '.format(self)
                path = remove_surrogates(item[b'path']) if item else ''
                space = columns - len(msg)
                if space < 12:
                    msg = ''
                    space = columns - len(msg)
                if space >= 8:
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


def get_security_dir(repository_id=None):
    """Determine where to store local security information."""
    xdg_config = os.environ.get('XDG_CONFIG_HOME', os.path.join(os.path.expanduser('~'), '.config'))
    security_dir = os.environ.get('BORG_SECURITY_DIR', os.path.join(xdg_config, 'borg', 'security'))
    if repository_id:
        security_dir = os.path.join(security_dir, repository_id)
    if not os.path.exists(security_dir):
        os.makedirs(security_dir)
        os.chmod(security_dir, stat.S_IRWXU)
    return security_dir


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
        ts = safe_s(os.stat(s).st_mtime)
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


def PrefixSpec(s):
    return replace_placeholders(s)


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
        'now': current_time.now(),
        'utcnow': current_time.utcnow(),
        'user': uid2user(os.getuid(), os.getuid()),
        'borgversion': borg_version,
        'borgmajor': '%d' % borg_version_tuple[:1],
        'borgminor': '%d.%d' % borg_version_tuple[:2],
        'borgpatch': '%d.%d.%d' % borg_version_tuple[:3],
    }
    return format_line(text, data)


# Not too rarely, we get crappy timestamps from the fs, that overflow some computations.
# As they are crap anyway (valid filesystem timestamps always refer to the past up to
# the present, but never to the future), nothing is lost if we just clamp them to the
# maximum value we can support.
# As long as people are using borg on 32bit platforms to access borg archives, we must
# keep this value True. But we can expect that we can stop supporting 32bit platforms
# well before coming close to the year 2038, so this will never be a practical problem.
SUPPORT_32BIT_PLATFORMS = True  # set this to False before y2038.

if SUPPORT_32BIT_PLATFORMS:
    # second timestamps will fit into a signed int32 (platform time_t limit).
    # nanosecond timestamps thus will naturally fit into a signed int64.
    # subtract last 48h to avoid any issues that could be caused by tz calculations.
    # this is in the year 2038, so it is also less than y9999 (which is a datetime internal limit).
    # msgpack can pack up to uint64.
    MAX_S = 2**31-1 - 48*3600
    MAX_NS = MAX_S * 1000000000
else:
    # nanosecond timestamps will fit into a signed int64.
    # subtract last 48h to avoid any issues that could be caused by tz calculations.
    # this is in the year 2262, so it is also less than y9999 (which is a datetime internal limit).
    # round down to 1e9 multiple, so MAX_NS corresponds precisely to a integer MAX_S.
    # msgpack can pack up to uint64.
    MAX_NS = (2**63-1 - 48*3600*1000000000) // 1000000000 * 1000000000
    MAX_S = MAX_NS // 1000000000


def safe_s(ts):
    if 0 <= ts <= MAX_S:
        return ts
    elif ts < 0:
        return 0
    else:
        return MAX_S


def safe_ns(ts):
    if 0 <= ts <= MAX_NS:
        return ts
    elif ts < 0:
        return 0
    else:
        return MAX_NS


def safe_timestamp(item_timestamp_ns):
    t_ns = safe_ns(bigint_to_int(item_timestamp_ns))
    return datetime.fromtimestamp(t_ns / 1e9)


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


def bin_to_hex(binary):
    return hexlify(binary).decode('ascii')


def parse_stringified_list(s):
    l = re.split(" *, *", s)
    return [item for item in l if item != '']


class Location:
    """Object representing a repository / archive location
    """
    proto = user = _host = port = path = archive = None

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
    # to avoid ambiguities with other regexes, it must also not start with ":" nor with "//" nor with "ssh://".
    scp_path_re = r"""
        (?!(:|//|ssh://))                                   # not starting with ":" or // or ssh://
        (?P<path>([^:]|(:(?!:)))+)                          # any chars, but no "::"
        """

    # file_path must not contain :: (it ends at :: or string end), but may contain single colons.
    # it must start with a / and that slash is part of the path.
    file_path_re = r"""
        (?P<path>(([^/]*)/([^:]|(:(?!:)))+))                # start opt. servername, then /, then any chars, but no "::"
        """

    # abs_path must not contain :: (it ends at :: or string end), but may contain single colons.
    # it must start with a / and that slash is part of the path.
    abs_path_re = r"""
        (?P<path>(/([^:]|(:(?!:)))+))                       # start with /, then any chars, but no "::"
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
        (?P<host>([^:/]+|\[[0-9a-fA-F:.]+\]))(?::(?P<port>\d+))?  # host or host:port or [ipv6] or [ipv6]:port
        """ + abs_path_re + optional_archive_re, re.VERBOSE)  # path or path::archive

    file_re = re.compile(r"""
        (?P<proto>file)://                                  # file://
        """ + file_path_re + optional_archive_re, re.VERBOSE)  # servername/path, path or path::archive

    # note: scp_re is also use for local pathes
    scp_re = re.compile(r"""
        (
            """ + optional_user_re + r"""                   # user@  (optional)
            (?P<host>([^:/]+|\[[0-9a-fA-F:.]+\])):          # host: (don't match / or [ipv6] in host to disambiguate from file:)
        )?                                                  # user@host: part is optional
        """ + scp_path_re + optional_archive_re, re.VERBOSE)  # path with optional archive

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
            raise ValueError('Location: parse failed: %s' % self.orig)

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
            self._host = m.group('host')
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
            self._host = m.group('host')
            self.path = normpath_special(m.group('path'))
            self.archive = m.group('archive')
            self.proto = self._host and 'ssh' or 'file'
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
            name = re.sub('[^\w]', '_', self.host) + '__' + name
        if len(name) > 100:
            # Limit file names to some reasonable length. Most file systems
            # limit them to 255 [unit of choice]; due to variations in unicode
            # handling we truncate to 100 *characters*.
            name = name[:100]
        return os.path.join(get_keys_dir(), name)

    def __repr__(self):
        return "Location(%s)" % self

    @property
    def host(self):
        # strip square brackets used for IPv6 addrs
        if self._host is not None:
            return self._host.lstrip('[').rstrip(']')

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
                                           self._host,  # needed for ipv6 addrs
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
        retry_msg=None, invalid_msg=None, env_msg='{} (from {})',
        falsish=FALSISH, truish=TRUISH, defaultish=DEFAULTISH,
        default=False, retry=True, env_var_override=None, ofile=None, input=input):
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

    each positional argument may be a single or multiple lines (separated by newlines) of text.
    """
    lines = []
    for msg in msgs:
        lines.extend(msg.splitlines())
    for line in lines:
        logger.log(level, line)


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

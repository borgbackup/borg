from .support import argparse  # see support/__init__.py docstring, DEPRECATED - remove after requiring py 3.4

import binascii
from collections import namedtuple
from functools import wraps
import grp
import os
import pwd
import re
try:
    from shutil import get_terminal_size
except ImportError:
    def get_terminal_size(fallback=(80, 24)):
        TerminalSize = namedtuple('TerminalSize', ['columns', 'lines'])
        return TerminalSize(int(os.environ.get('COLUMNS', fallback[0])), int(os.environ.get('LINES', fallback[1])))
import sys
import platform
import time
import unicodedata

from datetime import datetime, timezone, timedelta
from fnmatch import translate
from operator import attrgetter


from . import hashindex
from . import chunker
from . import crypto
import msgpack
import msgpack.fallback


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
    multiplier = {'H': 1, 'd': 24, 'w': 24*7, 'm': 24*31, 'y': 24*365}
    try:
        hours = int(within[:-1]) * multiplier[within[-1]]
    except (KeyError, ValueError):
        # I don't like how this displays the original exception too:
        raise argparse.ArgumentTypeError('Unable to parse --within option: "%s"' % within)
    if hours <= 0:
        raise argparse.ArgumentTypeError('Number specified using --within option must be positive')
    target = datetime.now(timezone.utc) - timedelta(seconds=hours*60*60)
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

    def show_progress(self, item=None, final=False, stream=None):
        columns, lines = get_terminal_size()
        if not final:
            msg = '{0.osize_fmt} O {0.csize_fmt} C {0.usize_fmt} D {0.nfiles} N '.format(self)
            path = remove_surrogates(item[b'path']) if item else ''
            space = columns - len(msg)
            if space < len('...') + len(path):
                path = '%s...%s' % (path[:(space//2)-len('...')], path[-space//2:])
            msg += "{0:<{space}}".format(path, space=space)
        else:
            msg = ' ' * columns
        print(msg, file=stream or sys.stderr, end="\r")
        (stream or sys.stderr).flush()


def get_keys_dir():
    """Determine where to repository keys and cache"""
    return os.environ.get('BORG_KEYS_DIR',
                          os.path.join(os.path.expanduser('~'), '.borg', 'keys'))


def get_cache_dir():
    """Determine where to repository keys and cache"""
    xdg_cache = os.environ.get('XDG_CACHE_HOME', os.path.join(os.path.expanduser('~'), '.cache'))
    return os.environ.get('BORG_CACHE_DIR', os.path.join(xdg_cache, 'borg'))


def to_localtime(ts):
    """Convert datetime object from UTC to local time zone"""
    return datetime(*time.localtime((ts - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds())[:6])


def parse_timestamp(timestamp):
    """Parse a ISO 8601 timestamp string"""
    if '.' in timestamp:  # microseconds might not be pressent
        return datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%f').replace(tzinfo=timezone.utc)
    else:
        return datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)


def update_excludes(args):
    """Merge exclude patterns from files with those on command line.
    Empty lines and lines starting with '#' are ignored, but whitespace
    is not stripped."""
    if hasattr(args, 'exclude_files') and args.exclude_files:
        if not hasattr(args, 'excludes') or args.excludes is None:
            args.excludes = []
        for file in args.exclude_files:
            patterns = [line.rstrip('\r\n') for line in file if not line.startswith('#')]
            args.excludes += [ExcludePattern(pattern) for pattern in patterns if pattern]
            file.close()


def adjust_patterns(paths, excludes):
    if paths:
        return (excludes or []) + [IncludePattern(path) for path in paths] + [ExcludePattern('*')]
    else:
        return excludes


def exclude_path(path, patterns):
    """Used by create and extract sub-commands to determine
    whether or not an item should be processed.
    """
    for pattern in (patterns or []):
        if pattern.match(path):
            return isinstance(pattern, ExcludePattern)
    return False


# For both IncludePattern and ExcludePattern, we require that
# the pattern either match the whole path or an initial segment
# of the path up to but not including a path separator.  To
# unify the two cases, we add a path separator to the end of
# the path before matching.

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


class IncludePattern:
    """Literal files or directories listed on the command line
    for some operations (e.g. extract, but not create).
    If a directory is specified, all paths that start with that
    path match as well.  A trailing slash makes no difference.
    """
    def __init__(self, pattern):
        self.pattern_orig = pattern
        self.match_count = 0

        if sys.platform in ('darwin',):
            pattern = unicodedata.normalize("NFD", pattern)

        self.pattern = os.path.normpath(pattern).rstrip(os.path.sep)+os.path.sep

    @normalized
    def match(self, path):
        matches = (path+os.path.sep).startswith(self.pattern)
        if matches:
            self.match_count += 1
        return matches

    def __repr__(self):
        return '%s(%s)' % (type(self), self.pattern)

    def __str__(self):
        return self.pattern_orig


class ExcludePattern(IncludePattern):
    """Shell glob patterns to exclude.  A trailing slash means to
    exclude the contents of a directory, but not the directory itself.
    """
    def __init__(self, pattern):
        self.pattern_orig = pattern
        self.match_count = 0

        if pattern.endswith(os.path.sep):
            self.pattern = os.path.normpath(pattern).rstrip(os.path.sep)+os.path.sep+'*'+os.path.sep
        else:
            self.pattern = os.path.normpath(pattern)+os.path.sep+'*'

        if sys.platform in ('darwin',):
            self.pattern = unicodedata.normalize("NFD", self.pattern)

        # fnmatch and re.match both cache compiled regular expressions.
        # Nevertheless, this is about 10 times faster.
        self.regex = re.compile(translate(self.pattern))

    @normalized
    def match(self, path):
        matches = self.regex.match(path+os.path.sep) is not None
        if matches:
            self.match_count += 1
        return matches

    def __repr__(self):
        return '%s(%s)' % (type(self), self.pattern)

    def __str__(self):
        return self.pattern_orig


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
    compression = values[0]
    try:
        compression = int(compression)
        if count > 1:
            raise ValueError
        # DEPRECATED: it is just --compression N
        if 0 <= compression <= 9:
            print('Warning: --compression %d is deprecated, please use --compression zlib,%d.' % (compression, compression))
            if compression == 0:
                print('Hint: instead of --compression zlib,0 you could also use --compression none for better performance.')
                print('Hint: archives generated using --compression none are not compatible with borg < 0.25.0.')
            return dict(name='zlib', level=compression)
        raise ValueError
    except ValueError:
        # --compression algo[,...]
        name = compression
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


def format_time(t):
    """use ISO-8601 date and time format
    """
    return t.strftime('%Y-%m-%d %H:%M:%S')


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


def format_file_mode(mod):
    """Format file mode bits for list output
    """
    def x(v):
        return ''.join(v & m and s or '-'
                       for m, s in ((4, 'r'), (2, 'w'), (1, 'x')))
    return '%s%s%s' % (x(mod // 64), x(mod // 8), x(mod))


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

    def parse(self, text):
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
            self.path = m.group('path')
            self.archive = m.group('archive')
            return True
        m = self.file_re.match(text)
        if m:
            self.proto = m.group('proto')
            self.path = m.group('path')
            self.archive = m.group('archive')
            return True
        m = self.scp_re.match(text)
        if m:
            self.user = m.group('user')
            self.host = m.group('host')
            self.path = m.group('path')
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
            raise argparse.ArgumentTypeError('Invalid location format: "%s"' % text)
        if archive is True and not loc.archive:
            raise argparse.ArgumentTypeError('"%s": No archive specified' % text)
        elif archive is False and loc.archive:
            raise argparse.ArgumentTypeError('"%s" No archive can be specified' % text)
        return loc
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


if sys.version < '3.3':
    # st_xtime_ns attributes only available in 3.3+
    def st_atime_ns(st):
        return int(st.st_atime * 1e9)

    def st_ctime_ns(st):
        return int(st.st_ctime * 1e9)

    def st_mtime_ns(st):
        return int(st.st_mtime * 1e9)

    # unhexlify in < 3.3 incorrectly only accepts bytes input
    def unhexlify(data):
        if isinstance(data, str):
            data = data.encode('ascii')
        return binascii.unhexlify(data)
else:
    def st_atime_ns(st):
        return st.st_atime_ns

    def st_ctime_ns(st):
        return st.st_ctime_ns

    def st_mtime_ns(st):
        return st.st_mtime_ns

    unhexlify = binascii.unhexlify


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


def yes(msg=None, retry_msg=None, false_msg=None, true_msg=None,
        default=False, default_notty=None, default_eof=None,
        falsish=('No', 'no', 'N', 'n'), truish=('Yes', 'yes', 'Y', 'y'),
        env_var_override=None, ifile=None, ofile=None, input=input):
    """
    Output <msg> (usually a question) and let user input an answer.
    Qualifies the answer according to falsish and truish as True or False.
    If it didn't qualify and retry_msg is None (no retries wanted),
    return the default [which defaults to False]. Otherwise let user retry
    answering until answer is qualified.

    If env_var_override is given and it is non-empty, counts as truish answer
    and won't ask user for an answer.
    If we don't have a tty as input and default_notty is not None, return its value.
    Otherwise read input from non-tty and proceed as normal.
    If EOF is received instead an input, return default_eof [or default, if not given].

    :param msg: introducing message to output on ofile, no \n is added [None]
    :param retry_msg: retry message to output on ofile, no \n is added [None]
           (also enforces retries instead of returning default)
    :param false_msg: message to output before returning False [None]
    :param true_msg: message to output before returning True [None]
    :param default: default return value (empty answer is given) [False]
    :param default_notty: if not None, return its value if no tty is connected [None]
    :param default_eof: return value if EOF was read as answer [same as default]
    :param falsish: sequence of answers qualifying as False
    :param truish: sequence of answers qualifying as True
    :param env_var_override: environment variable name [None]
    :param ifile: input stream [sys.stdin] (only for testing!)
    :param ofile: output stream [sys.stderr]
    :param input: input function [input from builtins]
    :return: boolean answer value, True or False
    """
    # note: we do not assign sys.stdin/stderr as defaults above, so they are
    # really evaluated NOW,  not at function definition time.
    if ifile is None:
        ifile = sys.stdin
    if ofile is None:
        ofile = sys.stderr
    if default not in (True, False):
        raise ValueError("invalid default value, must be True or False")
    if default_notty not in (None, True, False):
        raise ValueError("invalid default_notty value, must be None, True or False")
    if default_eof not in (None, True, False):
        raise ValueError("invalid default_eof value, must be None, True or False")
    if msg:
        print(msg, file=ofile, end='')
        ofile.flush()
    if env_var_override:
        value = os.environ.get(env_var_override)
        # currently, any non-empty value counts as truish
        # TODO: change this so one can give y/n there?
        if value:
            value = bool(value)
            value_str = truish[0] if value else falsish[0]
            print("{} (from {})".format(value_str, env_var_override), file=ofile)
            return value
    if default_notty is not None and not ifile.isatty():
        # looks like ifile is not a terminal (but e.g. a pipe)
        return default_notty
    while True:
        try:
            answer = input()  # XXX how can we use ifile?
        except EOFError:
            return default_eof if default_eof is not None else default
        if answer in truish:
            if true_msg:
                print(true_msg, file=ofile)
            return True
        if answer in falsish:
            if false_msg:
                print(false_msg, file=ofile)
            return False
        if retry_msg is None:
            # no retries wanted, we just return the default
            return default
        if retry_msg:
            print(retry_msg, file=ofile, end='')
            ofile.flush()


class ProgressIndicatorPercent:
    def __init__(self, total, step=5, start=0, same_line=False, msg="%3.0f%%", file=sys.stderr):
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
        print(self.msg % percent, file=self.file, end='\r' if self.same_line else '\n')  # python 3.3 gives us flush=True
        self.file.flush()

    def finish(self):
        if self.same_line:
            print(" " * len(self.msg % 100.0), file=self.file, end='\r')



class ProgressIndicatorEndless:
    def __init__(self, step=10, file=sys.stderr):
        """
        Progress indicator (long row of dots)

        :param step: every Nth call, call the func
        :param file: output file, default: sys.stderr
        """
        self.counter = 0  # call counter
        self.triggered = 0  # increases 1 per trigger event
        self.step = step  # trigger every <step> calls
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
        print('.', end='', file=self.file)  # python 3.3 gives us flush=True
        self.file.flush()

    def finish(self):
        print(file=self.file)


def sysinfo():
    info = []
    info.append('Platform: %s' % (' '.join(platform.uname()), ))
    if sys.platform.startswith('linux'):
        info.append('Linux: %s %s %s  LibC: %s %s' % (platform.linux_distribution() + platform.libc_ver()))
    info.append('Python: %s %s' % (platform.python_implementation(), platform.python_version()))
    info.append('')
    return '\n'.join(info)

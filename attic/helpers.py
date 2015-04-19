import argparse
import binascii
import grp
import msgpack
import os
import pwd
import re
import sys
import time
from datetime import datetime, timezone, timedelta
from fnmatch import translate
from operator import attrgetter
import fcntl

import attic.hashindex
import attic.chunker
import attic.crypto


class Error(Exception):
    """Error base class"""

    exit_code = 1

    def get_message(self):
        return 'Error: ' + type(self).__doc__.format(*self.args)


class ExtensionModuleError(Error):
    """The Attic binary extension modules does not seem to be properly installed"""


class UpgradableLock:

    class ReadLockFailed(Error):
        """Failed to acquire read lock on {}"""

    class WriteLockFailed(Error):
        """Failed to acquire write lock on {}"""

    def __init__(self, path, exclusive=False):
        self.path = path
        try:
            self.fd = open(path, 'r+')
        except IOError:
            self.fd = open(path, 'r')
        try:
            if exclusive:
                fcntl.lockf(self.fd, fcntl.LOCK_EX)
            else:
                fcntl.lockf(self.fd, fcntl.LOCK_SH)
        # Python 3.2 raises IOError, Python3.3+ raises OSError
        except (IOError, OSError):
            if exclusive:
                raise self.WriteLockFailed(self.path)
            else:
                raise self.ReadLockFailed(self.path)
        self.is_exclusive = exclusive

    def upgrade(self):
        try:
            fcntl.lockf(self.fd, fcntl.LOCK_EX)
        # Python 3.2 raises IOError, Python3.3+ raises OSError
        except (IOError, OSError):
            raise self.WriteLockFailed(self.path)
        self.is_exclusive = True

    def release(self):
        fcntl.lockf(self.fd, fcntl.LOCK_UN)
        self.fd.close()


def check_extension_modules():
    import attic.platform
    if (attic.hashindex.API_VERSION != 2 or
        attic.chunker.API_VERSION != 2 or
        attic.crypto.API_VERSION != 2 or
        attic.platform.API_VERSION != 2):
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
        manifest.archives = dict((k.decode('utf-8'), v) for k,v in m[b'archives'].items())
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
                if len(keep) == n: break
    return keep


class Statistics:

    def __init__(self):
        self.osize = self.csize = self.usize = self.nfiles = 0

    def update(self, size, csize, unique):
        self.osize += size
        self.csize += csize
        if unique:
            self.usize += csize

    def print_(self, label, cache):
        total_size, total_csize, unique_size, unique_csize = cache.chunks.summarize()
        print()
        print('                       Original size      Compressed size    Deduplicated size')
        print('%-15s %20s %20s %20s' % (label, format_file_size(self.osize), format_file_size(self.csize), format_file_size(self.usize)))
        print('All archives:   %20s %20s %20s' % (format_file_size(total_size), format_file_size(total_csize), format_file_size(unique_csize)))


def get_keys_dir():
    """Determine where to repository keys and cache"""
    return os.environ.get('ATTIC_KEYS_DIR',
                          os.path.join(os.path.expanduser('~'), '.attic', 'keys'))


def get_cache_dir():
    """Determine where to repository keys and cache"""
    return os.environ.get('ATTIC_CACHE_DIR',
                          os.path.join(os.path.expanduser('~'), '.cache', 'attic'))


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

class IncludePattern:
    """Literal files or directories listed on the command line
    for some operations (e.g. extract, but not create).
    If a directory is specified, all paths that start with that
    path match as well.  A trailing slash makes no difference.
    """
    def __init__(self, pattern):
        self.pattern = pattern.rstrip(os.path.sep)+os.path.sep

    def match(self, path):
        return (path+os.path.sep).startswith(self.pattern)

    def __repr__(self):
        return '%s(%s)' % (type(self), self.pattern)


class ExcludePattern(IncludePattern):
    """Shell glob patterns to exclude.  A trailing slash means to
    exclude the contents of a directory, but not the directory itself.
    """
    def __init__(self, pattern):
        if pattern.endswith(os.path.sep):
            self.pattern = pattern+'*'+os.path.sep
        else:
            self.pattern = pattern+os.path.sep+'*'
        # fnmatch and re.match both cache compiled regular expressions.
        # Nevertheless, this is about 10 times faster.
        self.regex = re.compile(translate(self.pattern))

    def match(self, path):
        return self.regex.match(path+os.path.sep) is not None

    def __repr__(self):
        return '%s(%s)' % (type(self), self.pattern)


def is_cachedir(path):
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


def format_time(t):
    """Format datetime suitable for fixed length list output
    """
    if abs((datetime.now() - t).days) < 365:
        return t.strftime('%b %d %H:%M')
    else:
        return t.strftime('%b %d  %Y')


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


def format_file_size(v):
    """Format file size into a human friendly format
    """
    if abs(v) > 10**12:
        return '%.2f TB' % (v / 10**12)
    elif abs(v) > 10**9:
        return '%.2f GB' % (v / 10**9)
    elif abs(v) > 10**6:
        return '%.2f MB' % (v / 10**6)
    elif abs(v) > 10**3:
        return '%.2f kB' % (v / 10**3)
    else:
        return '%d B' % v


def format_archive(archive):
    return '%-36s %s' % (archive.name, to_localtime(archive.ts).strftime('%c'))


class IntegrityError(Error):
    """Data integrity error"""


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
    for entry in acl.decode('ascii').split('\n'):
        if entry:
            fields = entry.split(':')
            if len(fields) == 4:
                entries.append(':'.join([fields[0], fields[3], fields[2]]))
            else:
                entries.append(entry)
    return ('\n'.join(entries)).encode('ascii')


class Location:
    """Object representing a repository / archive location
    """
    proto = user = host = port = path = archive = None
    ssh_re = re.compile(r'(?P<proto>ssh)://(?:(?P<user>[^@]+)@)?'
                        r'(?P<host>[^:/#]+)(?::(?P<port>\d+))?'
                        r'(?P<path>[^:]+)(?:::(?P<archive>.+))?$')
    file_re = re.compile(r'(?P<proto>file)://'
                         r'(?P<path>[^:]+)(?:::(?P<archive>.+))?$')
    scp_re = re.compile(r'((?:(?P<user>[^@]+)@)?(?P<host>[^:/]+):)?'
                        r'(?P<path>[^:]+)(?:::(?P<archive>.+))?$')

    def __init__(self, text):
        self.orig = text
        if not self.parse(text):
            raise ValueError

    def parse(self, text):
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
        items = []
        items.append('proto=%r' % self.proto)
        items.append('user=%r' % self.user)
        items.append('host=%r' % self.host)
        items.append('port=%r' % self.port)
        items.append('path=%r' % self.path)
        items.append('archive=%r' % self.archive)
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


def read_msgpack(filename):
    with open(filename, 'rb') as fd:
        return msgpack.unpack(fd)


def write_msgpack(filename, d):
    with open(filename + '.tmp', 'wb') as fd:
        msgpack.pack(d, fd)
        fd.flush()
        os.fsync(fd)
    os.rename(filename + '.tmp', filename)


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
        return sorted(super(StableDict, self).items())


if sys.version < '3.3':
    # st_mtime_ns attribute only available in 3.3+
    def st_mtime_ns(st):
        return int(st.st_mtime * 1e9)

    # unhexlify in < 3.3 incorrectly only accepts bytes input
    def unhexlify(data):
        if isinstance(data, str):
            data = data.encode('ascii')
        return binascii.unhexlify(data)
else:
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


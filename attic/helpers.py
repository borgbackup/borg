import argparse
import binascii
import grp
import msgpack
import os
import pwd
import re
import stat
import sys
import time
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from operator import attrgetter
import fcntl


class Error(Exception):
    """Error base class"""

    exit_code = 1

    def get_message(self):
        return 'Error: ' + type(self).__doc__.format(*self.args)


class UpgradableLock:

    class LockUpgradeFailed(Error):
        """Failed to acquire write lock on {}"""

    def __init__(self, path, exclusive=False):
        self.path = path
        try:
            self.fd = open(path, 'r+')
        except IOError:
            self.fd = open(path, 'r')
        if exclusive:
            fcntl.lockf(self.fd, fcntl.LOCK_EX)
        else:
            fcntl.lockf(self.fd, fcntl.LOCK_SH)
        self.is_exclusive = exclusive

    def upgrade(self):
        try:
            fcntl.lockf(self.fd, fcntl.LOCK_EX)
        except OSError as e:
            raise self.LockUpgradeFailed(self.path)
        self.is_exclusive = True

    def release(self):
        fcntl.lockf(self.fd, fcntl.LOCK_UN)
        self.fd.close()


class Manifest:

    MANIFEST_ID = b'\0' * 32

    def __init__(self):
        self.archives = {}
        self.config = {}

    @classmethod
    def load(cls, repository):
        from .key import key_factory
        manifest = cls()
        manifest.repository = repository
        cdata = repository.get(manifest.MANIFEST_ID)
        manifest.key = key = key_factory(repository, cdata)
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
        data = msgpack.packb({
            'version': 1,
            'archives': self.archives,
            'timestamp': self.timestamp,
            'config': self.config,
        })
        self.id = self.key.id_hash(data)
        self.repository.put(self.MANIFEST_ID, self.key.encrypt(data))


def prune_split(archives, pattern, n, skip=[]):
    items = {}
    keep = []
    for a in archives:
        key = to_localtime(a.ts).strftime(pattern)
        items.setdefault(key, [])
        items[key].append(a)
    for key, values in sorted(items.items(), reverse=True):
        if n and values[0] not in skip:
            values.sort(key=attrgetter('ts'), reverse=True)
            keep.append(values[0])
            n -= 1
    return keep


class Statistics:

    def __init__(self):
        self.osize = self.csize = self.usize = self.nfiles = 0

    def update(self, size, csize, unique):
        self.osize += size
        self.csize += csize
        if unique:
            self.usize += csize

    def print_(self):
        print('Number of files: %d' % self.nfiles)
        print('Original size: %d (%s)' % (self.osize, format_file_size(self.osize)))
        print('Compressed size: %s (%s)' % (self.csize, format_file_size(self.csize)))
        print('Unique data: %d (%s)' % (self.usize, format_file_size(self.usize)))


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


def adjust_patterns(paths, excludes):
    if paths:
        return (excludes or []) + [IncludePattern(path) for path in paths] + [ExcludePattern('*')]
    else:
        return excludes


def exclude_path(path, patterns):
    """Used by create and extract sub-commands to determine
    if an item should be processed or not
    """
    for pattern in (patterns or []):
        if pattern.match(path):
            return isinstance(pattern, ExcludePattern)
    return False


class IncludePattern:
    """--include PATTERN
    """
    def __init__(self, pattern):
        self.pattern = pattern

    def match(self, path):
        dir, name = os.path.split(path)
        return (path == self.pattern
                or (dir + os.path.sep).startswith(self.pattern))

    def __repr__(self):
        return '%s(%s)' % (type(self), self.pattern)


class ExcludePattern(IncludePattern):
    """
    """
    def __init__(self, pattern):
        self.pattern = self.dirpattern = pattern
        if not pattern.endswith(os.path.sep):
            self.dirpattern += os.path.sep

    def match(self, path):
        dir, name = os.path.split(path)
        return (path == self.pattern
                or (dir + os.path.sep).startswith(self.dirpattern)
                or fnmatchcase(name, self.pattern))

    def __repr__(self):
        return '%s(%s)' % (type(self), self.pattern)


def walk_path(path, skip_inodes=None):
    st = os.lstat(path)
    if skip_inodes and (st.st_ino, st.st_dev) in skip_inodes:
        return
    yield path, st
    if stat.S_ISDIR(st.st_mode):
        for f in os.listdir(path):
            for x in walk_path(os.path.join(path, f), skip_inodes):
                yield x


def format_time(t):
    """Format datetime suitable for fixed length list output
    """
    if (datetime.now() - t).days < 365:
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
    if v > 1024 * 1024 * 1024:
        return '%.2f GB' % (v / 1024. / 1024. / 1024.)
    elif v > 1024 * 1024:
        return '%.2f MB' % (v / 1024. / 1024.)
    elif v > 1024:
        return '%.2f kB' % (v / 1024.)
    else:
        return '%d B' % v


class IntegrityError(Exception):
    """
    """


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
def uid2user(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return None


@memoize
def user2uid(user):
    try:
        return user and pwd.getpwnam(user).pw_uid
    except KeyError:
        return None


@memoize
def gid2group(gid):
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return None


@memoize
def group2gid(group):
    try:
        return group and grp.getgrnam(group).gr_gid
    except KeyError:
        return None


class Location:
    """Object representing a repository / archive location
    """
    proto = user = host = port = path = archive = None
    ssh_re = re.compile(r'(?P<proto>ssh)://(?:(?P<user>[^@]+)@)?'
                        r'(?P<host>[^:/#]+)(?::(?P<port>\d+))?'
                        r'(?P<path>[^:]+)(?:::(?P<archive>.+))?')
    file_re = re.compile(r'(?P<proto>file)://'
                         r'(?P<path>[^:]+)(?:::(?P<archive>.+))?')
    scp_re = re.compile(r'((?:(?P<user>[^@]+)@)?(?P<host>[^:/]+):)?'
                        r'(?P<path>[^:]+)(?:::(?P<archive>.+))?')

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


_safe_re = re.compile('^((..)?/+)+')


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

from __future__ import with_statement
import argparse
from datetime import datetime, timedelta
from fnmatch import fnmatchcase
import grp
import os
import pwd
import re
import stat
import struct
import sys
import time
import urllib

# OSX filenames are UTF-8 Only so any non-utf8 filenames are url encoded
if sys.platform == 'darwin':
    def encode_filename(name):
        try:
            name.decode('utf-8')
            return name
        except UnicodeDecodeError:
            return urllib.quote(name)
else:
    encode_filename = str

class Counter(object):

    __slots__ = ('v',)

    def __init__(self, value=0):
        self.v = value

    def inc(self, amount=1):
        self.v += amount

    def dec(self, amount=1):
        self.v -= amount

    def __cmp__(self, x):
        return cmp(self.v, x)

    def __repr__(self):
        return '<Counter(%r)>' % self.v


def get_keys_dir():
    """Determine where to store keys and cache"""
    return os.environ.get('DARC_KEYS_DIR',
                          os.path.join(os.path.expanduser('~'), '.darc', 'keys'))

def get_cache_dir():
    """Determine where to store keys and cache"""
    return os.environ.get('DARC_CACHE_DIR',
                          os.path.join(os.path.expanduser('~'), '.darc', 'cache'))


def deferrable(f):
    def wrapper(*args, **kw):
        callback = kw.pop('callback', None)
        if callback:
            data = kw.pop('callback_data', None)
            try:
                res = f(*args, **kw)
            except Exception, e:
                callback(None, e, data)
            else:
                callback(res, None, data)
        else:
            return f(*args, **kw)
    return wrapper

def error_callback(res, error, data):
    if res:
        raise res

def to_localtime(ts):
    """Convert datetime object from UTC to local time zone"""
    return ts - timedelta(seconds=time.altzone)

def read_set(path):
    """Read set from disk (as int32s)
    """
    with open(path, 'rb') as fd:
        data = fd.read()
        return set(struct.unpack('<%di' % (len(data) / 4), data))


def write_set(s, path):
    """Write set to disk (as int32s)
    """
    with open(path, 'wb') as fd:
        fd.write(struct.pack('<%di' % len(s), *s))


def encode_long(v):
    bytes = []
    while True:
        if v > 0x7f:
            bytes.append(0x80 | (v % 0x80))
            v >>= 7
        else:
            bytes.append(v)
            return ''.join(chr(x) for x in bytes)


def decode_long(bytes):
    v = 0
    base = 0
    for x in bytes:
        b = ord(x)
        if b & 0x80:
            v += (b & 0x7f) << base
            base += 7
        else:
            return v + (b << base)


def exclude_path(path, patterns):
    """Used by create and extract sub-commands to determine
    if an item should be processed or not
    """
    for pattern in (patterns or []):
        if pattern.match(path):
            return isinstance(pattern, ExcludePattern)
    return False


class IncludePattern(object):
    """--include PATTERN

    >>> py = IncludePattern('*.py')
    >>> foo = IncludePattern('/foo')
    >>> py.match('/foo/foo.py')
    True
    >>> py.match('/bar/foo.java')
    False
    >>> foo.match('/foo/foo.py')
    True
    >>> foo.match('/bar/foo.java')
    False
    >>> foo.match('/foobar/foo.py')
    False
    >>> foo.match('/foo')
    True
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


class ExcludePattern(IncludePattern):
    """
    """


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


def format_file_mode(mod):
    """Format file mode bits for list output
    """
    def x(v):
        return ''.join(v & m and s or '-'
                       for m, s in ((4, 'r'), (2, 'w'), (1, 'x')))
    return '%s%s%s' % (x(mod / 64), x(mod / 8), x(mod))

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
        return str(v)

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
        return pwd.getpwnam(user).pw_uid
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
        return grp.getgrnam(group).gr_gid
    except KeyError:
        return None


class Location(object):
    """Object representing a store / archive location

    >>> Location('ssh://user@host:1234/some/path::archive')
    Location(proto='ssh', user='user', host='host', port=1234, path='/some/path', archive='archive')
    >>> Location('file:///some/path::archive')
    Location(proto='file', user=None, host=None, port=None, path='/some/path', archive='archive')
    >>> Location('user@host:/some/path::archive')
    Location(proto='ssh', user='user', host='host', port=22, path='/some/path', archive='archive')
    >>> Location('/some/path::archive')
    Location(proto='file', user=None, host=None, port=None, path='/some/path', archive='archive')
    """
    proto = user = host = port = path = archive = None
    ssh_re = re.compile(r'(?P<proto>ssh)://(?:(?P<user>[^@]+)@)?'
                        r'(?P<host>[^:/#]+)(?::(?P<port>\d+))?'
                        r'(?P<path>[^:]*)(?:::(?P<archive>.+))?')
    file_re = re.compile(r'(?P<proto>file)://'
                         r'(?P<path>[^:]*)(?:::(?P<archive>.+))?')
    scp_re = re.compile(r'((?:(?P<user>[^@]+)@)?(?P<host>[^:/]+):)?'
                        r'(?P<path>[^:]*)(?:::(?P<archive>.+))?')

    def __init__(self, text):
        if not self.parse(text):
            raise ValueError

    def parse(self, text):
        m = self.ssh_re.match(text)
        if m:
            self.proto = m.group('proto')
            self.user = m.group('user')
            self.host = m.group('host')
            self.port = m.group('port') and int(m.group('port')) or 22
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
            if self.proto == 'ssh':
                self.port = 22
            return True
        return False

    def __str__(self):
        items = []
        items.append('proto=%r' % self.proto)
        items.append('user=%r' % self.user)
        items.append('host=%r' % self.host)
        items.append('port=%r' % self.port)
        items.append('path=%r'% self.path)
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



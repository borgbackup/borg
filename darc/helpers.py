import argparse
from datetime import datetime
import grp
import pwd
import re


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

    loc_re = re.compile(r'^((?:(?P<user>[^@]+)@)?(?P<host>[^:]+):)?'
                        r'(?P<path>[^:]*)(?:::(?P<archive>[^:]+))?$')

    def __init__(self, text):
        loc = self.loc_re.match(text)
        loc = loc and loc.groupdict()
        if not loc:
            raise ValueError
        self.user = loc['user']
        self.host = loc['host']
        self.path = loc['path']
        if not self.host and not self.path:
            raise ValueError
        self.archive = loc['archive']

    def __str__(self):
        text = ''
        if self.user:
            text += '%s@' % self.user
        if self.host:
            text += '%s::' % self.host
        if self.path:
            text += self.path
        if self.archive:
            text += ':%s' % self.archive
        return text

    def __repr__(self):
        return "Location('%s')" % self


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



import argparse
import re


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



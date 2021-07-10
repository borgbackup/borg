import argparse
import contextlib
import collections
import enum
import errno
import grp
import hashlib
import logging
import io
import json
import os
import os.path
import platform
import pwd
import re
import shlex
import signal
import socket
import stat
import subprocess
import sys
import textwrap
import time
import uuid
from binascii import hexlify
from collections import namedtuple, deque, abc, Counter
from datetime import datetime, timezone, timedelta
from functools import partial, lru_cache
from itertools import islice
from operator import attrgetter
from os import scandir
from string import Formatter
from shutil import get_terminal_size

# MSGPACK =====================================================================
# we are rather picky about msgpack versions, because a good working msgpack is
# very important for borg, see https://github.com/borgbackup/borg/issues/3753
#
# because some linux distributions didn't get their dependency management right
# and broke borgbackup by upgrading msgpack to incompatible versions, we now
# bundle msgpack-python 0.5.6, which is the latest and best msgpack that is
# still compatible with borg 1.1.x and we use the bundled version by default.
#
# if you are a package maintainer and don't like bundled library code, feel
# free to not use the bundled code:
# - set prefer_system_msgpack = True
# - make sure that an external msgpack-python gets installed
# - make sure the external msgpack-python always stays at supported versions.
# - best versions seem to be 0.4.6, 0.4.7, 0.4.8 and 0.5.6.
# - if you can't satisfy the above requirement, these are versions that might
#   also work ok, IF you make sure to use the COMPILED version of
#   msgpack-python NOT the PURE PYTHON fallback implementation: 0.5.1 and 0.5.4
#
# Please note:
# - using any other version is not supported by borg development and
#   any feedback related to issues caused by this will be ignored.
# - especially, it is known that msgpack 0.6.x does NOT work for borg 1.1.x.

prefer_system_msgpack = False

try:
    if prefer_system_msgpack:
        raise ImportError
    # use the bundled msgpack 0.5.6 known-good version - other code only imports it from here:
    import borg.algorithms.msgpack as msgpack
    from borg.algorithms.msgpack import fallback as msgpack_fallback
except ImportError:
    # use an external msgpack version
    import msgpack
    from msgpack import fallback as msgpack_fallback


from .logger import create_logger
logger = create_logger()

import borg.crypto.low_level
from . import __version__ as borg_version
from . import __version_tuple__ as borg_version_tuple
from . import chunker
from . import hashindex
from . import shellpattern
from .constants import *  # NOQA


# generic mechanism to enable users to invoke workarounds by setting the
# BORG_WORKAROUNDS environment variable to a list of comma-separated strings.
# see the docs for a list of known workaround strings.
workarounds = tuple(os.environ.get('BORG_WORKAROUNDS', '').split(','))


'''
The global exit_code variable is used so that modules other than archiver can increase the program exit code if a
warning or error occurred during their operation. This is different from archiver.exit_code, which is only accessible
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
    """Error: {}"""
    # Error base class

    # if we raise such an Error and it is only caught by the uppermost
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
    """Error: {}"""
    # like Error, but show a traceback also
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


class InvalidPlaceholder(PlaceholderError):
    """Invalid placeholder "{}" in string: {}"""


class PythonLibcTooOld(Error):
    """FATAL: this Python was compiled for a too old (g)libc and misses required functionality."""


def check_python():
    required_funcs = {os.stat, os.utime, os.chown}
    if not os.supports_follow_symlinks.issuperset(required_funcs):
        raise PythonLibcTooOld


class MandatoryFeatureUnsupported(Error):
    """Unsupported repository feature(s) {}. A newer version of borg is required to access this repository."""


def check_extension_modules():
    from . import platform, compress, item
    if hashindex.API_VERSION != '1.1_07':
        raise ExtensionModuleError
    if chunker.API_VERSION != '1.1_01':
        raise ExtensionModuleError
    if compress.API_VERSION != '1.1_06':
        raise ExtensionModuleError
    if borg.crypto.low_level.API_VERSION != '1.1_02':
        raise ExtensionModuleError
    if platform.API_VERSION != platform.OS_API_VERSION or platform.API_VERSION != '1.1_04':
        raise ExtensionModuleError
    if item.API_VERSION != '1.1_03':
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


ArchiveInfo = namedtuple('ArchiveInfo', 'name id ts')


class Archives(abc.MutableMapping):
    """
    Nice wrapper around the archives dict, making sure only valid types/values get in
    and we can deal with str keys (and it internally encodes to byte keys) and either
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
            ts = ts.replace(tzinfo=None).strftime(ISO_FORMAT)
        assert isinstance(ts, str)
        ts = ts.encode()
        self._archives[name] = {b'id': id, b'time': ts}

    def __delitem__(self, name):
        assert isinstance(name, str)
        name = safe_encode(name)
        del self._archives[name]

    def list(self, *, glob=None, match_end=r'\Z', sort_by=(), first=None, last=None, reverse=False):
        """
        Return list of ArchiveInfo instances according to the parameters.

        First match *glob* (considering *match_end*), then *sort_by*.
        Apply *first* and *last* filters, and then possibly *reverse* the list.

        *sort_by* is a list of sort keys applied in reverse order.

        Note: for better robustness, all filtering / limiting parameters must default to
              "not limit / not filter", so a FULL archive list is produced by a simple .list().
              some callers EXPECT to iterate over all archives in a repo for correct operation.
        """
        if isinstance(sort_by, (str, bytes)):
            raise TypeError('sort_by must be a sequence of str')
        regex = re.compile(shellpattern.translate(glob or '*', match_end=match_end))
        archives = [x for x in self.values() if regex.match(x.name) is not None]
        for sortkey in reversed(sort_by):
            archives.sort(key=attrgetter(sortkey))
        if first:
            archives = archives[:first]
        elif last:
            archives = archives[max(len(archives) - last, 0):]
        if reverse:
            archives.reverse()
        return archives

    def list_considering(self, args):
        """
        get a list of archives, considering --first/last/prefix/glob-archives/sort cmdline args
        """
        if args.location.archive:
            raise Error('The options --first, --last, --prefix and --glob-archives can only be used on repository targets.')
        if args.prefix is not None:
            args.glob_archives = args.prefix + '*'
        return self.list(sort_by=args.sort_by.split(','), glob=args.glob_archives, first=args.first, last=args.last)

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
        self.archives = Archives()
        self.config = {}
        self.key = key
        self.repository = repository
        self.item_keys = frozenset(item_keys) if item_keys is not None else ITEM_KEYS
        self.tam_verified = False
        self.timestamp = None

    @property
    def id_str(self):
        return bin_to_hex(self.id)

    @property
    def last_timestamp(self):
        return parse_timestamp(self.timestamp, tzinfo=None)

    @classmethod
    def load(cls, repository, operations, key=None, force_tam_not_required=False):
        from .item import ManifestItem
        from .crypto.key import key_factory, tam_required_file, tam_required
        from .repository import Repository
        try:
            cdata = repository.get(cls.MANIFEST_ID)
        except Repository.ObjectNotFound:
            raise NoManifestError
        if not key:
            key = key_factory(repository, cdata)
        manifest = cls(key, repository)
        data = key.decrypt(None, cdata)
        manifest_dict, manifest.tam_verified = key.unpack_and_verify_manifest(data, force_tam_not_required=force_tam_not_required)
        m = ManifestItem(internal_dict=manifest_dict)
        manifest.id = key.id_hash(data)
        if m.get('version') not in (1, 2):
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
        from .item import ManifestItem
        if self.key.tam_required:
            self.config[b'tam_required'] = True
        # self.timestamp needs to be strictly monotonically increasing. Clocks often are not set correctly
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().strftime(ISO_FORMAT)
        else:
            prev_ts = self.last_timestamp
            incremented = (prev_ts + timedelta(microseconds=1)).strftime(ISO_FORMAT)
            self.timestamp = max(incremented, datetime.utcnow().strftime(ISO_FORMAT))
        # include checks for limits as enforced by limited unpacker (used by load())
        assert len(self.archives) <= MAX_ARCHIVES
        assert all(len(name) <= 255 for name in self.archives)
        assert len(self.item_keys) <= 100
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
        self.repository.put(self.MANIFEST_ID, self.key.encrypt(data))


def positive_int_validator(value):
    """argparse type for positive integers"""
    int_value = int(value)
    if int_value <= 0:
        raise argparse.ArgumentTypeError('A positive integer is required: %s' % value)
    return int_value


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


def ensure_dir(path, mode=stat.S_IRWXU, pretty_deadly=True):
    """
    Ensures that the dir exists with the right permissions.
    1) Make sure the directory exists in a race-free operation
    2) If mode is not None and the directory has been created, give the right
    permissions to the leaf directory
    3) If pretty_deadly is True, catch exceptions, reraise them with a pretty
    message.
    Returns if the directory has been created and has the right permissions,
    An exception otherwise. If a deadly exception happened it is reraised.
    """
    try:
        os.makedirs(path, mode=mode, exist_ok=True)
    except OSError as e:
        if pretty_deadly:
            raise Error(e.args[1])
        else:
            raise


def get_base_dir():
    """Get home directory / base directory for borg:

    - BORG_BASE_DIR, if set
    - HOME, if set
    - ~$USER, if USER is set
    - ~
    """
    base_dir = os.environ.get('BORG_BASE_DIR') or os.environ.get('HOME')
    # os.path.expanduser() behaves differently for '~' and '~someuser' as
    # parameters: when called with an explicit username, the possibly set
    # environment variable HOME is no longer respected. So we have to check if
    # it is set and only expand the user's home directory if HOME is unset.
    if not base_dir:
        base_dir = os.path.expanduser('~%s' % os.environ.get('USER', ''))
    return base_dir


def get_keys_dir():
    """Determine where to repository keys and cache"""

    keys_dir = os.environ.get('BORG_KEYS_DIR', os.path.join(get_config_dir(), 'keys'))
    ensure_dir(keys_dir)
    return keys_dir


def get_security_dir(repository_id=None):
    """Determine where to store local security information."""
    security_dir = os.environ.get('BORG_SECURITY_DIR', os.path.join(get_config_dir(), 'security'))
    if repository_id:
        security_dir = os.path.join(security_dir, repository_id)
    ensure_dir(security_dir)
    return security_dir


def get_cache_dir():
    """Determine where to repository keys and cache"""
    # Get cache home path
    cache_home = os.path.join(get_base_dir(), '.cache')
    # Try to use XDG_CACHE_HOME instead if BORG_BASE_DIR isn't explicitly set
    if not os.environ.get('BORG_BASE_DIR'):
        cache_home = os.environ.get('XDG_CACHE_HOME', cache_home)
    # Use BORG_CACHE_DIR if set, otherwise assemble final path from cache home path
    cache_dir = os.environ.get('BORG_CACHE_DIR', os.path.join(cache_home, 'borg'))
    # Create path if it doesn't exist yet
    ensure_dir(cache_dir)
    cache_fn = os.path.join(cache_dir, CACHE_TAG_NAME)
    if not os.path.exists(cache_fn):
        with open(cache_fn, 'wb') as fd:
            fd.write(CACHE_TAG_CONTENTS)
            fd.write(textwrap.dedent("""
            # This file is a cache directory tag created by Borg.
            # For information about cache directory tags, see:
            #       http://www.bford.info/cachedir/spec.html
            """).encode('ascii'))
    return cache_dir


def get_config_dir():
    """Determine where to store whole config"""
    # Get config home path
    config_home = os.path.join(get_base_dir(), '.config')
    # Try to use XDG_CONFIG_HOME instead if BORG_BASE_DIR isn't explicitly set
    if not os.environ.get('BORG_BASE_DIR'):
        config_home = os.environ.get('XDG_CONFIG_HOME', config_home)
    # Use BORG_CONFIG_DIR if set, otherwise assemble final path from config home path
    config_dir = os.environ.get('BORG_CONFIG_DIR', os.path.join(config_home, 'borg'))
    # Create path if it doesn't exist yet
    ensure_dir(config_dir)
    return config_dir


def to_localtime(ts):
    """Convert datetime object from UTC to local time zone"""
    return datetime(*time.localtime((ts - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds())[:6])


def parse_timestamp(timestamp, tzinfo=timezone.utc):
    """Parse a ISO 8601 timestamp string"""
    fmt = ISO_FORMAT if '.' in timestamp else ISO_FORMAT_NO_USECS
    dt = datetime.strptime(timestamp, fmt)
    if tzinfo is not None:
        dt = dt.replace(tzinfo=tzinfo)
    return dt


def timestamp(s):
    """Convert a --timestamp=s argument to a datetime object"""
    try:
        # is it pointing to a file / directory?
        ts = safe_s(os.stat(s).st_mtime)
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except OSError:
        # didn't work, try parsing as timestamp. UTC, no TZ, no microsecs support.
        for format in ('%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S+00:00',
                       '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S',
                       '%Y-%m-%dT%H:%M', '%Y-%m-%d %H:%M',
                       '%Y-%m-%d', '%Y-%j',
                       ):
            try:
                return datetime.strptime(s, format).replace(tzinfo=timezone.utc)
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


def FilesCacheMode(s):
    ENTRIES_MAP = dict(ctime='c', mtime='m', size='s', inode='i', rechunk='r', disabled='d')
    VALID_MODES = ('cis', 'ims', 'cs', 'ms', 'cr', 'mr', 'd', 's')  # letters in alpha order
    entries = set(s.strip().split(','))
    if not entries <= set(ENTRIES_MAP):
        raise ValueError('cache mode must be a comma-separated list of: %s' % ','.join(sorted(ENTRIES_MAP)))
    short_entries = {ENTRIES_MAP[entry] for entry in entries}
    mode = ''.join(sorted(short_entries))
    if mode not in VALID_MODES:
        raise ValueError('cache mode short must be one of: %s' % ','.join(VALID_MODES))
    return mode


assert FilesCacheMode(DEFAULT_FILES_CACHE_MODE_UI) == DEFAULT_FILES_CACHE_MODE  # keep these 2 values in sync!


def dir_is_cachedir(path):
    """Determines whether the specified path is a cache directory (and
    therefore should potentially be excluded from the backup) according to
    the CACHEDIR.TAG protocol
    (http://www.bford.info/cachedir/spec.html).
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
    directory or containing user-specified tag files/directories. Returns a
    list of the paths of the tag files/directories (either CACHEDIR.TAG or the
    matching user-specified files/directories).
    """
    tag_paths = []
    if exclude_caches and dir_is_cachedir(path):
        tag_paths.append(os.path.join(path, CACHE_TAG_NAME))
    if exclude_if_present is not None:
        for tag in exclude_if_present:
            tag_path = os.path.join(path, tag)
            if os.path.exists(tag_path):
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
            format_spec = ISO_FORMAT_NO_USECS
        return self.dt.__format__(format_spec)


def format_line(format, data):
    for _, key, _, conversion in Formatter().parse(format):
        if not key:
            continue
        if conversion or key not in data:
            raise InvalidPlaceholder(key, format)
    try:
        return format.format_map(data)
    except Exception as e:
        raise PlaceholderError(format, data, e.__class__.__name__, str(e))


def replace_placeholders(text, overrides={}):
    """Replace placeholders in text with their values."""
    from .platform import fqdn, hostname
    current_time = datetime.now(timezone.utc)
    data = {
        'pid': os.getpid(),
        'fqdn': fqdn,
        'reverse-fqdn': '.'.join(reversed(fqdn.split('.'))),
        'hostname': hostname,
        'now': DatetimeWrapper(current_time.astimezone(None)),
        'utcnow': DatetimeWrapper(current_time),
        'user': uid2user(os.getuid(), os.getuid()),
        'uuid4': str(uuid.uuid4()),
        'borgversion': borg_version,
        'borgmajor': '%d' % borg_version_tuple[:1],
        'borgminor': '%d.%d' % borg_version_tuple[:2],
        'borgpatch': '%d.%d.%d' % borg_version_tuple[:3],
        **overrides,
    }
    return format_line(text, data)


PrefixSpec = replace_placeholders

GlobSpec = replace_placeholders

CommentSpec = replace_placeholders

HUMAN_SORT_KEYS = ['timestamp'] + list(ArchiveInfo._fields)
HUMAN_SORT_KEYS.remove('ts')


def SortBySpec(text):
    for token in text.split(','):
        if token not in HUMAN_SORT_KEYS:
            raise ValueError('Invalid sort key: %s' % token)
    return text.replace('timestamp', 'ts')


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
    t_ns = safe_ns(item_timestamp_ns)
    return datetime.fromtimestamp(t_ns / 1e9)


def format_time(ts: datetime, format_spec=''):
    """
    Convert *ts* to a human-friendly format with textual weekday.
    """
    return ts.strftime('%a, %Y-%m-%d %H:%M:%S' if format_spec == '' else format_spec)


def isoformat_time(ts: datetime):
    """
    Format *ts* according to ISO 8601.
    """
    # note: first make all datetime objects tz aware before adding %z here.
    return ts.strftime(ISO_FORMAT)


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


class OutputTimestamp:
    def __init__(self, ts: datetime):
        if ts.tzinfo == timezone.utc:
            ts = to_localtime(ts)
        self.ts = ts

    def __format__(self, format_spec):
        return format_time(self.ts, format_spec=format_spec)

    def __str__(self):
        return '{}'.format(self)

    def isoformat(self):
        return isoformat_time(self.ts)

    to_json = isoformat


def format_file_size(v, precision=2, sign=False):
    """Format file size into a human friendly format
    """
    return sizeof_fmt_decimal(v, suffix='B', sep=' ', precision=precision, sign=sign)


class FileSize(int):
    def __format__(self, format_spec):
        return format_file_size(int(self)).__format__(format_spec)


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
    managed buffer (like a resizable bytearray)
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
        self.allocator = allocator
        self.limit = limit
        self.resize(size, init=True)

    def __len__(self):
        return len(self.buffer)

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
            self.buffer = self.allocator(size)

    def get(self, size=None, init=False):
        """
        return a buffer of at least the requested size (None: any current size).
        init=True can be given to trigger shrinking of the buffer to the given size.
        """
        if size is not None:
            self.resize(size, init)
        return self.buffer


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

    # note: scp_re is also use for local paths
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

    def __init__(self, text='', overrides={}):
        if not self.parse(text, overrides):
            raise ValueError('Invalid location format: "%s"' % self.orig)

    def parse(self, text, overrides={}):
        self.orig = text
        text = replace_placeholders(text, overrides)
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
        self.archive = m.group('archive')
        self.orig = repo if not self.archive else '%s::%s' % (repo, self.archive)
        return valid

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
        name = re.sub(r'[^\w]', '_', self.path).strip('_')
        if self.proto != 'file':
            name = re.sub(r'[^\w]', '_', self.host) + '__' + name
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

    def with_timestamp(self, timestamp):
        return Location(self.orig, overrides={
            'now': DatetimeWrapper(timestamp.astimezone(None)),
            'utcnow': DatetimeWrapper(timestamp),
        })


def location_validator(archive=None, proto=None):
    def validator(text):
        try:
            loc = Location(text)
        except ValueError as err:
            raise argparse.ArgumentTypeError(str(err)) from None
        if archive is True and not loc.archive:
            raise argparse.ArgumentTypeError('"%s": No archive specified' % text)
        elif archive is False and loc.archive:
            raise argparse.ArgumentTypeError('"%s": No archive can be specified' % text)
        if proto is not None and loc.proto != proto:
            if proto == 'file':
                raise argparse.ArgumentTypeError('"%s": Repository must be local' % text)
            else:
                raise argparse.ArgumentTypeError('"%s": Repository must be remote' % text)
        return loc
    return validator


def archivename_validator():
    def validator(text):
        text = replace_placeholders(text)
        if '/' in text or '::' in text or not text:
            raise argparse.ArgumentTypeError('Invalid archive name: "%s"' % text)
        return text
    return validator


def decode_dict(d, keys, encoding='utf-8', errors='surrogateescape'):
    for key in keys:
        if isinstance(d.get(key), bytes):
            d[key] = d[key].decode(encoding, errors)
    return d


def prepare_dump_dict(d):
    def decode_bytes(value):
        # this should somehow be reversible later, but usual strings should
        # look nice and chunk ids should mostly show in hex. Use a special
        # inband signaling character (ASCII DEL) to distinguish between
        # decoded and hex mode.
        if not value.startswith(b'\x7f'):
            try:
                value = value.decode()
                return value
            except UnicodeDecodeError:
                pass
        return '\u007f' + bin_to_hex(value)

    def decode_tuple(t):
        res = []
        for value in t:
            if isinstance(value, dict):
                value = decode(value)
            elif isinstance(value, tuple) or isinstance(value, list):
                value = decode_tuple(value)
            elif isinstance(value, bytes):
                value = decode_bytes(value)
            res.append(value)
        return res

    def decode(d):
        res = collections.OrderedDict()
        for key, value in d.items():
            if isinstance(value, dict):
                value = decode(value)
            elif isinstance(value, (tuple, list)):
                value = decode_tuple(value)
            elif isinstance(value, bytes):
                value = decode_bytes(value)
            if isinstance(key, bytes):
                key = key.decode()
            res[key] = value
        return res

    return decode(d)


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

    Returns: old and new get_process_id tuples
    """
    from .platform import get_process_id
    old_id = get_process_id()
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
    new_id = get_process_id()
    return old_id, new_id


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
    return msgpack.Packer is msgpack_fallback.Packer


def is_supported_msgpack():
    # DO NOT CHANGE OR REMOVE! See also requirements and comments in setup.py.
    v = msgpack.version[:3]
    return (0, 4, 6) <= v <= (0, 5, 6) and \
           v not in [(0, 5, 0), (0, 5, 2), (0, 5, 3), (0, 5, 5)]


FALSISH = ('No', 'NO', 'no', 'N', 'n', '0', )
TRUISH = ('Yes', 'YES', 'yes', 'Y', 'y', '1', )
DEFAULTISH = ('Default', 'DEFAULT', 'default', 'D', 'd', '', )


def yes(msg=None, false_msg=None, true_msg=None, default_msg=None,
        retry_msg=None, invalid_msg=None, env_msg='{} (from {})',
        falsish=FALSISH, truish=TRUISH, defaultish=DEFAULTISH,
        default=False, retry=True, env_var_override=None, ofile=None, input=input, prompt=True,
        msgid=None):
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
    def output(msg, msg_type, is_prompt=False, **kwargs):
        json_output = getattr(logging.getLogger('borg'), 'json', False)
        if json_output:
            kwargs.update(dict(
                type='question_%s' % msg_type,
                msgid=msgid,
                message=msg,
            ))
            print(json.dumps(kwargs), file=sys.stderr)
        else:
            if is_prompt:
                print(msg, file=ofile, end='', flush=True)
            else:
                print(msg, file=ofile)

    msgid = msgid or env_var_override
    # note: we do not assign sys.stderr as default above, so it is
    # really evaluated NOW,  not at function definition time.
    if ofile is None:
        ofile = sys.stderr
    if default not in (True, False):
        raise ValueError("invalid default value, must be True or False")
    if msg:
        output(msg, 'prompt', is_prompt=True)
    while True:
        answer = None
        if env_var_override:
            answer = os.environ.get(env_var_override)
            if answer is not None and env_msg:
                output(env_msg.format(answer, env_var_override), 'env_answer', env_var=env_var_override)
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
                output(default_msg, 'accepted_default')
            return default
        if answer in truish:
            if true_msg:
                output(true_msg, 'accepted_true')
            return True
        if answer in falsish:
            if false_msg:
                output(false_msg, 'accepted_false')
            return False
        # if we get here, the answer was invalid
        if invalid_msg:
            output(invalid_msg, 'invalid_answer')
        if not retry:
            return default
        if retry_msg:
            output(retry_msg, 'prompt_retry', is_prompt=True)
        # in case we used an environment variable and it gave an invalid answer, do not use it again:
        env_var_override = None


def hostname_is_unique():
    return yes(env_var_override='BORG_HOSTNAME_IS_UNIQUE', prompt=False, env_msg=None, default=True)


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
    JSON_TYPE = None
    json = False

    operation_id_counter = 0

    @classmethod
    def operation_id(cls):
        """Unique number, can be used by receiving applications to distinguish different operations."""
        cls.operation_id_counter += 1
        return cls.operation_id_counter

    def __init__(self, msgid=None):
        self.handler = None
        self.logger = logging.getLogger(self.LOGGER)
        self.id = self.operation_id()
        self.msgid = msgid

        # If there are no handlers, set one up explicitly because the
        # terminator and propagation needs to be set.  If there are,
        # they must have been set up by BORG_LOGGING_CONF: skip setup.
        if not self.logger.handlers:
            self.handler = logging.StreamHandler(stream=sys.stderr)
            self.handler.setLevel(logging.INFO)
            logger = logging.getLogger('borg')
            # Some special attributes on the borg logger, created by setup_logging
            # But also be able to work without that
            try:
                formatter = logger.formatter
                terminator = '\n' if logger.json else '\r'
                self.json = logger.json
            except AttributeError:
                terminator = '\r'
            else:
                self.handler.setFormatter(formatter)
            self.handler.terminator = terminator

            self.logger.addHandler(self.handler)
            if self.logger.level == logging.NOTSET:
                self.logger.setLevel(logging.WARN)
            self.logger.propagate = False

        # If --progress is not set then the progress logger level will be WARN
        # due to setup_implied_logging (it may be NOTSET with a logging config file,
        # but the interactions there are generally unclear), so self.emit becomes
        # False, which is correct.
        # If --progress is set then the level will be INFO as per setup_implied_logging;
        # note that this is always the case for serve processes due to a "args.progress |= is_serve".
        # In this case self.emit is True.
        self.emit = self.logger.getEffectiveLevel() == logging.INFO

    def __del__(self):
        if self.handler is not None:
            self.logger.removeHandler(self.handler)
            self.handler.close()

    def output_json(self, *, finished=False, **kwargs):
        assert self.json
        if not self.emit:
            return
        kwargs.update(dict(
            operation=self.id,
            msgid=self.msgid,
            type=self.JSON_TYPE,
            finished=finished,
            time=time.time(),
        ))
        print(json.dumps(kwargs), file=sys.stderr, flush=True)

    def finish(self):
        if self.json:
            self.output_json(finished=True)
        else:
            self.output('')


def justify_to_terminal_size(message):
    terminal_space = get_terminal_size(fallback=(-1, -1))[0]
    # justify only if we are outputting to a terminal
    if terminal_space != -1:
        return message.ljust(terminal_space)
    return message


class ProgressIndicatorMessage(ProgressIndicatorBase):
    JSON_TYPE = 'progress_message'

    def output(self, msg):
        if self.json:
            self.output_json(message=msg)
        else:
            self.logger.info(justify_to_terminal_size(msg))


class ProgressIndicatorPercent(ProgressIndicatorBase):
    JSON_TYPE = 'progress_percent'

    def __init__(self, total=0, step=5, start=0, msg="%3.0f%%", msgid=None):
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

        super().__init__(msgid=msgid)

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
                if not self.json:
                    # no need to truncate if we're not outputting to a terminal
                    terminal_space = get_terminal_size(fallback=(-1, -1))[0]
                    if terminal_space != -1:
                        space = terminal_space - len(self.msg % tuple([pct] + info[:-1] + ['']))
                        info[-1] = ellipsis_truncate(info[-1], space)
                return self.output(self.msg % tuple([pct] + info), justify=False, info=info)

            return self.output(self.msg % pct)

    def output(self, message, justify=True, info=None):
        if self.json:
            self.output_json(message=message, current=self.counter, total=self.total, info=info)
        else:
            if justify:
                message = justify_to_terminal_size(message)
            self.logger.info(message)


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
    show_sysinfo = os.environ.get('BORG_SHOW_SYSINFO', 'yes').lower()
    if show_sysinfo == 'no':
        return ''

    python_implementation = platform.python_implementation()
    python_version = platform.python_version()
    # platform.uname() does a shell call internally to get processor info,
    # creating #3732 issue, so rather use os.uname().
    try:
        uname = os.uname()
    except AttributeError:
        uname = None
    if sys.platform.startswith('linux'):
        try:
            linux_distribution = platform.linux_distribution()
        except:
            # platform.linux_distribution() is deprecated since py 3.5 and removed in 3.7.
            linux_distribution = ('Unknown Linux', '', '')
    else:
        linux_distribution = None
    try:
        msgpack_version = '.'.join(str(v) for v in msgpack.version)
    except:
        msgpack_version = 'unknown'
    info = []
    if uname is not None:
        info.append('Platform: %s' % (' '.join(uname), ))
    if linux_distribution is not None:
        info.append('Linux: %s %s %s' % linux_distribution)
    info.append('Borg: %s  Python: %s %s msgpack: %s' % (
                borg_version, python_implementation, python_version, msgpack_version))
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
        return "- NEWLINE: OS dependent line separator\n" \
               "- NL: alias of NEWLINE\n" \
               "- NUL: NUL character for creating print0 / xargs -0 like output, see barchive/bpath\n" \
               "- SPACE\n" \
               "- TAB\n" \
               "- CR\n" \
               "- LF"


class ArchiveFormatter(BaseFormatter):
    KEY_DESCRIPTIONS = {
        'archive': 'archive name interpreted as text (might be missing non-text characters, see barchive)',
        'name': 'alias of "archive"',
        'barchive': 'verbatim archive name, can contain any character except NUL',
        'comment': 'archive comment interpreted as text (might be missing non-text characters, see bcomment)',
        'bcomment': 'verbatim archive comment, can contain any character except NUL',
        # *start* is the key used by borg-info for this timestamp, this makes the formats more compatible
        'start': 'time (start) of creation of the archive',
        'time': 'alias of "start"',
        'end': 'time (end) of creation of the archive',
        'id': 'internal ID of the archive',
        'hostname': 'hostname of host on which this archive was created',
        'username': 'username of user who created this archive',
    }
    KEY_GROUPS = (
        ('archive', 'name', 'barchive', 'comment', 'bcomment', 'id'),
        ('start', 'time', 'end'),
        ('hostname', 'username'),
    )

    @classmethod
    def available_keys(cls):
        fake_archive_info = ArchiveInfo('archivename', b'\1'*32, datetime(1970, 1, 1, tzinfo=timezone.utc))
        formatter = cls('', None, None, None)
        keys = []
        keys.extend(formatter.call_keys.keys())
        keys.extend(formatter.get_item_data(fake_archive_info).keys())
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
                text = "- " + key
                if key in cls.KEY_DESCRIPTIONS:
                    text += ": " + cls.KEY_DESCRIPTIONS[key]
                help.append(text)
            help.append("")
        assert not keys, str(keys)
        return "\n".join(help)

    def __init__(self, format, repository, manifest, key, *, json=False):
        self.repository = repository
        self.manifest = manifest
        self.key = key
        self.name = None
        self.id = None
        self._archive = None
        self.json = json
        static_keys = {}  # here could be stuff on repo level, above archive level
        static_keys.update(self.FIXED_KEYS)
        self.format = partial_format(format, static_keys)
        self.format_keys = {f[1] for f in Formatter().parse(format)}
        self.call_keys = {
            'hostname': partial(self.get_meta, 'hostname', rs=True),
            'username': partial(self.get_meta, 'username', rs=True),
            'comment': partial(self.get_meta, 'comment', rs=True),
            'bcomment': partial(self.get_meta, 'comment', rs=False),
            'end': self.get_ts_end,
        }
        self.used_call_keys = set(self.call_keys) & self.format_keys
        if self.json:
            self.item_data = {}
            self.format_item = self.format_item_json
        else:
            self.item_data = static_keys

    def format_item_json(self, item):
        return json.dumps(self.get_item_data(item), cls=BorgJsonEncoder) + '\n'

    def get_item_data(self, archive_info):
        self.name = archive_info.name
        self.id = archive_info.id
        item_data = {}
        item_data.update(self.item_data)
        item_data.update({
            'name': remove_surrogates(archive_info.name),
            'archive': remove_surrogates(archive_info.name),
            'barchive': archive_info.name,
            'id': bin_to_hex(archive_info.id),
            'time': self.format_time(archive_info.ts),
            'start': self.format_time(archive_info.ts),
        })
        for key in self.used_call_keys:
            item_data[key] = self.call_keys[key]()
        return item_data

    @property
    def archive(self):
        """lazy load / update loaded archive"""
        if self._archive is None or self._archive.id != self.id:
            from .archive import Archive
            self._archive = Archive(self.repository, self.key, self.manifest, self.name)
        return self._archive

    def get_meta(self, key, rs):
        value = self.archive.metadata.get(key, '')
        return remove_surrogates(value) if rs else value

    def get_ts_end(self):
        return self.format_time(self.archive.ts_end)

    def format_time(self, ts):
        return OutputTimestamp(ts)


class ItemFormatter(BaseFormatter):
    KEY_DESCRIPTIONS = {
        'bpath': 'verbatim POSIX path, can contain any character except NUL',
        'path': 'path interpreted as text (might be missing non-text characters, see bpath)',
        'source': 'link target for links (identical to linktarget)',
        'extra': 'prepends {source} with " -> " for soft links and " link to " for hard links',
        'csize': 'compressed size',
        'dsize': 'deduplicated size',
        'dcsize': 'deduplicated compressed size',
        'num_chunks': 'number of chunks in this file',
        'unique_chunks': 'number of unique chunks in this file',
        'health': 'either "healthy" (file ok) or "broken" (if file has all-zero replacement chunks)',
    }
    KEY_GROUPS = (
        ('type', 'mode', 'uid', 'gid', 'user', 'group', 'path', 'bpath', 'source', 'linktarget', 'flags'),
        ('size', 'csize', 'dsize', 'dcsize', 'num_chunks', 'unique_chunks'),
        ('mtime', 'ctime', 'atime', 'isomtime', 'isoctime', 'isoatime'),
        tuple(sorted(hashlib.algorithms_guaranteed)),
        ('archiveid', 'archivename', 'extra'),
        ('health', )
    )

    KEYS_REQUIRING_CACHE = (
        'dsize', 'dcsize', 'unique_chunks',
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
                text = "- " + key
                if key in cls.KEY_DESCRIPTIONS:
                    text += ": " + cls.KEY_DESCRIPTIONS[key]
                help.append(text)
            help.append("")
        assert not keys, str(keys)
        return "\n".join(help)

    @classmethod
    def format_needs_cache(cls, format):
        format_keys = {f[1] for f in Formatter().parse(format)}
        return any(key in cls.KEYS_REQUIRING_CACHE for key in format_keys)

    def __init__(self, archive, format, *, json_lines=False):
        self.archive = archive
        self.json_lines = json_lines
        static_keys = {
            'archivename': archive.name,
            'archiveid': archive.fpr,
        }
        static_keys.update(self.FIXED_KEYS)
        if self.json_lines:
            self.item_data = {}
            self.format_item = self.format_item_json
        else:
            self.item_data = static_keys
        self.format = partial_format(format, static_keys)
        self.format_keys = {f[1] for f in Formatter().parse(format)}
        self.call_keys = {
            'size': self.calculate_size,
            'csize': self.calculate_csize,
            'dsize': partial(self.sum_unique_chunks_metadata, lambda chunk: chunk.size),
            'dcsize': partial(self.sum_unique_chunks_metadata, lambda chunk: chunk.csize),
            'num_chunks': self.calculate_num_chunks,
            'unique_chunks': partial(self.sum_unique_chunks_metadata, lambda chunk: 1),
            'isomtime': partial(self.format_iso_time, 'mtime'),
            'isoctime': partial(self.format_iso_time, 'ctime'),
            'isoatime': partial(self.format_iso_time, 'atime'),
            'mtime': partial(self.format_time, 'mtime'),
            'ctime': partial(self.format_time, 'ctime'),
            'atime': partial(self.format_time, 'atime'),
        }
        for hash_function in hashlib.algorithms_guaranteed:
            self.add_key(hash_function, partial(self.hash_item, hash_function))
        self.used_call_keys = set(self.call_keys) & self.format_keys

    def format_item_json(self, item):
        return json.dumps(self.get_item_data(item), cls=BorgJsonEncoder) + '\n'

    def add_key(self, key, callable_with_item):
        self.call_keys[key] = callable_with_item
        self.used_call_keys = set(self.call_keys) & self.format_keys

    def get_item_data(self, item):
        item_data = {}
        item_data.update(self.item_data)
        mode = stat.filemode(item.mode)
        item_type = mode[0]

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
        if self.json_lines:
            item_data['healthy'] = 'chunks_healthy' not in item
        else:
            item_data['bpath'] = item.path
            item_data['extra'] = extra
            item_data['health'] = 'broken' if 'chunks_healthy' in item else 'healthy'
        item_data['source'] = source
        item_data['linktarget'] = source
        item_data['flags'] = item.get('bsdflags')
        for key in self.used_call_keys:
            item_data[key] = self.call_keys[key](item)
        return item_data

    def sum_unique_chunks_metadata(self, metadata_func, item):
        """
        sum unique chunks metadata, a unique chunk is a chunk which is referenced globally as often as it is in the
        item

        item: The item to sum its unique chunks' metadata
        metadata_func: A function that takes a parameter of type ChunkIndexEntry and returns a number, used to return
                       the metadata needed from the chunk
        """
        chunk_index = self.archive.cache.chunks
        chunks = item.get('chunks', [])
        chunks_counter = Counter(c.id for c in chunks)
        return sum(metadata_func(c) for c in chunks if chunk_index[c.id].refcount == chunks_counter[c.id])

    def calculate_num_chunks(self, item):
        return len(item.get('chunks', []))

    def calculate_size(self, item):
        # note: does not support hardlink slaves, they will be size 0
        return item.get_size(compressed=False)

    def calculate_csize(self, item):
        # note: does not support hardlink slaves, they will be csize 0
        return item.get_size(compressed=True)

    def hash_item(self, hash_function, item):
        if 'chunks' not in item:
            return ""
        hash = hashlib.new(hash_function)
        for data in self.archive.pipeline.fetch_many([c.id for c in item.chunks]):
            hash.update(data)
        return hash.hexdigest()

    def format_time(self, key, item):
        return OutputTimestamp(safe_timestamp(item.get(key) or item.mtime))

    def format_iso_time(self, key, item):
        return self.format_time(key, item).isoformat()


class ChunkIteratorFileWrapper:
    """File-like wrapper for chunk iterators"""

    def __init__(self, chunk_iterator, read_callback=None):
        """
        *chunk_iterator* should be an iterator yielding bytes. These will be buffered
        internally as necessary to satisfy .read() calls.

        *read_callback* will be called with one argument, some byte string that has
        just been read and will be subsequently returned to a caller of .read().
        It can be used to update a progress display.
        """
        self.chunk_iterator = chunk_iterator
        self.chunk_offset = 0
        self.chunk = b''
        self.exhausted = False
        self.read_callback = read_callback

    def _refill(self):
        remaining = len(self.chunk) - self.chunk_offset
        if not remaining:
            try:
                chunk = next(self.chunk_iterator)
                self.chunk = memoryview(chunk)
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
            if self.read_callback:
                self.read_callback(read_data)
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


def hardlinkable(mode):
    """return True if we support hardlinked items of this type"""
    return stat.S_ISREG(mode) or stat.S_ISBLK(mode) or stat.S_ISCHR(mode) or stat.S_ISFIFO(mode)


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


def scandir_keyfunc(dirent):
    try:
        return (0, dirent.inode())
    except OSError as e:
        # maybe a permission denied error while doing a stat() on the dirent
        logger.debug('scandir_inorder: Unable to stat %s: %s', dirent.path, e)
        # order this dirent after all the others lexically by file name
        # we may not break the whole scandir just because of an exception in one dirent
        # ignore the exception for now, since another stat will be done later anyways
        # (or the entry will be skipped by an exclude pattern)
        return (1, dirent.name)


def scandir_inorder(path='.'):
    return sorted(scandir(path), key=scandir_keyfunc)


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


class BorgJsonEncoder(json.JSONEncoder):
    def default(self, o):
        from .repository import Repository
        from .remote import RemoteRepository
        from .archive import Archive
        from .cache import LocalCache, AdHocCache
        if isinstance(o, Repository) or isinstance(o, RemoteRepository):
            return {
                'id': bin_to_hex(o.id),
                'location': o._location.canonical_path(),
            }
        if isinstance(o, Archive):
            return o.info()
        if isinstance(o, LocalCache):
            return {
                'path': o.path,
                'stats': o.stats(),
            }
        if isinstance(o, AdHocCache):
            return {
                'stats': o.stats(),
            }
        if callable(getattr(o, 'to_json', None)):
            return o.to_json()
        return super().default(o)


def basic_json_data(manifest, *, cache=None, extra=None):
    key = manifest.key
    data = extra or {}
    data.update({
        'repository': BorgJsonEncoder().default(manifest.repository),
        'encryption': {
            'mode': key.ARG_NAME,
        },
    })
    data['repository']['last_modified'] = OutputTimestamp(manifest.last_timestamp.replace(tzinfo=timezone.utc))
    if key.NAME.startswith('key file'):
        data['encryption']['keyfile'] = key.find_key()
    if cache:
        data['cache'] = cache
    return data


def json_dump(obj):
    """Dump using BorgJSONEncoder."""
    return json.dumps(obj, sort_keys=True, indent=4, cls=BorgJsonEncoder)


def json_print(obj):
    print(json_dump(obj))


def secure_erase(path):
    """Attempt to securely erase a file by writing random data over it before deleting it."""
    with open(path, 'r+b') as fd:
        length = os.stat(fd.fileno()).st_size
        fd.write(os.urandom(length))
        fd.flush()
        os.fsync(fd.fileno())
    os.unlink(path)


def truncate_and_unlink(path):
    """
    Truncate and then unlink *path*.

    Do not create *path* if it does not exist.
    Open *path* for truncation in r+b mode (=O_RDWR|O_BINARY).

    Use this when deleting potentially large files when recovering
    from a VFS error such as ENOSPC. It can help a full file system
    recover. Refer to the "File system interaction" section
    in repository.py for further explanations.
    """
    try:
        with open(path, 'r+b') as fd:
            fd.truncate()
    except OSError as err:
        if err.errno != errno.ENOTSUP:
            raise
        # don't crash if the above ops are not supported.
    os.unlink(path)


def popen_with_error_handling(cmd_line: str, log_prefix='', **kwargs):
    """
    Handle typical errors raised by subprocess.Popen. Return None if an error occurred,
    otherwise return the Popen object.

    *cmd_line* is split using shlex (e.g. 'gzip -9' => ['gzip', '-9']).

    Log messages will be prefixed with *log_prefix*; if set, it should end with a space
    (e.g. log_prefix='--some-option: ').

    Does not change the exit code.
    """
    assert not kwargs.get('shell'), 'Sorry pal, shell mode is a no-no'
    try:
        command = shlex.split(cmd_line)
        if not command:
            raise ValueError('an empty command line is not permitted')
    except ValueError as ve:
        logger.error('%s%s', log_prefix, ve)
        return
    logger.debug('%scommand line: %s', log_prefix, command)
    try:
        return subprocess.Popen(command, **kwargs)
    except FileNotFoundError:
        logger.error('%sexecutable not found: %s', log_prefix, command[0])
        return
    except PermissionError:
        logger.error('%spermission denied: %s', log_prefix, command[0])
        return


def prepare_subprocess_env(system, env=None):
    """
    Prepare the environment for a subprocess we are going to create.

    :param system: True for preparing to invoke system-installed binaries,
                   False for stuff inside the pyinstaller environment (like borg, python).
    :param env: optionally give a environment dict here. if not given, default to os.environ.
    :return: a modified copy of the environment
    """
    env = dict(env if env is not None else os.environ)
    if system:
        # a pyinstaller binary's bootloader modifies LD_LIBRARY_PATH=/tmp/_MEIXXXXXX,
        # but we do not want that system binaries (like ssh or other) pick up
        # (non-matching) libraries from there.
        # thus we install the original LDLP, before pyinstaller has modified it:
        lp_key = 'LD_LIBRARY_PATH'
        lp_orig = env.get(lp_key + '_ORIG')
        if lp_orig is not None:
            env[lp_key] = lp_orig
        else:
            # We get here in 2 cases:
            # 1. when not running a pyinstaller-made binary.
            #    in this case, we must not kill LDLP.
            # 2. when running a pyinstaller-made binary and there was no LDLP
            #    in the original env (in this case, the pyinstaller bootloader
            #    does *not* put ..._ORIG into the env either).
            #    in this case, we must kill LDLP.
            #    We can recognize this via sys.frozen and sys._MEIPASS being set.
            lp = env.get(lp_key)
            if lp is not None and getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
                env.pop(lp_key)
    # security: do not give secrets to subprocess
    env.pop('BORG_PASSPHRASE', None)
    # for information, give borg version to the subprocess
    env['BORG_VERSION'] = borg_version
    return env


def dash_open(path, mode):
    assert '+' not in mode  # the streams are either r or w, but never both
    if path == '-':
        stream = sys.stdin if 'r' in mode else sys.stdout
        return stream.buffer if 'b' in mode else stream
    else:
        return open(path, mode)


def is_terminal(fd=sys.stdout):
    return hasattr(fd, 'isatty') and fd.isatty() and (sys.platform != 'win32' or 'ANSICON' in os.environ)


def umount(mountpoint):
    env = prepare_subprocess_env(system=True)
    try:
        return subprocess.call(['fusermount', '-u', mountpoint], env=env)
    except FileNotFoundError:
        return subprocess.call(['umount', mountpoint], env=env)

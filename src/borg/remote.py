import errno
import fcntl
import functools
import inspect
import json
import logging
import os
import select
import shlex
import shutil
import struct
import sys
import tempfile
import textwrap
import time
import traceback
from subprocess import Popen, PIPE

import msgpack

from . import __version__
from .compress import LZ4
from .helpers import Error, IntegrityError
from .helpers import bin_to_hex
from .helpers import get_home_dir
from .helpers import hostname_is_unique
from .helpers import replace_placeholders
from .helpers import sysinfo
from .helpers import format_file_size
from .helpers import truncate_and_unlink
from .logger import create_logger, setup_logging
from .repository import Repository, MAX_OBJECT_SIZE, LIST_SCAN_LIMIT
from .version import parse_version, format_version
from .algorithms.checksums import xxh64

logger = create_logger(__name__)

RPC_PROTOCOL_VERSION = 2
BORG_VERSION = parse_version(__version__)
MSGID, MSG, ARGS, RESULT = b'i', b'm', b'a', b'r'

BUFSIZE = 10 * 1024 * 1024

MAX_INFLIGHT = 100

RATELIMIT_PERIOD = 0.1


def os_write(fd, data):
    """os.write wrapper so we do not lose data for partial writes."""
    # TODO: this issue is fixed in cygwin since at least 2.8.0, remove this
    #       wrapper / workaround when this version is considered ancient.
    # This is happening frequently on cygwin due to its small pipe buffer size of only 64kiB
    # and also due to its different blocking pipe behaviour compared to Linux/*BSD.
    # Neither Linux nor *BSD ever do partial writes on blocking pipes, unless interrupted by a
    # signal, in which case serve() would terminate.
    amount = remaining = len(data)
    while remaining:
        count = os.write(fd, data)
        remaining -= count
        if not remaining:
            break
        data = data[count:]
        time.sleep(count * 1e-09)
    return amount


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
    else:
        raise ValueError('kind must be "server" or "client"')
    return msgpack.Unpacker(**args)


class ConnectionClosed(Error):
    """Connection closed by remote host"""


class ConnectionClosedWithHint(ConnectionClosed):
    """Connection closed by remote host. {}"""


class PathNotAllowed(Error):
    """Repository path not allowed: {}"""


class InvalidRPCMethod(Error):
    """RPC method {} is not valid"""


class UnexpectedRPCDataFormatFromClient(Error):
    """Borg {}: Got unexpected RPC data format from client."""


class UnexpectedRPCDataFormatFromServer(Error):
    """Got unexpected RPC data format from server:\n{}"""

    def __init__(self, data):
        try:
            data = data.decode()[:128]
        except UnicodeDecodeError:
            data = data[:128]
            data = ['%02X' % byte for byte in data]
            data = textwrap.fill(' '.join(data), 16 * 3)
        super().__init__(data)


# Protocol compatibility:
# In general the server is responsible for rejecting too old clients and the client it responsible for rejecting
# too old servers. This ensures that the knowledge what is compatible is always held by the newer component.
#
# The server can do checks for the client version in RepositoryServer.negotiate. If the client_data is 2 then
# client is in the version range [0.29.0, 1.0.x] inclusive. For newer clients client_data is a dict which contains
# client_version.
#
# For the client the return of the negotiate method is either 2 if the server is in the version range [0.29.0, 1.0.x]
# inclusive, or it is a dict which includes the server version.
#
# All method calls on the remote repository object must be whitelisted in RepositoryServer.rpc_methods and have api
# stubs in RemoteRepository. The @api decorator on these stubs is used to set server version requirements.
#
# Method parameters are identified only by name and never by position. Unknown parameters are ignored by the server side.
# If a new parameter is important and may not be ignored, on the client a parameter specific version requirement needs
# to be added.
# When parameters are removed, they need to be preserved as defaulted parameters on the client stubs so that older
# servers still get compatible input.


compatMap = {
    'check': ('repair', 'save_space', ),
    'commit': ('save_space', ),
    'rollback': (),
    'destroy': (),
    '__len__': (),
    'list': ('limit', 'marker', ),
    'put': ('id', 'data', ),
    'get': ('id', ),
    'delete': ('id', ),
    'save_key': ('keydata', ),
    'load_key': (),
    'break_lock': (),
    'negotiate': ('client_data', ),
    'open': ('path', 'create', 'lock_wait', 'lock', 'exclusive', 'append_only', ),
    'get_free_nonce': (),
    'commit_nonce_reservation': ('next_unreserved', 'start_nonce', ),
}


def decode_keys(d):
    return {k.decode(): d[k] for k in d}


class RepositoryServer:  # pragma: no cover
    rpc_methods = (
        '__len__',
        'check',
        'commit',
        'delete',
        'destroy',
        'get',
        'list',
        'scan',
        'negotiate',
        'open',
        'put',
        'rollback',
        'save_key',
        'load_key',
        'break_lock',
        'get_free_nonce',
        'commit_nonce_reservation',
        'inject_exception',
    )

    def __init__(self, restrict_to_paths, restrict_to_repositories, append_only, storage_quota):
        self.repository = None
        self.restrict_to_paths = restrict_to_paths
        self.restrict_to_repositories = restrict_to_repositories
        # This flag is parsed from the serve command line via Archiver.do_serve,
        # i.e. it reflects local system policy and generally ranks higher than
        # whatever the client wants, except when initializing a new repository
        # (see RepositoryServer.open below).
        self.append_only = append_only
        self.storage_quota = storage_quota
        self.client_version = parse_version('1.0.8')  # fallback version if client is too old to send version information

    def positional_to_named(self, method, argv):
        """Translate from positional protocol to named protocol."""
        return {name: argv[pos] for pos, name in enumerate(compatMap[method])}

    def filter_args(self, f, kwargs):
        """Remove unknown named parameters from call, because client did (implicitly) say it's ok."""
        known = set(inspect.signature(f).parameters)
        return {name: kwargs[name] for name in kwargs if name in known}

    def serve(self):
        stdin_fd = sys.stdin.fileno()
        stdout_fd = sys.stdout.fileno()
        stderr_fd = sys.stdout.fileno()
        # Make stdin non-blocking
        fl = fcntl.fcntl(stdin_fd, fcntl.F_GETFL)
        fcntl.fcntl(stdin_fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        # Make stdout blocking
        fl = fcntl.fcntl(stdout_fd, fcntl.F_GETFL)
        fcntl.fcntl(stdout_fd, fcntl.F_SETFL, fl & ~os.O_NONBLOCK)
        # Make stderr blocking
        fl = fcntl.fcntl(stderr_fd, fcntl.F_GETFL)
        fcntl.fcntl(stderr_fd, fcntl.F_SETFL, fl & ~os.O_NONBLOCK)
        unpacker = get_limited_unpacker('server')
        while True:
            r, w, es = select.select([stdin_fd], [], [], 10)
            if r:
                data = os.read(stdin_fd, BUFSIZE)
                if not data:
                    if self.repository is not None:
                        self.repository.close()
                    else:
                        os_write(stderr_fd, 'Borg {}: Got connection close before repository was opened.\n'
                                 .format(__version__).encode())
                    return
                unpacker.feed(data)
                for unpacked in unpacker:
                    if isinstance(unpacked, dict):
                        dictFormat = True
                        msgid = unpacked[MSGID]
                        method = unpacked[MSG].decode()
                        args = decode_keys(unpacked[ARGS])
                    elif isinstance(unpacked, tuple) and len(unpacked) == 4:
                        dictFormat = False
                        # The first field 'type' was always 1 and has always been ignored
                        _, msgid, method, args = unpacked
                        method = method.decode()
                        args = self.positional_to_named(method, args)
                    else:
                        if self.repository is not None:
                            self.repository.close()
                        raise UnexpectedRPCDataFormatFromClient(__version__)
                    try:
                        if method not in self.rpc_methods:
                            raise InvalidRPCMethod(method)
                        try:
                            f = getattr(self, method)
                        except AttributeError:
                            f = getattr(self.repository, method)
                        args = self.filter_args(f, args)
                        res = f(**args)
                    except BaseException as e:
                        if dictFormat:
                            ex_short = traceback.format_exception_only(e.__class__, e)
                            ex_full = traceback.format_exception(*sys.exc_info())
                            ex_trace = True
                            if isinstance(e, Error):
                                ex_short = [e.get_message()]
                                ex_trace = e.traceback
                            if isinstance(e, (Repository.DoesNotExist, Repository.AlreadyExists, PathNotAllowed)):
                                # These exceptions are reconstructed on the client end in RemoteRepository.call_many(),
                                # and will be handled just like locally raised exceptions. Suppress the remote traceback
                                # for these, except ErrorWithTraceback, which should always display a traceback.
                                pass
                            else:
                                logging.debug('\n'.join(ex_full))

                            try:
                                msg = msgpack.packb({MSGID: msgid,
                                                    b'exception_class': e.__class__.__name__,
                                                    b'exception_args': e.args,
                                                    b'exception_full': ex_full,
                                                    b'exception_short': ex_short,
                                                    b'exception_trace': ex_trace,
                                                    b'sysinfo': sysinfo()})
                            except TypeError:
                                msg = msgpack.packb({MSGID: msgid,
                                                    b'exception_class': e.__class__.__name__,
                                                    b'exception_args': [x if isinstance(x, (str, bytes, int)) else None
                                                                        for x in e.args],
                                                    b'exception_full': ex_full,
                                                    b'exception_short': ex_short,
                                                    b'exception_trace': ex_trace,
                                                    b'sysinfo': sysinfo()})

                            os_write(stdout_fd, msg)
                        else:
                            if isinstance(e, (Repository.DoesNotExist, Repository.AlreadyExists, PathNotAllowed)):
                                # These exceptions are reconstructed on the client end in RemoteRepository.call_many(),
                                # and will be handled just like locally raised exceptions. Suppress the remote traceback
                                # for these, except ErrorWithTraceback, which should always display a traceback.
                                pass
                            else:
                                if isinstance(e, Error):
                                    tb_log_level = logging.ERROR if e.traceback else logging.DEBUG
                                    msg = e.get_message()
                                else:
                                    tb_log_level = logging.ERROR
                                    msg = '%s Exception in RPC call' % e.__class__.__name__
                                tb = '%s\n%s' % (traceback.format_exc(), sysinfo())
                                logging.error(msg)
                                logging.log(tb_log_level, tb)
                            exc = 'Remote Exception (see remote log for the traceback)'
                            os_write(stdout_fd, msgpack.packb((1, msgid, e.__class__.__name__, exc)))
                    else:
                        if dictFormat:
                            os_write(stdout_fd, msgpack.packb({MSGID: msgid, RESULT: res}))
                        else:
                            os_write(stdout_fd, msgpack.packb((1, msgid, None, res)))
            if es:
                self.repository.close()
                return

    def negotiate(self, client_data):
        # old format used in 1.0.x
        if client_data == RPC_PROTOCOL_VERSION:
            return RPC_PROTOCOL_VERSION
        # clients since 1.1.0b3 use a dict as client_data
        if isinstance(client_data, dict):
            self.client_version = client_data[b'client_version']
            if client_data.get(b'client_supports_log_v3', False):
                level = logging.getLevelName(logging.getLogger('').level)
                setup_logging(is_serve=True, json=True, level=level)
                logger.debug('Initialized logging system for new (v3) protocol')
        else:
            self.client_version = BORG_VERSION  # seems to be newer than current version (no known old format)

        # not a known old format, send newest negotiate this version knows
        return {'server_version': BORG_VERSION}

    def _resolve_path(self, path):
        if isinstance(path, bytes):
            path = os.fsdecode(path)
        # Leading slash is always present with URI (ssh://), but not with short-form (who@host:path).
        if path.startswith('/~/'):  # /~/x = path x relative to home dir
            path = os.path.join(get_home_dir(), path[3:])
        elif path.startswith('~/'):
            path = os.path.join(get_home_dir(), path[2:])
        elif path.startswith('/~'):  # /~username/x = relative to "user" home dir
            path = os.path.expanduser(path[1:])
        elif path.startswith('~'):
            path = os.path.expanduser(path)
        elif path.startswith('/./'):  # /./x = path x relative to cwd
            path = path[3:]
        return os.path.realpath(path)

    def open(self, path, create=False, lock_wait=None, lock=True, exclusive=None, append_only=False):
        logging.debug('Resolving repository path %r', path)
        path = self._resolve_path(path)
        logging.debug('Resolved repository path to %r', path)
        path_with_sep = os.path.join(path, '')  # make sure there is a trailing slash (os.sep)
        if self.restrict_to_paths:
            # if --restrict-to-path P is given, we make sure that we only operate in/below path P.
            # for the prefix check, it is important that the compared paths both have trailing slashes,
            # so that a path /foobar will NOT be accepted with --restrict-to-path /foo option.
            for restrict_to_path in self.restrict_to_paths:
                restrict_to_path_with_sep = os.path.join(os.path.realpath(restrict_to_path), '')  # trailing slash
                if path_with_sep.startswith(restrict_to_path_with_sep):
                    break
            else:
                raise PathNotAllowed(path)
        if self.restrict_to_repositories:
            for restrict_to_repository in self.restrict_to_repositories:
                restrict_to_repository_with_sep = os.path.join(os.path.realpath(restrict_to_repository), '')
                if restrict_to_repository_with_sep == path_with_sep:
                    break
            else:
                raise PathNotAllowed(path)
        # "borg init" on "borg serve --append-only" (=self.append_only) does not create an append only repo,
        # while "borg init --append-only" (=append_only) does, regardless of the --append-only (self.append_only)
        # flag for serve.
        append_only = (not create and self.append_only) or append_only
        self.repository = Repository(path, create, lock_wait=lock_wait, lock=lock,
                                     append_only=append_only,
                                     storage_quota=self.storage_quota,
                                     exclusive=exclusive)
        self.repository.__enter__()  # clean exit handled by serve() method
        return self.repository.id

    def inject_exception(self, kind):
        kind = kind.decode()
        s1 = 'test string'
        s2 = 'test string2'
        if kind == 'DoesNotExist':
            raise Repository.DoesNotExist(s1)
        elif kind == 'AlreadyExists':
            raise Repository.AlreadyExists(s1)
        elif kind == 'CheckNeeded':
            raise Repository.CheckNeeded(s1)
        elif kind == 'IntegrityError':
            raise IntegrityError(s1)
        elif kind == 'PathNotAllowed':
            raise PathNotAllowed('foo')
        elif kind == 'ObjectNotFound':
            raise Repository.ObjectNotFound(s1, s2)
        elif kind == 'InvalidRPCMethod':
            raise InvalidRPCMethod(s1)
        elif kind == 'divide':
            0 // 0


class SleepingBandwidthLimiter:
    def __init__(self, limit):
        if limit:
            self.ratelimit = int(limit * RATELIMIT_PERIOD)
            self.ratelimit_last = time.monotonic()
            self.ratelimit_quota = self.ratelimit
        else:
            self.ratelimit = None

    def write(self, fd, to_send):
        if self.ratelimit:
            now = time.monotonic()
            if self.ratelimit_last + RATELIMIT_PERIOD <= now:
                self.ratelimit_quota += self.ratelimit
                if self.ratelimit_quota > 2 * self.ratelimit:
                    self.ratelimit_quota = 2 * self.ratelimit
                self.ratelimit_last = now
            if self.ratelimit_quota == 0:
                tosleep = self.ratelimit_last + RATELIMIT_PERIOD - now
                time.sleep(tosleep)
                self.ratelimit_quota += self.ratelimit
                self.ratelimit_last = time.monotonic()
            if len(to_send) > self.ratelimit_quota:
                to_send = to_send[:self.ratelimit_quota]
        written = os.write(fd, to_send)
        if self.ratelimit:
            self.ratelimit_quota -= written
        return written


def api(*, since, **kwargs_decorator):
    """Check version requirements and use self.call to do the remote method call.

    <since> specifies the version in which borg introduced this method,
    calling this method when connected to an older version will fail without transmiting
    anything to the server.

    Further kwargs can be used to encode version specific restrictions.
    If a previous hardcoded behaviour is parameterized in a version, this allows calls that
    use the previously hardcoded behaviour to pass through and generates an error if another
    behaviour is requested by the client.

    e.g. when 'append_only' was introduced in 1.0.7 the previous behaviour was what now is append_only=False.
    Thus @api(..., append_only={'since': parse_version('1.0.7'), 'previously': False}) allows calls
    with append_only=False for all version but rejects calls using append_only=True on versions older than 1.0.7.
    """
    def decorator(f):
        @functools.wraps(f)
        def do_rpc(self, *args, **kwargs):
            sig = inspect.signature(f)
            bound_args = sig.bind(self, *args, **kwargs)
            named = {}  # Arguments for the remote process
            extra = {}  # Arguments for the local process
            for name, param in sig.parameters.items():
                if name == 'self':
                    continue
                if name in bound_args.arguments:
                    if name == 'wait':
                        extra[name] = bound_args.arguments[name]
                    else:
                        named[name] = bound_args.arguments[name]
                else:
                    if param.default is not param.empty:
                        named[name] = param.default

            if self.server_version < since:
                raise self.RPCServerOutdated(f.__name__, format_version(since))

            for name, restriction in kwargs_decorator.items():
                if restriction['since'] <= self.server_version:
                    continue
                if 'previously' in restriction and named[name] == restriction['previously']:
                    continue

                raise self.RPCServerOutdated("{0} {1}={2!s}".format(f.__name__, name, named[name]),
                                             format_version(restriction['since']))

            return self.call(f.__name__, named, **extra)
        return do_rpc
    return decorator


class RemoteRepository:
    extra_test_args = []

    class RPCError(Exception):
        def __init__(self, unpacked):
            # for borg < 1.1: unpacked only has b'exception_class' as key
            # for borg 1.1+: unpacked has keys: b'exception_args', b'exception_full', b'exception_short', b'sysinfo'
            self.unpacked = unpacked

        def get_message(self):
            if b'exception_short' in self.unpacked:
                return b'\n'.join(self.unpacked[b'exception_short']).decode()
            else:
                return self.exception_class

        @property
        def traceback(self):
            return self.unpacked.get(b'exception_trace', True)

        @property
        def exception_class(self):
            return self.unpacked[b'exception_class'].decode()

        @property
        def exception_full(self):
            if b'exception_full' in self.unpacked:
                return b'\n'.join(self.unpacked[b'exception_full']).decode()
            else:
                return self.get_message() + '\nRemote Exception (see remote log for the traceback)'

        @property
        def sysinfo(self):
            if b'sysinfo' in self.unpacked:
                return self.unpacked[b'sysinfo'].decode()
            else:
                return ''

    class RPCServerOutdated(Error):
        """Borg server is too old for {}. Required version {}"""

        @property
        def method(self):
            return self.args[0]

        @property
        def required_version(self):
            return self.args[1]

    # If compatibility with 1.0.x is not longer needed, replace all checks of this with True and simplify the code
    dictFormat = False  # outside of __init__ for testing of legacy free protocol

    def __init__(self, location, create=False, exclusive=False, lock_wait=None, lock=True, append_only=False, args=None):
        self.location = self._location = location
        self.preload_ids = []
        self.msgid = 0
        self.rx_bytes = 0
        self.tx_bytes = 0
        self.to_send = b''
        self.chunkid_to_msgids = {}
        self.ignore_responses = set()
        self.responses = {}
        self.async_responses = {}
        self.shutdown_time = None
        self.ratelimit = SleepingBandwidthLimiter(args.remote_ratelimit * 1024 if args and args.remote_ratelimit else 0)
        self.unpacker = get_limited_unpacker('client')
        self.server_version = parse_version('1.0.8')  # fallback version if server is too old to send version information
        self.p = None
        testing = location.host == '__testsuite__'
        borg_cmd = self.borg_cmd(args, testing)
        env = dict(os.environ)
        if not testing:
            borg_cmd = self.ssh_cmd(location) + borg_cmd
            # pyinstaller binary modifies LD_LIBRARY_PATH=/tmp/_ME... but we do not want
            # that the system's ssh binary picks up (non-matching) libraries from there.
            # thus we install the original LDLP, before pyinstaller has modified it:
            lp_key = 'LD_LIBRARY_PATH'
            lp_orig = env.get(lp_key + '_ORIG')  # pyinstaller >= 20160820 has this
            if lp_orig is not None:
                env[lp_key] = lp_orig
            else:
                env.pop(lp_key, None)
        env.pop('BORG_PASSPHRASE', None)  # security: do not give secrets to subprocess
        env['BORG_VERSION'] = __version__
        logger.debug('SSH command line: %s', borg_cmd)
        self.p = Popen(borg_cmd, bufsize=0, stdin=PIPE, stdout=PIPE, stderr=PIPE, env=env)
        self.stdin_fd = self.p.stdin.fileno()
        self.stdout_fd = self.p.stdout.fileno()
        self.stderr_fd = self.p.stderr.fileno()
        fcntl.fcntl(self.stdin_fd, fcntl.F_SETFL, fcntl.fcntl(self.stdin_fd, fcntl.F_GETFL) | os.O_NONBLOCK)
        fcntl.fcntl(self.stdout_fd, fcntl.F_SETFL, fcntl.fcntl(self.stdout_fd, fcntl.F_GETFL) | os.O_NONBLOCK)
        fcntl.fcntl(self.stderr_fd, fcntl.F_SETFL, fcntl.fcntl(self.stderr_fd, fcntl.F_GETFL) | os.O_NONBLOCK)
        self.r_fds = [self.stdout_fd, self.stderr_fd]
        self.x_fds = [self.stdin_fd, self.stdout_fd, self.stderr_fd]

        try:
            try:
                version = self.call('negotiate', {'client_data': {
                    b'client_version': BORG_VERSION,
                    b'client_supports_log_v3': True,
                }})
            except ConnectionClosed:
                raise ConnectionClosedWithHint('Is borg working on the server?') from None
            if version == RPC_PROTOCOL_VERSION:
                self.dictFormat = False
            elif isinstance(version, dict) and b'server_version' in version:
                self.dictFormat = True
                self.server_version = version[b'server_version']
            else:
                raise Exception('Server insisted on using unsupported protocol version %s' % version)

            def do_open():
                self.id = self.open(path=self.location.path, create=create, lock_wait=lock_wait,
                                    lock=lock, exclusive=exclusive, append_only=append_only)

            if self.dictFormat:
                do_open()
            else:
                # Ugly detection of versions prior to 1.0.7: If open throws it has to be 1.0.6 or lower
                try:
                    do_open()
                except self.RPCError as err:
                    if err.exception_class != 'TypeError':
                        raise
                    msg = """\
Please note:
If you see a TypeError complaining about the number of positional arguments
given to open(), you can ignore it if it comes from a borg version < 1.0.7.
This TypeError is a cosmetic side effect of the compatibility code borg
clients >= 1.0.7 have to support older borg servers.
This problem will go away as soon as the server has been upgraded to 1.0.7+.
"""
                    # emit this msg in the same way as the 'Remote: ...' lines that show the remote TypeError
                    sys.stderr.write(msg)
                    self.server_version = parse_version('1.0.6')
                    compatMap['open'] = ('path', 'create', 'lock_wait', 'lock', ),
                    # try again with corrected version and compatMap
                    do_open()
        except Exception:
            self.close()
            raise

    def __del__(self):
        if len(self.responses):
            logging.debug('still %d cached responses left in RemoteRepository' % (len(self.responses),))
        if self.p:
            self.close()
            assert False, 'cleanup happened in Repository.__del__'

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, self.location.canonical_path())

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            if exc_type is not None:
                self.shutdown_time = time.monotonic() + 30
                self.rollback()
        finally:
            # in any case, we want to cleanly close the repo, even if the
            # rollback can not succeed (e.g. because the connection was
            # already closed) and raised another exception:
            logger.debug('RemoteRepository: %s bytes sent, %s bytes received, %d messages sent',
                         format_file_size(self.tx_bytes), format_file_size(self.rx_bytes), self.msgid)
            self.close()

    @property
    def id_str(self):
        return bin_to_hex(self.id)

    def borg_cmd(self, args, testing):
        """return a borg serve command line"""
        # give some args/options to 'borg serve' process as they were given to us
        opts = []
        if args is not None:
            opts.append('--umask=%03o' % args.umask)
            root_logger = logging.getLogger()
            if root_logger.isEnabledFor(logging.DEBUG):
                opts.append('--debug')
            elif root_logger.isEnabledFor(logging.INFO):
                opts.append('--info')
            elif root_logger.isEnabledFor(logging.WARNING):
                pass  # warning is default
            elif root_logger.isEnabledFor(logging.ERROR):
                opts.append('--error')
            elif root_logger.isEnabledFor(logging.CRITICAL):
                opts.append('--critical')
            else:
                raise ValueError('log level missing, fix this code')

            # Tell the remote server about debug topics it may need to consider.
            # Note that debug topics are usable for "spew" or "trace" logs which would
            # be too plentiful to transfer for normal use, so the server doesn't send
            # them unless explicitly enabled.
            #
            # Needless to say, if you do --debug-topic=repository.compaction, for example,
            # with a 1.0.x server it won't work, because the server does not recognize the
            # option.
            #
            # This is not considered a problem, since this is a debugging feature that
            # should not be used for regular use.
            for topic in args.debug_topics:
                if '.' not in topic:
                    topic = 'borg.debug.' + topic
                if 'repository' in topic:
                    opts.append('--debug-topic=%s' % topic)

            if 'storage_quota' in args and args.storage_quota:
                opts.append('--storage-quota=%s' % args.storage_quota)
        env_vars = []
        if not hostname_is_unique():
            env_vars.append('BORG_HOSTNAME_IS_UNIQUE=no')
        if testing:
            return env_vars + [sys.executable, '-m', 'borg.archiver', 'serve'] + opts + self.extra_test_args
        else:  # pragma: no cover
            remote_path = args.remote_path or os.environ.get('BORG_REMOTE_PATH', 'borg')
            remote_path = replace_placeholders(remote_path)
            return env_vars + [remote_path, 'serve'] + opts

    def ssh_cmd(self, location):
        """return a ssh command line that can be prefixed to a borg command line"""
        args = shlex.split(os.environ.get('BORG_RSH', 'ssh'))
        if location.port:
            args += ['-p', str(location.port)]
        if location.user:
            args.append('%s@%s' % (location.user, location.host))
        else:
            args.append('%s' % location.host)
        return args

    def named_to_positional(self, method, kwargs):
        return [kwargs[name] for name in compatMap[method]]

    def call(self, cmd, args, **kw):
        for resp in self.call_many(cmd, [args], **kw):
            return resp

    def call_many(self, cmd, calls, wait=True, is_preloaded=False, async_wait=True):
        if not calls and cmd != 'async_responses':
            return

        def pop_preload_msgid(chunkid):
            msgid = self.chunkid_to_msgids[chunkid].pop(0)
            if not self.chunkid_to_msgids[chunkid]:
                del self.chunkid_to_msgids[chunkid]
            return msgid

        def handle_error(unpacked):
            error = unpacked[b'exception_class'].decode()
            old_server = b'exception_args' not in unpacked
            args = unpacked.get(b'exception_args')

            if error == 'DoesNotExist':
                raise Repository.DoesNotExist(self.location.orig)
            elif error == 'AlreadyExists':
                raise Repository.AlreadyExists(self.location.orig)
            elif error == 'CheckNeeded':
                raise Repository.CheckNeeded(self.location.orig)
            elif error == 'IntegrityError':
                if old_server:
                    raise IntegrityError('(not available)')
                else:
                    raise IntegrityError(args[0].decode())
            elif error == 'PathNotAllowed':
                if old_server:
                    raise PathNotAllowed('(unknown)')
                else:
                    raise PathNotAllowed(args[0].decode())
            elif error == 'ObjectNotFound':
                if old_server:
                    raise Repository.ObjectNotFound('(not available)', self.location.orig)
                else:
                    raise Repository.ObjectNotFound(args[0].decode(), self.location.orig)
            elif error == 'InvalidRPCMethod':
                if old_server:
                    raise InvalidRPCMethod('(not available)')
                else:
                    raise InvalidRPCMethod(args[0].decode())
            else:
                raise self.RPCError(unpacked)

        calls = list(calls)
        waiting_for = []
        while wait or calls:
            if self.shutdown_time and time.monotonic() > self.shutdown_time:
                # we are shutting this RemoteRepository down already, make sure we do not waste
                # a lot of time in case a lot of async stuff is coming in or remote is gone or slow.
                logger.debug('shutdown_time reached, shutting down with %d waiting_for and %d async_responses.',
                             len(waiting_for), len(self.async_responses))
                return
            while waiting_for:
                try:
                    unpacked = self.responses.pop(waiting_for[0])
                    waiting_for.pop(0)
                    if b'exception_class' in unpacked:
                        handle_error(unpacked)
                    else:
                        yield unpacked[RESULT]
                        if not waiting_for and not calls:
                            return
                except KeyError:
                    break
            if cmd == 'async_responses':
                while True:
                    try:
                        msgid, unpacked = self.async_responses.popitem()
                    except KeyError:
                        # there is nothing left what we already have received
                        if async_wait and self.ignore_responses:
                            # but do not return if we shall wait and there is something left to wait for:
                            break
                        else:
                            return
                    else:
                        if b'exception_class' in unpacked:
                            handle_error(unpacked)
                        else:
                            yield unpacked[RESULT]
            if self.to_send or ((calls or self.preload_ids) and len(waiting_for) < MAX_INFLIGHT):
                w_fds = [self.stdin_fd]
            else:
                w_fds = []
            r, w, x = select.select(self.r_fds, w_fds, self.x_fds, 1)
            if x:
                raise Exception('FD exception occurred')
            for fd in r:
                if fd is self.stdout_fd:
                    data = os.read(fd, BUFSIZE)
                    if not data:
                        raise ConnectionClosed()
                    self.rx_bytes += len(data)
                    self.unpacker.feed(data)
                    for unpacked in self.unpacker:
                        if isinstance(unpacked, dict):
                            msgid = unpacked[MSGID]
                        elif isinstance(unpacked, tuple) and len(unpacked) == 4:
                            # The first field 'type' was always 1 and has always been ignored
                            _, msgid, error, res = unpacked
                            if error:
                                # ignore res, because it is only a fixed string anyway.
                                unpacked = {MSGID: msgid, b'exception_class': error}
                            else:
                                unpacked = {MSGID: msgid, RESULT: res}
                        else:
                            raise UnexpectedRPCDataFormatFromServer(data)
                        if msgid in self.ignore_responses:
                            self.ignore_responses.remove(msgid)
                            # async methods never return values, but may raise exceptions.
                            if b'exception_class' in unpacked:
                                self.async_responses[msgid] = unpacked
                            else:
                                # we currently do not have async result values except "None",
                                # so we do not add them into async_responses.
                                if unpacked[RESULT] is not None:
                                    self.async_responses[msgid] = unpacked
                        else:
                            self.responses[msgid] = unpacked
                elif fd is self.stderr_fd:
                    data = os.read(fd, 32768)
                    if not data:
                        raise ConnectionClosed()
                    self.rx_bytes += len(data)
                    data = data.decode('utf-8')
                    for line in data.splitlines(keepends=True):
                        handle_remote_line(line)
            if w:
                while not self.to_send and (calls or self.preload_ids) and len(waiting_for) < MAX_INFLIGHT:
                    if calls:
                        if is_preloaded:
                            assert cmd == 'get', "is_preload is only supported for 'get'"
                            if calls[0]['id'] in self.chunkid_to_msgids:
                                waiting_for.append(pop_preload_msgid(calls.pop(0)['id']))
                        else:
                            args = calls.pop(0)
                            if cmd == 'get' and args['id'] in self.chunkid_to_msgids:
                                waiting_for.append(pop_preload_msgid(args['id']))
                            else:
                                self.msgid += 1
                                waiting_for.append(self.msgid)
                                if self.dictFormat:
                                    self.to_send = msgpack.packb({MSGID: self.msgid, MSG: cmd, ARGS: args})
                                else:
                                    self.to_send = msgpack.packb((1, self.msgid, cmd, self.named_to_positional(cmd, args)))
                    if not self.to_send and self.preload_ids:
                        chunk_id = self.preload_ids.pop(0)
                        args = {'id': chunk_id}
                        self.msgid += 1
                        self.chunkid_to_msgids.setdefault(chunk_id, []).append(self.msgid)
                        if self.dictFormat:
                            self.to_send = msgpack.packb({MSGID: self.msgid, MSG: 'get', ARGS: args})
                        else:
                            self.to_send = msgpack.packb((1, self.msgid, 'get', self.named_to_positional(cmd, args)))

                if self.to_send:
                    try:
                        written = self.ratelimit.write(self.stdin_fd, self.to_send)
                        self.tx_bytes += written
                        self.to_send = self.to_send[written:]
                    except OSError as e:
                        # io.write might raise EAGAIN even though select indicates
                        # that the fd should be writable
                        if e.errno != errno.EAGAIN:
                            raise
        self.ignore_responses |= set(waiting_for)  # we lose order here

    @api(since=parse_version('1.0.0'),
         append_only={'since': parse_version('1.0.7'), 'previously': False})
    def open(self, path, create=False, lock_wait=None, lock=True, exclusive=False, append_only=False):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version('1.0.0'))
    def check(self, repair=False, save_space=False):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version('1.0.0'))
    def commit(self, save_space=False):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version('1.0.0'))
    def rollback(self):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version('1.0.0'))
    def destroy(self):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version('1.0.0'))
    def __len__(self):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version('1.0.0'))
    def list(self, limit=None, marker=None):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version('1.1.0b3'))
    def scan(self, limit=None, marker=None):
        """actual remoting is done via self.call in the @api decorator"""

    def get(self, id):
        for resp in self.get_many([id]):
            return resp

    def get_many(self, ids, is_preloaded=False):
        for resp in self.call_many('get', [{'id': id} for id in ids], is_preloaded=is_preloaded):
            yield resp

    @api(since=parse_version('1.0.0'))
    def put(self, id, data, wait=True):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version('1.0.0'))
    def delete(self, id, wait=True):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version('1.0.0'))
    def save_key(self, keydata):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version('1.0.0'))
    def load_key(self):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version('1.0.0'))
    def get_free_nonce(self):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version('1.0.0'))
    def commit_nonce_reservation(self, next_unreserved, start_nonce):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version('1.0.0'))
    def break_lock(self):
        """actual remoting is done via self.call in the @api decorator"""

    def close(self):
        if self.p:
            self.p.stdin.close()
            self.p.stdout.close()
            self.p.wait()
            self.p = None

    def async_response(self, wait=True):
        for resp in self.call_many('async_responses', calls=[], wait=True, async_wait=wait):
            return resp

    def preload(self, ids):
        self.preload_ids += ids


def handle_remote_line(line):
    """
    Handle a remote log line.

    This function is remarkably complex because it handles multiple wire formats.
    """
    if line.startswith('{'):
        # This format is used by Borg since 1.1.0b6 for new-protocol clients.
        # It is the same format that is exposed by --log-json.
        msg = json.loads(line)

        if msg['type'] not in ('progress_message', 'progress_percent', 'log_message'):
            logger.warning('Dropped remote log message with unknown type %r: %s', msg['type'], line)
            return

        if msg['type'] == 'log_message':
            # Re-emit log messages on the same level as the remote to get correct log suppression and verbosity.
            level = getattr(logging, msg['levelname'], logging.CRITICAL)
            assert isinstance(level, int)
            target_logger = logging.getLogger(msg['name'])
            msg['message'] = 'Remote: ' + msg['message']
            # In JSON mode, we manually check whether the log message should be propagated.
            if logging.getLogger('borg').json and level >= target_logger.getEffectiveLevel():
                sys.stderr.write(json.dumps(msg) + '\n')
            else:
                target_logger.log(level, '%s', msg['message'])
        elif msg['type'].startswith('progress_'):
            # Progress messages are a bit more complex.
            # First of all, we check whether progress output is enabled. This is signalled
            # through the effective level of the borg.output.progress logger
            # (also see ProgressIndicatorBase in borg.helpers).
            progress_logger = logging.getLogger('borg.output.progress')
            if progress_logger.getEffectiveLevel() == logging.INFO:
                # When progress output is enabled, we check whether the client is in
                # --log-json mode, as signalled by the "json" attribute on the "borg" logger.
                if logging.getLogger('borg').json:
                    # In --log-json mode we re-emit the progress JSON line as sent by the server,
                    # with the message, if any, prefixed with "Remote: ".
                    if 'message' in msg:
                        msg['message'] = 'Remote: ' + msg['message']
                    sys.stderr.write(json.dumps(msg) + '\n')
                elif 'message' in msg:
                    # In text log mode we write only the message to stderr and terminate with \r
                    # (carriage return, i.e. move the write cursor back to the beginning of the line)
                    # so that the next message, progress or not, overwrites it. This mirrors the behaviour
                    # of local progress displays.
                    sys.stderr.write('Remote: ' + msg['message'] + '\r')
    elif line.startswith('$LOG '):
        # This format is used by Borg since 1.1.0b1.
        # It prefixed log lines with $LOG as a marker, followed by the log level
        # and optionally a logger name, then "Remote:" as a separator followed by the original
        # message.
        #
        # It is the oldest format supported by these servers, so it was important to make
        # it readable with older (1.0.x) clients.
        #
        # TODO: Remove this block (so it'll be handled by the "else:" below) with a Borg 1.1 RC.
        #       Also check whether client_supports_log_v3 should be removed.
        _, level, msg = line.split(' ', 2)
        level = getattr(logging, level, logging.CRITICAL)  # str -> int
        if msg.startswith('Remote:'):
            # server format: '$LOG <level> Remote: <msg>'
            logging.log(level, msg.rstrip())
        else:
            # server format '$LOG <level> <logname> Remote: <msg>'
            logname, msg = msg.split(' ', 1)
            logging.getLogger(logname).log(level, msg.rstrip())
    else:
        # Plain 1.0.x and older format - re-emit to stderr (mirroring what the 1.0.x
        # client did) or as a generic log message.
        # We don't know what priority the line had.
        if logging.getLogger('borg').json:
            logging.getLogger('').warning('Remote: ' + line.strip())
        else:
            # In non-JSON mode we circumvent logging to preserve carriage returns (\r)
            # which are generated by remote progress displays.
            sys.stderr.write('Remote: ' + line)


class RepositoryNoCache:
    """A not caching Repository wrapper, passes through to repository.

    Just to have same API (including the context manager) as RepositoryCache.

    *transform* is a callable taking two arguments, key and raw repository data.
    The return value is returned from get()/get_many(). By default, the raw
    repository data is returned.
    """
    def __init__(self, repository, transform=None):
        self.repository = repository
        self.transform = transform or (lambda key, data: data)

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def get(self, key):
        return next(self.get_many([key], cache=False))

    def get_many(self, keys, cache=True):
        for key, data in zip(keys, self.repository.get_many(keys)):
            yield self.transform(key, data)

    def log_instrumentation(self):
        pass


class RepositoryCache(RepositoryNoCache):
    """
    A caching Repository wrapper.

    Caches Repository GET operations locally.

    *pack* and *unpack* complement *transform* of the base class.
    *pack* receives the output of *transform* and should return bytes,
    which are stored in the cache. *unpack* receives these bytes and
    should return the initial data (as returned by *transform*).
    """

    def __init__(self, repository, pack=None, unpack=None, transform=None):
        super().__init__(repository, transform)
        self.pack = pack or (lambda data: data)
        self.unpack = unpack or (lambda data: data)
        self.cache = set()
        self.basedir = tempfile.mkdtemp(prefix='borg-cache-')
        self.query_size_limit()
        self.size = 0
        # Instrumentation
        self.hits = 0
        self.misses = 0
        self.slow_misses = 0
        self.slow_lat = 0.0
        self.evictions = 0
        self.enospc = 0

    def query_size_limit(self):
        stat_fs = os.statvfs(self.basedir)
        available_space = stat_fs.f_bsize * stat_fs.f_bavail
        self.size_limit = int(min(available_space * 0.25, 2**31))

    def key_filename(self, key):
        return os.path.join(self.basedir, bin_to_hex(key))

    def backoff(self):
        self.query_size_limit()
        target_size = int(0.9 * self.size_limit)
        while self.size > target_size and self.cache:
            key = self.cache.pop()
            file = self.key_filename(key)
            self.size -= os.stat(file).st_size
            os.unlink(file)
            self.evictions += 1

    def add_entry(self, key, data, cache):
        transformed = self.transform(key, data)
        if not cache:
            return transformed
        packed = self.pack(transformed)
        file = self.key_filename(key)
        try:
            with open(file, 'wb') as fd:
                fd.write(packed)
        except OSError as os_error:
            try:
                truncate_and_unlink(file)
            except FileNotFoundError:
                pass  # open() could have failed as well
            if os_error.errno == errno.ENOSPC:
                self.enospc += 1
                self.backoff()
            else:
                raise
        else:
            self.size += len(packed)
            self.cache.add(key)
            if self.size > self.size_limit:
                self.backoff()
        return transformed

    def log_instrumentation(self):
        logger.debug('RepositoryCache: current items %d, size %s / %s, %d hits, %d misses, %d slow misses (+%.1fs), '
                     '%d evictions, %d ENOSPC hit',
                     len(self.cache), format_file_size(self.size), format_file_size(self.size_limit),
                     self.hits, self.misses, self.slow_misses, self.slow_lat,
                     self.evictions, self.enospc)

    def close(self):
        self.log_instrumentation()
        self.cache.clear()
        shutil.rmtree(self.basedir)

    def get_many(self, keys, cache=True):
        unknown_keys = [key for key in keys if key not in self.cache]
        repository_iterator = zip(unknown_keys, self.repository.get_many(unknown_keys))
        for key in keys:
            if key in self.cache:
                file = self.key_filename(key)
                with open(file, 'rb') as fd:
                    self.hits += 1
                    yield self.unpack(fd.read())
            else:
                for key_, data in repository_iterator:
                    if key_ == key:
                        transformed = self.add_entry(key, data, cache)
                        self.misses += 1
                        yield transformed
                        break
                else:
                    # slow path: eviction during this get_many removed this key from the cache
                    t0 = time.perf_counter()
                    data = self.repository.get(key)
                    self.slow_lat += time.perf_counter() - t0
                    transformed = self.add_entry(key, data, cache)
                    self.slow_misses += 1
                    yield transformed
        # Consume any pending requests
        for _ in repository_iterator:
            pass


def cache_if_remote(repository, *, decrypted_cache=False, pack=None, unpack=None, transform=None, force_cache=False):
    """
    Return a Repository(No)Cache for *repository*.

    If *decrypted_cache* is a key object, then get and get_many will return a tuple
    (csize, plaintext) instead of the actual data in the repository. The cache will
    store decrypted data, which increases CPU efficiency (by avoiding repeatedly decrypting
    and more importantly MAC and ID checking cached objects).
    Internally, objects are compressed with LZ4.
    """
    if decrypted_cache and (pack or unpack or transform):
        raise ValueError('decrypted_cache and pack/unpack/transform are incompatible')
    elif decrypted_cache:
        key = decrypted_cache
        # 32 bit csize, 64 bit (8 byte) xxh64
        cache_struct = struct.Struct('=I8s')
        compressor = LZ4()

        def pack(data):
            csize, decrypted = data
            compressed = compressor.compress(decrypted)
            return cache_struct.pack(csize, xxh64(compressed)) + compressed

        def unpack(data):
            data = memoryview(data)
            csize, checksum = cache_struct.unpack(data[:cache_struct.size])
            compressed = data[cache_struct.size:]
            if checksum != xxh64(compressed):
                raise IntegrityError('detected corrupted data in metadata cache')
            return csize, compressor.decompress(compressed)

        def transform(id_, data):
            csize = len(data)
            decrypted = key.decrypt(id_, data)
            return csize, decrypted

    if isinstance(repository, RemoteRepository) or force_cache:
        return RepositoryCache(repository, pack, unpack, transform)
    else:
        return RepositoryNoCache(repository, transform)

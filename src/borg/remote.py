import errno
import fcntl
import functools
import inspect
import logging
import os
import select
import shlex
import sys
import tempfile
import time
import traceback
import textwrap
import time
from subprocess import Popen, PIPE

import msgpack

from . import __version__
from .helpers import Error, IntegrityError
from .helpers import get_home_dir
from .helpers import sysinfo
from .helpers import bin_to_hex
from .helpers import replace_placeholders
from .helpers import yes
from .repository import Repository
from .version import parse_version, format_version
from .logger import create_logger

logger = create_logger(__name__)

RPC_PROTOCOL_VERSION = 2
BORG_VERSION = parse_version(__version__)
MSGID, MSG, ARGS, RESULT = b'i', b'm', b'a', b'r'

BUFSIZE = 10 * 1024 * 1024

MAX_INFLIGHT = 100

RATELIMIT_PERIOD = 0.1


def os_write(fd, data):
    """os.write wrapper so we do not lose data for partial writes."""
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


class ConnectionClosed(Error):
    """Connection closed by remote host"""


class ConnectionClosedWithHint(ConnectionClosed):
    """Connection closed by remote host. {}"""


class PathNotAllowed(Error):
    """Repository path not allowed"""


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

    def __init__(self, restrict_to_paths, append_only):
        self.repository = None
        self.restrict_to_paths = restrict_to_paths
        self.append_only = append_only
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
        unpacker = msgpack.Unpacker(use_list=False)
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
                            if isinstance(e, Error):
                                ex_short = e.get_message()
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
                                                    b'sysinfo': sysinfo()})
                            except TypeError:
                                msg = msgpack.packb({MSGID: msgid,
                                                    b'exception_class': e.__class__.__name__,
                                                    b'exception_args': [x if isinstance(x, (str, bytes, int)) else None
                                                                        for x in e.args],
                                                    b'exception_full': ex_full,
                                                    b'exception_short': ex_short,
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
        if self.restrict_to_paths:
            # if --restrict-to-path P is given, we make sure that we only operate in/below path P.
            # for the prefix check, it is important that the compared pathes both have trailing slashes,
            # so that a path /foobar will NOT be accepted with --restrict-to-path /foo option.
            path_with_sep = os.path.join(path, '')  # make sure there is a trailing slash (os.sep)
            for restrict_to_path in self.restrict_to_paths:
                restrict_to_path_with_sep = os.path.join(os.path.realpath(restrict_to_path), '')  # trailing slash
                if path_with_sep.startswith(restrict_to_path_with_sep):
                    break
            else:
                raise PathNotAllowed(path)
        self.repository = Repository(path, create, lock_wait=lock_wait, lock=lock,
                                     append_only=self.append_only or append_only,
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
            raise PathNotAllowed()
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
            named = {}
            for name, param in sig.parameters.items():
                if name == 'self':
                    continue
                if name in bound_args.arguments:
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

            return self.call(f.__name__, named)
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
        self.to_send = b''
        self.chunkid_to_msgids = {}
        self.ignore_responses = set()
        self.responses = {}
        self.ratelimit = SleepingBandwidthLimiter(args.remote_ratelimit * 1024 if args and args.remote_ratelimit else 0)

        self.unpacker = msgpack.Unpacker(use_list=False)
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
                version = self.call('negotiate', {'client_data': {b'client_version': BORG_VERSION}})
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
                self.rollback()
        finally:
            # in any case, we want to cleanly close the repo, even if the
            # rollback can not succeed (e.g. because the connection was
            # already closed) and raised another exception:
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
        env_vars = []
        if yes(env_var_override='BORG_HOSTNAME_IS_UNIQUE', env_msg=None, prompt=False):
            env_vars.append('BORG_HOSTNAME_IS_UNIQUE=yes')
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

    def call_many(self, cmd, calls, wait=True, is_preloaded=False):
        if not calls:
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
                raise PathNotAllowed()
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
                            if b'exception_class' in unpacked:
                                handle_error(unpacked)
                        else:
                            self.responses[msgid] = unpacked
                elif fd is self.stderr_fd:
                    data = os.read(fd, 32768)
                    if not data:
                        raise ConnectionClosed()
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
                        self.to_send = self.to_send[self.ratelimit.write(self.stdin_fd, self.to_send):]
                    except OSError as e:
                        # io.write might raise EAGAIN even though select indicates
                        # that the fd should be writable
                        if e.errno != errno.EAGAIN:
                            raise
        self.ignore_responses |= set(waiting_for)

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

    def preload(self, ids):
        self.preload_ids += ids


def handle_remote_line(line):
    if line.startswith('$LOG '):
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
        sys.stderr.write('Remote: ' + line)


class RepositoryNoCache:
    """A not caching Repository wrapper, passes through to repository.

    Just to have same API (including the context manager) as RepositoryCache.
    """
    def __init__(self, repository):
        self.repository = repository

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def get(self, key):
        return next(self.get_many([key]))

    def get_many(self, keys):
        for data in self.repository.get_many(keys):
            yield data


class RepositoryCache(RepositoryNoCache):
    """A caching Repository wrapper

    Caches Repository GET operations using a local temporary Repository.
    """
    # maximum object size that will be cached, 64 kiB.
    THRESHOLD = 2**16

    def __init__(self, repository):
        super().__init__(repository)
        tmppath = tempfile.mkdtemp(prefix='borg-tmp')
        self.caching_repo = Repository(tmppath, create=True, exclusive=True)
        self.caching_repo.__enter__()  # handled by context manager in base class

    def close(self):
        if self.caching_repo is not None:
            self.caching_repo.destroy()
            self.caching_repo = None

    def get_many(self, keys):
        unknown_keys = [key for key in keys if key not in self.caching_repo]
        repository_iterator = zip(unknown_keys, self.repository.get_many(unknown_keys))
        for key in keys:
            try:
                yield self.caching_repo.get(key)
            except Repository.ObjectNotFound:
                for key_, data in repository_iterator:
                    if key_ == key:
                        if len(data) <= self.THRESHOLD:
                            self.caching_repo.put(key, data)
                        yield data
                        break
        # Consume any pending requests
        for _ in repository_iterator:
            pass


def cache_if_remote(repository):
    if isinstance(repository, RemoteRepository):
        return RepositoryCache(repository)
    else:
        return RepositoryNoCache(repository)

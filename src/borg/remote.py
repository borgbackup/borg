import atexit
import errno
import functools
import inspect
import logging
import os
import queue
import select
import shlex
import shutil
import socket
import struct
import sys
import tempfile
import textwrap
import time
import traceback
from subprocess import Popen, PIPE

import borg.logger
from . import __version__
from .compress import Compressor
from .constants import *  # NOQA
from .helpers import Error, ErrorWithTraceback, IntegrityError
from .helpers import bin_to_hex
from .helpers import get_limited_unpacker
from .helpers import replace_placeholders
from .helpers import sysinfo
from .helpers import format_file_size
from .helpers import safe_unlink
from .helpers import prepare_subprocess_env, ignore_sigint
from .helpers import get_socket_filename
from .fslocking import LockTimeout, NotLocked, NotMyLock, LockFailed
from .logger import create_logger, borg_serve_log_queue
from .manifest import NoManifestError
from .helpers import msgpack
from .legacyrepository import LegacyRepository
from .repository import Repository
from .version import parse_version, format_version
from .checksums import xxh64
from .helpers.datastruct import EfficientCollectionQueue

logger = create_logger(__name__)

BORG_VERSION = parse_version(__version__)
MSGID, MSG, ARGS, RESULT, LOG = "i", "m", "a", "r", "l"

MAX_INFLIGHT = 100

RATELIMIT_PERIOD = 0.1


class ConnectionClosed(Error):
    """Connection closed by remote host"""

    exit_mcode = 80


class ConnectionClosedWithHint(ConnectionClosed):
    """Connection closed by remote host. {}"""

    exit_mcode = 81


class PathNotAllowed(Error):
    """Repository path not allowed: {}"""

    exit_mcode = 83


class InvalidRPCMethod(Error):
    """RPC method {} is not valid"""

    exit_mcode = 82


class UnexpectedRPCDataFormatFromClient(Error):
    """Borg {}: Got unexpected RPC data format from client."""

    exit_mcode = 85


class UnexpectedRPCDataFormatFromServer(Error):
    """Got unexpected RPC data format from server:\n{}"""

    exit_mcode = 86

    def __init__(self, data):
        try:
            data = data.decode()[:128]
        except UnicodeDecodeError:
            data = data[:128]
            data = ["%02X" % byte for byte in data]
            data = textwrap.fill(" ".join(data), 16 * 3)
        super().__init__(data)


class ConnectionBrokenWithHint(Error):
    """Connection to remote host is broken. {}"""

    exit_mcode = 87


# Protocol compatibility:
# In general the server is responsible for rejecting too old clients and the client it responsible for rejecting
# too old servers. This ensures that the knowledge what is compatible is always held by the newer component.
#
# For the client the return of the negotiate method is a dict which includes the server version.
#
# All method calls on the remote repository object must be allowlisted in RepositoryServer.rpc_methods and have api
# stubs in RemoteRepository*. The @api decorator on these stubs is used to set server version requirements.
#
# Method parameters are identified only by name and never by position. Unknown parameters are ignored by the server.
# If a new parameter is important and may not be ignored, on the client a parameter specific version requirement needs
# to be added.
# When parameters are removed, they need to be preserved as defaulted parameters on the client stubs so that older
# servers still get compatible input.


class RepositoryServer:  # pragma: no cover
    _legacy_rpc_methods = (  # LegacyRepository
        "__len__",
        "check",
        "commit",
        "delete",
        "destroy",
        "get",
        "list",
        "negotiate",
        "open",
        "close",
        "info",
        "put",
        "rollback",
        "save_key",
        "load_key",
        "break_lock",
        "inject_exception",
        "get_manifest",  # borg2 LegacyRepository has this
    )

    _rpc_methods = (  # Repository
        "__len__",
        "check",
        "delete",
        "destroy",
        "get",
        "list",
        "negotiate",
        "open",
        "close",
        "info",
        "put",
        "save_key",
        "load_key",
        "break_lock",
        "inject_exception",
        "get_manifest",
        "put_manifest",
        "store_list",
        "store_load",
        "store_store",
        "store_delete",
        "store_move",
    )

    def __init__(self, restrict_to_paths, restrict_to_repositories, use_socket, permissions=None):
        self.repository = None
        self.RepoCls = None
        self.rpc_methods = ("open", "close", "negotiate")
        self.restrict_to_paths = restrict_to_paths
        self.restrict_to_repositories = restrict_to_repositories
        self.permissions = permissions
        # This flag is parsed from the serve command line via Archiver.do_serve,
        # i.e. it reflects local system policy and generally ranks higher than
        # whatever the client wants, except when initializing a new repository
        # (see RepositoryServer.open below).
        self.client_version = None  # we update this after client sends version information
        if use_socket is False:
            self.socket_path = None
        elif use_socket is True:  # --socket
            self.socket_path = get_socket_filename()
        else:  # --socket=/some/path
            self.socket_path = use_socket

    def filter_args(self, f, kwargs):
        """Remove unknown named parameters from call, because client did (implicitly) say it's ok."""
        known = set(inspect.signature(f).parameters)
        return {name: kwargs[name] for name in kwargs if name in known}

    def send_queued_log(self):
        while True:
            try:
                # lr_dict contents see BorgQueueHandler
                lr_dict = borg_serve_log_queue.get_nowait()
            except queue.Empty:
                break
            else:
                msg = msgpack.packb({LOG: lr_dict})
                os.write(self.stdout_fd, msg)

    def serve(self):
        def inner_serve():
            os.set_blocking(self.stdin_fd, False)
            assert not os.get_blocking(self.stdin_fd)
            os.set_blocking(self.stdout_fd, True)
            assert os.get_blocking(self.stdout_fd)

            unpacker = get_limited_unpacker("server")
            shutdown_serve = False
            while True:
                # before processing any new RPCs, send out all pending log output
                self.send_queued_log()

                if shutdown_serve:
                    # shutdown wanted! get out of here after sending all log output.
                    assert self.repository is None
                    return

                # process new RPCs
                r, w, es = select.select([self.stdin_fd], [], [], 10)
                if r:
                    data = os.read(self.stdin_fd, BUFSIZE)
                    if not data:
                        shutdown_serve = True
                        continue
                    unpacker.feed(data)
                    for unpacked in unpacker:
                        if isinstance(unpacked, dict):
                            msgid = unpacked[MSGID]
                            method = unpacked[MSG]
                            args = unpacked[ARGS]
                        else:
                            if self.repository is not None:
                                self.repository.close()
                            raise UnexpectedRPCDataFormatFromClient(__version__)
                        try:
                            # logger.debug(f"{type(self)} method: {type(self.repository)}.{method}")
                            if method not in self.rpc_methods:
                                raise InvalidRPCMethod(method)
                            try:
                                f = getattr(self, method)
                            except AttributeError:
                                f = getattr(self.repository, method)
                            args = self.filter_args(f, args)
                            res = f(**args)
                        except BaseException as e:
                            # These exceptions are reconstructed on the client end in RemoteRepository.call_many(),
                            # and will be handled just like locally raised exceptions. Suppress the remote traceback
                            # for these, except ErrorWithTraceback, which should always display a traceback.
                            reconstructed_exceptions = (
                                Repository.InvalidRepository,
                                Repository.InvalidRepositoryConfig,
                                Repository.DoesNotExist,
                                Repository.AlreadyExists,
                                Repository.PathAlreadyExists,
                                PathNotAllowed,
                                Repository.InsufficientFreeSpaceError,
                            )
                            # logger.exception(e)
                            ex_short = traceback.format_exception_only(e.__class__, e)
                            ex_full = traceback.format_exception(*sys.exc_info())
                            ex_trace = True
                            if isinstance(e, Error):
                                ex_short = [e.get_message()]
                                ex_trace = e.traceback
                            if not isinstance(e, reconstructed_exceptions):
                                logging.debug("\n".join(ex_full))

                            sys_info = sysinfo()
                            try:
                                msg = msgpack.packb(
                                    {
                                        MSGID: msgid,
                                        "exception_class": e.__class__.__name__,
                                        "exception_args": e.args,
                                        "exception_full": ex_full,
                                        "exception_short": ex_short,
                                        "exception_trace": ex_trace,
                                        "sysinfo": sys_info,
                                    }
                                )
                            except TypeError:
                                msg = msgpack.packb(
                                    {
                                        MSGID: msgid,
                                        "exception_class": e.__class__.__name__,
                                        "exception_args": [
                                            x if isinstance(x, (str, bytes, int)) else None for x in e.args
                                        ],
                                        "exception_full": ex_full,
                                        "exception_short": ex_short,
                                        "exception_trace": ex_trace,
                                        "sysinfo": sys_info,
                                    }
                                )
                            os.write(self.stdout_fd, msg)
                        else:
                            os.write(self.stdout_fd, msgpack.packb({MSGID: msgid, RESULT: res}))
                if es:
                    shutdown_serve = True
                    continue

        if self.socket_path:  # server for socket:// connections
            try:
                # remove any left-over socket file
                os.unlink(self.socket_path)
            except OSError:
                if os.path.exists(self.socket_path):
                    raise
            sock_dir = os.path.dirname(self.socket_path)
            os.makedirs(sock_dir, exist_ok=True)
            if self.socket_path.endswith(".sock"):
                pid_file = self.socket_path.replace(".sock", ".pid")
            else:
                pid_file = self.socket_path + ".pid"
            pid = os.getpid()
            with open(pid_file, "w") as f:
                f.write(str(pid))
            atexit.register(functools.partial(os.remove, pid_file))
            atexit.register(functools.partial(os.remove, self.socket_path))
            sock = socket.socket(family=socket.AF_UNIX, type=socket.SOCK_STREAM)
            sock.bind(self.socket_path)  # this creates the socket file in the fs
            sock.listen(0)  # no backlog
            os.chmod(self.socket_path, mode=0o0770)  # group members may use the socket, too.
            print(f"borg serve: PID {pid}, listening on socket {self.socket_path} ...", file=sys.stderr)

            while True:
                connection, client_address = sock.accept()
                print(f"Accepted a connection on socket {self.socket_path} ...", file=sys.stderr)
                self.stdin_fd = connection.makefile("rb").fileno()
                self.stdout_fd = connection.makefile("wb").fileno()
                inner_serve()
                print(f"Finished with connection on socket {self.socket_path} .", file=sys.stderr)
        else:  # server for one ssh:// connection
            self.stdin_fd = sys.stdin.fileno()
            self.stdout_fd = sys.stdout.fileno()
            inner_serve()

    def negotiate(self, client_data):
        if isinstance(client_data, dict):
            self.client_version = client_data["client_version"]
        else:
            self.client_version = BORG_VERSION  # seems to be newer than current version (no known old format)

        # not a known old format, send newest negotiate this version knows
        return {"server_version": BORG_VERSION}

    def _resolve_path(self, path):
        if isinstance(path, bytes):
            path = os.fsdecode(path)
        path = os.path.realpath(path)
        return path

    def open(self, path, create=False, lock_wait=None, lock=True, exclusive=None, v1_or_v2=False):
        self.RepoCls = LegacyRepository if v1_or_v2 else Repository
        self.rpc_methods = self._legacy_rpc_methods if v1_or_v2 else self._rpc_methods
        logging.debug("Resolving repository path %r", path)
        path = self._resolve_path(path)
        logging.debug("Resolved repository path to %r", path)
        path_with_sep = os.path.join(path, "")  # make sure there is a trailing slash (os.sep)
        if self.restrict_to_paths:
            # if --restrict-to-path P is given, we make sure that we only operate in/below path P.
            # for the prefix check, it is important that the compared paths both have trailing slashes,
            # so that a path /foobar will NOT be accepted with --restrict-to-path /foo option.
            for restrict_to_path in self.restrict_to_paths:
                restrict_to_path_with_sep = os.path.join(os.path.realpath(restrict_to_path), "")  # trailing slash
                if path_with_sep.startswith(restrict_to_path_with_sep):
                    break
            else:
                raise PathNotAllowed(path)
        if self.restrict_to_repositories:
            for restrict_to_repository in self.restrict_to_repositories:
                restrict_to_repository_with_sep = os.path.join(os.path.realpath(restrict_to_repository), "")
                if restrict_to_repository_with_sep == path_with_sep:
                    break
            else:
                raise PathNotAllowed(path)
        kwargs = dict(lock_wait=lock_wait, lock=lock, exclusive=exclusive, send_log_cb=self.send_queued_log)
        if not v1_or_v2:
            kwargs["permissions"] = self.permissions
        self.repository = self.RepoCls(path, create, **kwargs)
        self.repository.__enter__()  # clean exit handled by serve() method
        return self.repository.id

    def close(self):
        if self.repository is not None:
            self.repository.__exit__(None, None, None)
            self.repository = None
        borg.logger.flush_logging()
        self.send_queued_log()

    def inject_exception(self, kind):
        s1 = "test string"
        s2 = "test string2"
        if kind == "DoesNotExist":
            raise self.RepoCls.DoesNotExist(s1)
        elif kind == "AlreadyExists":
            raise self.RepoCls.AlreadyExists(s1)
        elif kind == "CheckNeeded":
            raise self.RepoCls.CheckNeeded(s1)
        elif kind == "IntegrityError":
            raise IntegrityError(s1)
        elif kind == "PathNotAllowed":
            raise PathNotAllowed("foo")
        elif kind == "ObjectNotFound":
            raise self.RepoCls.ObjectNotFound(s1, s2)
        elif kind == "InvalidRPCMethod":
            raise InvalidRPCMethod(s1)
        elif kind == "divide":
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
                to_send = to_send[: self.ratelimit_quota]
        try:
            written = os.write(fd, to_send)
        except BrokenPipeError:
            raise ConnectionBrokenWithHint("Broken Pipe") from None
        if self.ratelimit:
            self.ratelimit_quota -= written
        return written


def api(*, since, **kwargs_decorator):
    """Check version requirements and use self.call to do the remote method call.

    <since> specifies the version in which borg introduced this method.
    Calling this method when connected to an older version will fail without transmitting anything to the server.

    Further kwargs can be used to encode version specific restrictions:

    <previously> is the value resulting in the behaviour before introducing the new parameter.
    If a previous hardcoded behaviour is parameterized in a version, this allows calls that use the previously
    hardcoded behaviour to pass through and generates an error if another behaviour is requested by the client.
    E.g. when 'append_only' was introduced in 1.0.7 the previous behaviour was what now is append_only=False.
    Thus @api(..., append_only={'since': parse_version('1.0.7'), 'previously': False}) allows calls
    with append_only=False for all version but rejects calls using append_only=True on versions older than 1.0.7.

    <dontcare> is a flag to set the behaviour if an old version is called the new way.
    If set to True, the method is called without the (not yet supported) parameter (this should be done if that is the
    more desirable behaviour). If False, an exception is generated.
    E.g. before 'threshold' was introduced in 1.2.0a8, a hardcoded threshold of 0.1 was used in commit().
    """

    def decorator(f):
        @functools.wraps(f)
        def do_rpc(self, *args, **kwargs):
            sig = inspect.signature(f)
            bound_args = sig.bind(self, *args, **kwargs)
            named = {}  # Arguments for the remote process
            extra = {}  # Arguments for the local process
            for name, param in sig.parameters.items():
                if name == "self":
                    continue
                if name in bound_args.arguments:
                    if name == "wait":
                        extra[name] = bound_args.arguments[name]
                    else:
                        named[name] = bound_args.arguments[name]
                else:
                    if param.default is not param.empty:
                        named[name] = param.default

            if self.server_version < since:
                raise self.RPCServerOutdated(f.__name__, format_version(since))

            for name, restriction in kwargs_decorator.items():
                if restriction["since"] <= self.server_version:
                    continue
                if "previously" in restriction and named[name] == restriction["previously"]:
                    continue
                if restriction.get("dontcare", False):
                    continue

                raise self.RPCServerOutdated(
                    f"{f.__name__} {name}={named[name]!s}", format_version(restriction["since"])
                )

            return self.call(f.__name__, named, **extra)

        return do_rpc

    return decorator


class RemoteRepository:
    extra_test_args = []  # type: ignore

    class RPCError(Exception):
        def __init__(self, unpacked):
            # unpacked has keys: 'exception_args', 'exception_full', 'exception_short', 'sysinfo'
            self.unpacked = unpacked

        def get_message(self):
            return "\n".join(self.unpacked["exception_short"])

        @property
        def traceback(self):
            return self.unpacked.get("exception_trace", True)

        @property
        def exception_class(self):
            return self.unpacked["exception_class"]

        @property
        def exception_full(self):
            return "\n".join(self.unpacked["exception_full"])

        @property
        def sysinfo(self):
            return self.unpacked["sysinfo"]

    class RPCServerOutdated(Error):
        """Borg server is too old for {}. Required version {}"""

        exit_mcode = 84

        @property
        def method(self):
            return self.args[0]

        @property
        def required_version(self):
            return self.args[1]

    def __init__(self, location, create=False, exclusive=False, lock_wait=1.0, lock=True, args=None):
        self.location = self._location = location
        self.preload_ids = []
        self.msgid = 0
        self.rx_bytes = 0
        self.tx_bytes = 0
        self.to_send = EfficientCollectionQueue(1024 * 1024, bytes)
        self.stdin_fd = self.stdout_fd = self.stderr_fd = None
        self.stderr_received = b""  # incomplete stderr line bytes received (no \n yet)
        self.chunkid_to_msgids = {}
        self.ignore_responses = set()
        self.responses = {}
        self.async_responses = {}
        self.shutdown_time = None
        self.ratelimit = SleepingBandwidthLimiter(args.upload_ratelimit * 1024 if args and args.upload_ratelimit else 0)
        self.upload_buffer_size_limit = args.upload_buffer * 1024 * 1024 if args and args.upload_buffer else 0
        self.unpacker = get_limited_unpacker("client")
        self.server_version = None  # we update this after server sends its version
        self.p = self.sock = None
        self._args = args
        if self.location.proto == "ssh":
            testing = location.host == "__testsuite__"
            # when testing, we invoke and talk to a borg process directly (no ssh).
            # when not testing, we invoke the system-installed ssh binary to talk to a remote borg.
            env = prepare_subprocess_env(system=not testing)
            borg_cmd = self.borg_cmd(args, testing)
            if not testing:
                borg_cmd = self.ssh_cmd(location) + borg_cmd
            logger.debug("SSH command line: %s", borg_cmd)
            # we do not want the ssh getting killed by Ctrl-C/SIGINT because it is needed for clean shutdown of borg.
            self.p = Popen(
                borg_cmd, bufsize=0, stdin=PIPE, stdout=PIPE, stderr=PIPE, env=env, preexec_fn=ignore_sigint
            )  # nosec B603
            self.stdin_fd = self.p.stdin.fileno()
            self.stdout_fd = self.p.stdout.fileno()
            self.stderr_fd = self.p.stderr.fileno()
            self.r_fds = [self.stdout_fd, self.stderr_fd]
            self.x_fds = [self.stdin_fd, self.stdout_fd, self.stderr_fd]
        elif self.location.proto == "socket":
            if args.use_socket is False or args.use_socket is True:  # nothing or --socket
                socket_path = get_socket_filename()
            else:  # --socket=/some/path
                socket_path = args.use_socket
            self.sock = socket.socket(family=socket.AF_UNIX, type=socket.SOCK_STREAM)
            try:
                self.sock.connect(socket_path)  # note: socket_path length is rather limited.
            except FileNotFoundError:
                self.sock = None
                raise Error(f"The socket file {socket_path} does not exist.")
            except ConnectionRefusedError:
                self.sock = None
                raise Error(f"There is no borg serve running for the socket file {socket_path}.")
            self.stdin_fd = self.sock.makefile("wb").fileno()
            self.stdout_fd = self.sock.makefile("rb").fileno()
            self.stderr_fd = None
            self.r_fds = [self.stdout_fd]
            self.x_fds = [self.stdin_fd, self.stdout_fd]
        else:
            raise Error(f"Unsupported protocol {location.proto}")

        os.set_blocking(self.stdin_fd, False)
        assert not os.get_blocking(self.stdin_fd)
        os.set_blocking(self.stdout_fd, False)
        assert not os.get_blocking(self.stdout_fd)
        if self.stderr_fd is not None:
            os.set_blocking(self.stderr_fd, False)
            assert not os.get_blocking(self.stderr_fd)

        try:
            try:
                version = self.call("negotiate", {"client_data": {"client_version": BORG_VERSION}})
            except ConnectionClosed:
                raise ConnectionClosedWithHint("Is borg working on the server?") from None
            if isinstance(version, dict):
                self.server_version = version["server_version"]
            else:
                raise Exception("Server insisted on using unsupported protocol version %s" % version)

            self.id = self.open(
                path=self.location.path, create=create, lock_wait=lock_wait, lock=lock, exclusive=exclusive
            )
            info = self.info()
            self.version = info["version"]

        except Exception:
            self.close()
            raise

    def __del__(self):
        if len(self.responses):
            logging.debug("still %d cached responses left in RemoteRepository" % (len(self.responses),))
        if self.p or self.sock:
            self.close()
            assert False, "cleanup happened in RemoteRepository.__del__"

    def __repr__(self):
        return f"<{self.__class__.__name__} {self.location.canonical_path()}>"

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            if exc_type is not None:
                self.shutdown_time = time.monotonic() + 30
        finally:
            # in any case, we want to close the repo cleanly.
            logger.debug(
                "RemoteRepository: %s bytes sent, %s bytes received, %d messages sent",
                format_file_size(self.tx_bytes),
                format_file_size(self.rx_bytes),
                self.msgid,
            )
            self.close()

    @property
    def id_str(self):
        return bin_to_hex(self.id)

    def borg_cmd(self, args, testing):
        """return a borg serve command line"""
        # give some args/options to 'borg serve' process as they were given to us
        opts = []
        if args is not None:
            root_logger = logging.getLogger()
            if root_logger.isEnabledFor(logging.DEBUG):
                opts.append("--debug")
            elif root_logger.isEnabledFor(logging.INFO):
                opts.append("--info")
            elif root_logger.isEnabledFor(logging.WARNING):
                pass  # warning is default
            elif root_logger.isEnabledFor(logging.ERROR):
                opts.append("--error")
            elif root_logger.isEnabledFor(logging.CRITICAL):
                opts.append("--critical")
            else:
                raise ValueError("log level missing, fix this code")

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
                if "." not in topic:
                    topic = "borg.debug." + topic
                if "repository" in topic:
                    opts.append("--debug-topic=%s" % topic)
        env_vars = []
        if testing:
            return env_vars + [sys.executable, "-m", "borg", "serve"] + opts + self.extra_test_args
        else:  # pragma: no cover
            remote_path = args.remote_path or os.environ.get("BORG_REMOTE_PATH", "borg")
            remote_path = replace_placeholders(remote_path)
            return env_vars + [remote_path, "serve"] + opts

    def ssh_cmd(self, location):
        """return a ssh command line that can be prefixed to a borg command line"""
        rsh = self._args.rsh or os.environ.get("BORG_RSH", "ssh")
        args = shlex.split(rsh)
        if location.port:
            args += ["-p", str(location.port)]
        if location.user:
            args.append(f"{location.user}@{location.host}")
        else:
            args.append("%s" % location.host)
        return args

    def call(self, cmd, args, **kw):
        for resp in self.call_many(cmd, [args], **kw):
            return resp

    def call_many(self, cmd, calls, wait=True, is_preloaded=False, async_wait=True):
        if not calls and cmd != "async_responses":
            return

        assert not is_preloaded or cmd == "get", "is_preloaded is only supported for 'get'"

        def send_buffer():
            if self.to_send:
                try:
                    written = self.ratelimit.write(self.stdin_fd, self.to_send.peek_front())
                    self.tx_bytes += written
                    self.to_send.pop_front(written)
                except OSError as e:
                    # io.write might raise EAGAIN even though select indicates
                    # that the fd should be writable.
                    # EWOULDBLOCK is added for defensive programming sake.
                    if e.errno not in [errno.EAGAIN, errno.EWOULDBLOCK]:
                        raise

        def pop_preload_msgid(chunkid):
            msgid = self.chunkid_to_msgids[chunkid].pop(0)
            if not self.chunkid_to_msgids[chunkid]:
                del self.chunkid_to_msgids[chunkid]
            return msgid

        def handle_error(unpacked):
            if "exception_class" not in unpacked:
                return

            error = unpacked["exception_class"]
            args = unpacked["exception_args"]

            if error == "Error":
                raise Error(args[0])
            elif error == "ErrorWithTraceback":
                raise ErrorWithTraceback(args[0])
            elif error == "InvalidRepository":
                raise Repository.InvalidRepository(self.location.processed)
            elif error == "DoesNotExist":
                raise Repository.DoesNotExist(self.location.processed)
            elif error == "AlreadyExists":
                raise Repository.AlreadyExists(self.location.processed)
            elif error == "CheckNeeded":
                raise Repository.CheckNeeded(self.location.processed)
            elif error == "IntegrityError":
                raise IntegrityError(args[0])
            elif error == "PathNotAllowed":
                raise PathNotAllowed(args[0])
            elif error == "PathPermissionDenied":
                raise Repository.PathPermissionDenied(args[0])
            elif error == "PathAlreadyExists":
                raise Repository.PathAlreadyExists(args[0])
            elif error == "ParentPathDoesNotExist":
                raise Repository.ParentPathDoesNotExist(args[0])
            elif error == "ObjectNotFound":
                raise Repository.ObjectNotFound(args[0], self.location.processed)
            elif error == "InvalidRPCMethod":
                raise InvalidRPCMethod(args[0])
            elif error == "LockTimeout":
                raise LockTimeout(args[0])
            elif error == "LockFailed":
                raise LockFailed(args[0], args[1])
            elif error == "NotLocked":
                raise NotLocked(args[0])
            elif error == "NotMyLock":
                raise NotMyLock(args[0])
            elif error == "NoManifestError":
                raise NoManifestError
            elif error == "InsufficientFreeSpaceError":
                raise Repository.InsufficientFreeSpaceError(args[0], args[1])
            elif error == "InvalidRepositoryConfig":
                raise Repository.InvalidRepositoryConfig(self.location.processed, args[1])
            else:
                raise self.RPCError(unpacked)

        calls = list(calls)
        waiting_for = []
        maximum_to_send = 0 if wait else self.upload_buffer_size_limit
        send_buffer()  # Try to send data, as some cases (async_response) will never try to send data otherwise.
        while wait or calls:
            logger.debug(
                f"call_many: calls: {len(calls)} waiting_for: {len(waiting_for)} responses: {len(self.responses)}"
            )
            if self.shutdown_time and time.monotonic() > self.shutdown_time:
                # we are shutting this RemoteRepository down already, make sure we do not waste
                # a lot of time in case a lot of async stuff is coming in or remote is gone or slow.
                logger.debug(
                    "shutdown_time reached, shutting down with %d waiting_for and %d async_responses.",
                    len(waiting_for),
                    len(self.async_responses),
                )
                return
            while waiting_for:
                try:
                    unpacked = self.responses.pop(waiting_for[0])
                    waiting_for.pop(0)
                    handle_error(unpacked)
                    yield unpacked[RESULT]
                    if not waiting_for and not calls:
                        return
                except KeyError:
                    break
            if cmd == "async_responses":
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
                        handle_error(unpacked)
                        yield unpacked[RESULT]
            if self.to_send or ((calls or self.preload_ids) and len(waiting_for) < MAX_INFLIGHT):
                w_fds = [self.stdin_fd]
            else:
                w_fds = []
            r, w, x = select.select(self.r_fds, w_fds, self.x_fds, 1)
            if x:
                raise Exception("FD exception occurred")
            for fd in r:
                if fd is self.stdout_fd:
                    data = os.read(fd, BUFSIZE)
                    if not data:
                        raise ConnectionClosed()
                    self.rx_bytes += len(data)
                    self.unpacker.feed(data)
                    for unpacked in self.unpacker:
                        if not isinstance(unpacked, dict):
                            raise UnexpectedRPCDataFormatFromServer(data)

                        lr_dict = unpacked.get(LOG)
                        if lr_dict is not None:
                            # Re-emit remote log messages locally.
                            _logger = logging.getLogger(lr_dict["name"])
                            if _logger.isEnabledFor(lr_dict["level"]):
                                _logger.handle(logging.LogRecord(**lr_dict))
                            continue

                        msgid = unpacked[MSGID]
                        if msgid in self.ignore_responses:
                            self.ignore_responses.remove(msgid)
                            # async methods never return values, but may raise exceptions.
                            if "exception_class" in unpacked:
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
                    # deal with incomplete lines (may appear due to block buffering)
                    if self.stderr_received:
                        data = self.stderr_received + data
                        self.stderr_received = b""
                    lines = data.splitlines(keepends=True)
                    if lines and not lines[-1].endswith((b"\r", b"\n")):
                        self.stderr_received = lines.pop()
                    # now we have complete lines in <lines> and any partial line in self.stderr_received.
                    _logger = logging.getLogger()
                    for line in lines:
                        # borg serve (remote/server side) should not emit stuff on stderr,
                        # but e.g. the ssh process (local/client side) might output errors there.
                        assert line.endswith((b"\r", b"\n"))
                        # something came in on stderr, log it to not lose it.
                        # decode late, avoid partial utf-8 sequences.
                        _logger.warning("stderr: " + line.decode().strip())
            if w:
                while (
                    (len(self.to_send) <= maximum_to_send)
                    and (calls or self.preload_ids)
                    and len(waiting_for) < MAX_INFLIGHT
                ):
                    if calls:
                        args = calls[0]
                        if cmd == "get" and args["id"] in self.chunkid_to_msgids:
                            # we have a get command and have already sent a request for this chunkid when
                            # doing preloading, so we know the msgid of the response we are waiting for:
                            waiting_for.append(pop_preload_msgid(args["id"]))
                            del calls[0]
                        elif not is_preloaded:
                            # make and send a request (already done if we are using preloading)
                            self.msgid += 1
                            waiting_for.append(self.msgid)
                            del calls[0]
                            self.to_send.push_back(msgpack.packb({MSGID: self.msgid, MSG: cmd, ARGS: args}))
                    if not self.to_send and self.preload_ids:
                        chunk_id = self.preload_ids.pop(0)
                        # for preloading chunks, the raise_missing behaviour is defined HERE,
                        # not in the get_many / fetch_many call that later fetches the preloaded chunks.
                        args = {"id": chunk_id, "raise_missing": False}
                        self.msgid += 1
                        self.chunkid_to_msgids.setdefault(chunk_id, []).append(self.msgid)
                        self.to_send.push_back(msgpack.packb({MSGID: self.msgid, MSG: "get", ARGS: args}))

                send_buffer()
        self.ignore_responses |= set(waiting_for)  # we lose order here

    @api(since=parse_version("1.0.0"), v1_or_v2={"since": parse_version("2.0.0b9"), "previously": True})
    def open(self, path, create=False, lock_wait=None, lock=True, exclusive=False, v1_or_v2=False):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version("2.0.0a3"))
    def info(self):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version("1.0.0"), max_duration={"since": parse_version("1.2.0a4"), "previously": 0})
    def check(self, repair=False, max_duration=0):
        """actual remoting is done via self.call in the @api decorator"""

    @api(
        since=parse_version("1.0.0"),
        compact={"since": parse_version("1.2.0a0"), "previously": True, "dontcare": True},
        threshold={"since": parse_version("1.2.0a8"), "previously": 0.1, "dontcare": True},
    )
    def commit(self, compact=True, threshold=0.1):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version("1.0.0"))
    def rollback(self):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version("1.0.0"))
    def destroy(self):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version("1.0.0"))
    def __len__(self):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version("1.0.0"))
    def list(self, limit=None, marker=None):
        """actual remoting is done via self.call in the @api decorator"""

    def get(self, id, read_data=True, raise_missing=True):
        for resp in self.get_many([id], read_data=read_data, raise_missing=raise_missing):
            return resp

    def get_many(self, ids, read_data=True, is_preloaded=False, raise_missing=True):
        yield from self.call_many(
            "get",
            [{"id": id, "read_data": read_data, "raise_missing": raise_missing} for id in ids],
            is_preloaded=is_preloaded,
        )

    @api(since=parse_version("1.0.0"))
    def put(self, id, data, wait=True):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version("1.0.0"))
    def delete(self, id, wait=True):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version("1.0.0"))
    def save_key(self, keydata):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version("1.0.0"))
    def load_key(self):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version("1.0.0"))
    def break_lock(self):
        """actual remoting is done via self.call in the @api decorator"""

    def close(self):
        if self.p or self.sock:
            self.call("close", {}, wait=True)
        if self.p:
            self.p.stdin.close()
            self.p.stdout.close()
            self.p.wait()
            self.p = None
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError as e:
                if e.errno != errno.ENOTCONN:
                    raise
            self.sock.close()
            self.sock = None

    def async_response(self, wait=True):
        for resp in self.call_many("async_responses", calls=[], wait=True, async_wait=wait):
            return resp

    def preload(self, ids):
        self.preload_ids += ids

    @api(since=parse_version("2.0.0b8"))
    def get_manifest(self):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version("2.0.0b8"))
    def put_manifest(self, data):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version("2.0.0b8"), deleted={"since": parse_version("2.0.0b14"), "previously": False})
    def store_list(self, name, *, deleted=False):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version("2.0.0b8"))
    def store_load(self, name):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version("2.0.0b8"))
    def store_store(self, name, value):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version("2.0.0b8"), deleted={"since": parse_version("2.0.0b14"), "previously": False})
    def store_delete(self, name, *, deleted=False):
        """actual remoting is done via self.call in the @api decorator"""

    @api(since=parse_version("2.0.0b14"))
    def store_move(self, name, new_name=None, *, delete=False, undelete=False, deleted=False):
        """actual remoting is done via self.call in the @api decorator"""


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

    def get(self, key, read_data=True, raise_missing=True):
        return next(self.get_many([key], read_data=read_data, raise_missing=raise_missing, cache=False))

    def get_many(self, keys, read_data=True, raise_missing=True, cache=True):
        for key, data in zip(keys, self.repository.get_many(keys, read_data=read_data, raise_missing=raise_missing)):
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
        self.basedir = tempfile.mkdtemp(prefix="borg-cache-")
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
        available_space = shutil.disk_usage(self.basedir).free
        self.size_limit = int(min(available_space * 0.25, 2**31))

    def prefixed_key(self, key, complete):
        # just prefix another byte telling whether this key refers to a complete chunk
        # or a without-data-metadata-only chunk (see also read_data param).
        prefix = b"\x01" if complete else b"\x00"
        return prefix + key

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

    def add_entry(self, key, data, cache, complete):
        transformed = self.transform(key, data)
        if not cache:
            return transformed
        packed = self.pack(transformed)
        pkey = self.prefixed_key(key, complete=complete)
        file = self.key_filename(pkey)
        try:
            with open(file, "wb") as fd:
                fd.write(packed)
        except OSError as os_error:
            try:
                safe_unlink(file)
            except FileNotFoundError:
                pass  # open() could have failed as well
            if os_error.errno == errno.ENOSPC:
                self.enospc += 1
                self.backoff()
            else:
                raise
        else:
            self.size += len(packed)
            self.cache.add(pkey)
            if self.size > self.size_limit:
                self.backoff()
        return transformed

    def log_instrumentation(self):
        logger.debug(
            "RepositoryCache: current items %d, size %s / %s, %d hits, %d misses, %d slow misses (+%.1fs), "
            "%d evictions, %d ENOSPC hit",
            len(self.cache),
            format_file_size(self.size),
            format_file_size(self.size_limit),
            self.hits,
            self.misses,
            self.slow_misses,
            self.slow_lat,
            self.evictions,
            self.enospc,
        )

    def close(self):
        self.log_instrumentation()
        self.cache.clear()
        shutil.rmtree(self.basedir)

    def get_many(self, keys, read_data=True, raise_missing=True, cache=True):
        # It could use different cache keys depending on read_data and cache full vs. meta-only chunks.
        unknown_keys = [key for key in keys if self.prefixed_key(key, complete=read_data) not in self.cache]
        repository_iterator = zip(
            unknown_keys, self.repository.get_many(unknown_keys, read_data=read_data, raise_missing=raise_missing)
        )
        for key in keys:
            pkey = self.prefixed_key(key, complete=read_data)
            if pkey in self.cache:
                file = self.key_filename(pkey)
                with open(file, "rb") as fd:
                    self.hits += 1
                    yield self.unpack(fd.read())
            else:
                for key_, data in repository_iterator:
                    if key_ == key:
                        transformed = self.add_entry(key, data, cache, complete=read_data)
                        self.misses += 1
                        yield transformed
                        break
                else:
                    # slow path: eviction during this get_many removed this key from the cache
                    t0 = time.perf_counter()
                    data = self.repository.get(key, read_data=read_data, raise_missing=raise_missing)
                    self.slow_lat += time.perf_counter() - t0
                    transformed = self.add_entry(key, data, cache, complete=read_data)
                    self.slow_misses += 1
                    yield transformed
        # Consume any pending requests
        for _ in repository_iterator:
            pass


def cache_if_remote(repository, *, decrypted_cache=False, pack=None, unpack=None, transform=None, force_cache=False):
    """
    Return a Repository(No)Cache for *repository*.

    If *decrypted_cache* is a repo_objs object, then get and get_many will return a tuple
    (csize, plaintext) instead of the actual data in the repository. The cache will
    store decrypted data, which increases CPU efficiency (by avoiding repeatedly decrypting
    and more importantly MAC and ID checking cached objects).
    Internally, objects are compressed with LZ4.
    """
    if decrypted_cache and (pack or unpack or transform):
        raise ValueError("decrypted_cache and pack/unpack/transform are incompatible")
    elif decrypted_cache:
        repo_objs = decrypted_cache
        # 32 bit csize, 64 bit (8 byte) xxh64, 1 byte ctype, 1 byte clevel
        cache_struct = struct.Struct("=I8sBB")
        compressor = Compressor("lz4")

        def pack(data):
            csize, decrypted = data
            meta, compressed = compressor.compress({}, decrypted)
            return cache_struct.pack(csize, xxh64(compressed), meta["ctype"], meta["clevel"]) + compressed

        def unpack(data):
            data = memoryview(data)
            csize, checksum, ctype, clevel = cache_struct.unpack(data[: cache_struct.size])
            compressed = data[cache_struct.size :]
            if checksum != xxh64(compressed):
                raise IntegrityError("detected corrupted data in metadata cache")
            meta = dict(ctype=ctype, clevel=clevel, csize=len(compressed))
            _, decrypted = compressor.decompress(meta, compressed)
            return csize, decrypted

        def transform(id_, data):
            meta, decrypted = repo_objs.parse(id_, data, ro_type=ROBJ_DONTCARE)
            csize = meta.get("csize", len(data))
            return csize, decrypted

    if isinstance(repository, RemoteRepository) or force_cache:
        return RepositoryCache(repository, pack, unpack, transform)
    else:
        return RepositoryNoCache(repository, transform)

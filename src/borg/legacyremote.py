import errno
import functools
import inspect
import logging
import os
import select
import shlex
import shutil
import socket
import struct
import sys
import tempfile
import textwrap
import time
from subprocess import Popen, PIPE

from . import __version__
from .compress import Compressor
from .constants import *  # NOQA
from .helpers import Error, ErrorWithTraceback, IntegrityError
from .helpers import bin_to_hex
from .helpers import get_limited_unpacker
from .helpers import replace_placeholders
from .helpers import format_file_size
from .helpers import safe_unlink
from .helpers import prepare_subprocess_env, ignore_sigint
from .helpers import get_socket_filename
from .fslocking import LockTimeout, NotLocked, NotMyLock, LockFailed
from .logger import create_logger
from .helpers import msgpack
from .legacyrepository import LegacyRepository
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
# stubs in LegacyRemoteRepository. The @api decorator on these stubs is used to set server version requirements.
#
# Method parameters are identified only by name and never by position. Unknown parameters are ignored by the server.
# If a new parameter is important and may not be ignored, on the client a parameter specific version requirement needs
# to be added.
# When parameters are removed, they need to be preserved as defaulted parameters on the client stubs so that older
# servers still get compatible input.


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


class LegacyRemoteRepository:
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

    def __init__(self, location, create=False, exclusive=False, lock_wait=None, lock=True, args=None):
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
                path=self.location.path,
                create=create,
                lock_wait=lock_wait,
                lock=lock,
                exclusive=exclusive,
                v1_or_v2=True,  # make remote use LegacyRepository
            )
            info = self.info()
            self.version = info["version"]

        except Exception:
            self.close()
            raise

    def __del__(self):
        if len(self.responses):
            logging.debug("still %d cached responses left in LegacyRemoteRepository" % (len(self.responses),))
        if self.p or self.sock:
            self.close()
            assert False, "cleanup happened in LegacyRemoteRepository.__del__"

    def __repr__(self):
        return f"<{self.__class__.__name__} {self.location.canonical_path()}>"

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            if exc_type is not None:
                self.shutdown_time = time.monotonic() + 30
                self.rollback()
        finally:
            # in any case, we want to close the repo cleanly, even if the
            # rollback can not succeed (e.g. because the connection was
            # already closed) and raised another exception:
            logger.debug(
                "LegacyRemoteRepository: %s bytes sent, %s bytes received, %d messages sent",
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
            elif error == "DoesNotExist":
                raise LegacyRepository.DoesNotExist(self.location.processed)
            elif error == "AlreadyExists":
                raise LegacyRepository.AlreadyExists(self.location.processed)
            elif error == "CheckNeeded":
                raise LegacyRepository.CheckNeeded(self.location.processed)
            elif error == "IntegrityError":
                raise IntegrityError(args[0])
            elif error == "PathNotAllowed":
                raise PathNotAllowed(args[0])
            elif error == "PathPermissionDenied":
                raise LegacyRepository.PathPermissionDenied(args[0])
            elif error == "ParentPathDoesNotExist":
                raise LegacyRepository.ParentPathDoesNotExist(args[0])
            elif error == "ObjectNotFound":
                raise LegacyRepository.ObjectNotFound(args[0], self.location.processed)
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
            else:
                raise self.RPCError(unpacked)

        calls = list(calls)
        waiting_for = []
        maximum_to_send = 0 if wait else self.upload_buffer_size_limit
        send_buffer()  # Try to send data, as some cases (async_response) will never try to send data otherwise.
        while wait or calls:
            if self.shutdown_time and time.monotonic() > self.shutdown_time:
                # we are shutting this LegacyRemoteRepository down already, make sure we do not waste
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
                        if is_preloaded:
                            assert cmd == "get", "is_preload is only supported for 'get'"
                            if calls[0]["id"] in self.chunkid_to_msgids:
                                waiting_for.append(pop_preload_msgid(calls.pop(0)["id"]))
                        else:
                            args = calls.pop(0)
                            if cmd == "get" and args["id"] in self.chunkid_to_msgids:
                                waiting_for.append(pop_preload_msgid(args["id"]))
                            else:
                                self.msgid += 1
                                waiting_for.append(self.msgid)
                                self.to_send.push_back(msgpack.packb({MSGID: self.msgid, MSG: cmd, ARGS: args}))
                    if not self.to_send and self.preload_ids:
                        chunk_id = self.preload_ids.pop(0)
                        args = {"id": chunk_id}
                        self.msgid += 1
                        self.chunkid_to_msgids.setdefault(chunk_id, []).append(self.msgid)
                        self.to_send.push_back(msgpack.packb({MSGID: self.msgid, MSG: "get", ARGS: args}))

                send_buffer()
        self.ignore_responses |= set(waiting_for)  # we lose order here

    @api(since=parse_version("1.0.0"), v1_or_v2={"since": parse_version("2.0.0b10"), "previously": True})
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

    def get(self, id, read_data=True):
        for resp in self.get_many([id], read_data=read_data):
            return resp

    def get_many(self, ids, read_data=True, is_preloaded=False):
        yield from self.call_many("get", [{"id": id, "read_data": read_data} for id in ids], is_preloaded=is_preloaded)

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

    def get(self, key, read_data=True):
        return next(self.get_many([key], read_data=read_data, cache=False))

    def get_many(self, keys, read_data=True, cache=True):
        for key, data in zip(keys, self.repository.get_many(keys, read_data=read_data)):
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

    def get_many(self, keys, read_data=True, cache=True):
        # It could use different cache keys depending on read_data and cache full vs. meta-only chunks.
        unknown_keys = [key for key in keys if self.prefixed_key(key, complete=read_data) not in self.cache]
        repository_iterator = zip(unknown_keys, self.repository.get_many(unknown_keys, read_data=read_data))
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
                    data = self.repository.get(key, read_data=read_data)
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

    if isinstance(repository, LegacyRemoteRepository) or force_cache:
        return RepositoryCache(repository, pack, unpack, transform)
    else:
        return RepositoryNoCache(repository, transform)

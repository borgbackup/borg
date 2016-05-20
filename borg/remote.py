import errno
import fcntl
import logging
import os
import select
import shlex
from subprocess import Popen, PIPE
import sys
import tempfile

from . import __version__

from .helpers import Error, IntegrityError, sysinfo
from .repository import Repository

import msgpack

RPC_PROTOCOL_VERSION = 2

BUFSIZE = 10 * 1024 * 1024


class ConnectionClosed(Error):
    """Connection closed by remote host"""


class ConnectionClosedWithHint(ConnectionClosed):
    """Connection closed by remote host. {}"""


class PathNotAllowed(Error):
    """Repository path not allowed"""


class InvalidRPCMethod(Error):
    """RPC method {} is not valid"""


class RepositoryServer:  # pragma: no cover
    rpc_methods = (
        '__len__',
        'check',
        'commit',
        'delete',
        'destroy',
        'get',
        'list',
        'negotiate',
        'open',
        'put',
        'rollback',
        'save_key',
        'load_key',
        'break_lock',
    )

    def __init__(self, restrict_to_paths):
        self.repository = None
        self.restrict_to_paths = restrict_to_paths

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
                    self.repository.close()
                    return
                unpacker.feed(data)
                for unpacked in unpacker:
                    if not (isinstance(unpacked, tuple) and len(unpacked) == 4):
                        self.repository.close()
                        raise Exception("Unexpected RPC data format.")
                    type, msgid, method, args = unpacked
                    method = method.decode('ascii')
                    try:
                        if method not in self.rpc_methods:
                            raise InvalidRPCMethod(method)
                        try:
                            f = getattr(self, method)
                        except AttributeError:
                            f = getattr(self.repository, method)
                        res = f(*args)
                    except BaseException as e:
                        # These exceptions are reconstructed on the client end in RemoteRepository.call_many(),
                        # and will be handled just like locally raised exceptions. Suppress the remote traceback
                        # for these, except ErrorWithTraceback, which should always display a traceback.
                        if not isinstance(e, (Repository.DoesNotExist, Repository.AlreadyExists, PathNotAllowed)):
                            logging.exception('Borg %s: exception in RPC call:', __version__)
                            logging.error(sysinfo())
                        exc = "Remote Exception (see remote log for the traceback)"
                        os.write(stdout_fd, msgpack.packb((1, msgid, e.__class__.__name__, exc)))
                    else:
                        os.write(stdout_fd, msgpack.packb((1, msgid, None, res)))
            if es:
                self.repository.close()
                return

    def negotiate(self, versions):
        return RPC_PROTOCOL_VERSION

    def open(self, path, create=False, lock_wait=None, lock=True):
        path = os.fsdecode(path)
        if path.startswith('/~'):
            path = path[1:]
        path = os.path.realpath(os.path.expanduser(path))
        if self.restrict_to_paths:
            for restrict_to_path in self.restrict_to_paths:
                if path.startswith(os.path.realpath(restrict_to_path)):
                    break
            else:
                raise PathNotAllowed(path)
        self.repository = Repository(path, create, lock_wait=lock_wait, lock=lock)
        self.repository.__enter__()  # clean exit handled by serve() method
        return self.repository.id


class RemoteRepository:
    extra_test_args = []

    class RPCError(Exception):
        def __init__(self, name):
            self.name = name

    def __init__(self, location, create=False, lock_wait=None, lock=True, args=None):
        self.location = self._location = location
        self.preload_ids = []
        self.msgid = 0
        self.to_send = b''
        self.cache = {}
        self.ignore_responses = set()
        self.responses = {}
        self.unpacker = msgpack.Unpacker(use_list=False)
        self.p = None
        testing = location.host == '__testsuite__'
        borg_cmd = self.borg_cmd(args, testing)
        env = dict(os.environ)
        if not testing:
            borg_cmd = self.ssh_cmd(location) + borg_cmd
            # pyinstaller binary adds LD_LIBRARY_PATH=/tmp/_ME... but we do not want
            # that the system's ssh binary picks up (non-matching) libraries from there
            env.pop('LD_LIBRARY_PATH', None)
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
            version = self.call('negotiate', RPC_PROTOCOL_VERSION)
        except ConnectionClosed:
            raise ConnectionClosedWithHint('Is borg working on the server?') from None
        if version != RPC_PROTOCOL_VERSION:
            raise Exception('Server insisted on using unsupported protocol version %d' % version)
        try:
            self.id = self.call('open', self.location.path, create, lock_wait, lock)
        except Exception:
            self.close()
            raise

    def __del__(self):
        if self.p:
            self.close()
            assert False, "cleanup happened in Repository.__del__"

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, self.location.canonical_path())

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.rollback()
        self.close()

    def borg_cmd(self, args, testing):
        """return a borg serve command line"""
        # give some args/options to "borg serve" process as they were given to us
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
        if testing:
            return [sys.executable, '-m', 'borg.archiver', 'serve'] + opts + self.extra_test_args
        else:  # pragma: no cover
            return [args.remote_path, 'serve'] + opts

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

    def call(self, cmd, *args, **kw):
        for resp in self.call_many(cmd, [args], **kw):
            return resp

    def call_many(self, cmd, calls, wait=True, is_preloaded=False):
        if not calls:
            return

        def fetch_from_cache(args):
            msgid = self.cache[args].pop(0)
            if not self.cache[args]:
                del self.cache[args]
            return msgid

        calls = list(calls)
        waiting_for = []
        w_fds = [self.stdin_fd]
        while wait or calls:
            while waiting_for:
                try:
                    error, res = self.responses.pop(waiting_for[0])
                    waiting_for.pop(0)
                    if error:
                        if error == b'DoesNotExist':
                            raise Repository.DoesNotExist(self.location.orig)
                        elif error == b'AlreadyExists':
                            raise Repository.AlreadyExists(self.location.orig)
                        elif error == b'CheckNeeded':
                            raise Repository.CheckNeeded(self.location.orig)
                        elif error == b'IntegrityError':
                            raise IntegrityError(res)
                        elif error == b'PathNotAllowed':
                            raise PathNotAllowed(*res)
                        elif error == b'ObjectNotFound':
                            raise Repository.ObjectNotFound(res[0], self.location.orig)
                        elif error == b'InvalidRPCMethod':
                            raise InvalidRPCMethod(*res)
                        else:
                            raise self.RPCError(res.decode('utf-8'))
                    else:
                        yield res
                        if not waiting_for and not calls:
                            return
                except KeyError:
                    break
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
                        if not (isinstance(unpacked, tuple) and len(unpacked) == 4):
                            raise Exception("Unexpected RPC data format.")
                        type, msgid, error, res = unpacked
                        if msgid in self.ignore_responses:
                            self.ignore_responses.remove(msgid)
                        else:
                            self.responses[msgid] = error, res
                elif fd is self.stderr_fd:
                    data = os.read(fd, 32768)
                    if not data:
                        raise ConnectionClosed()
                    data = data.decode('utf-8')
                    for line in data.splitlines(keepends=True):
                        if line.startswith('$LOG '):
                            _, level, msg = line.split(' ', 2)
                            level = getattr(logging, level, logging.CRITICAL)  # str -> int
                            logging.log(level, msg.rstrip())
                        else:
                            sys.stderr.write("Remote: " + line)
            if w:
                while not self.to_send and (calls or self.preload_ids) and len(waiting_for) < 100:
                    if calls:
                        if is_preloaded:
                            if calls[0] in self.cache:
                                waiting_for.append(fetch_from_cache(calls.pop(0)))
                        else:
                            args = calls.pop(0)
                            if cmd == 'get' and args in self.cache:
                                waiting_for.append(fetch_from_cache(args))
                            else:
                                self.msgid += 1
                                waiting_for.append(self.msgid)
                                self.to_send = msgpack.packb((1, self.msgid, cmd, args))
                    if not self.to_send and self.preload_ids:
                        args = (self.preload_ids.pop(0),)
                        self.msgid += 1
                        self.cache.setdefault(args, []).append(self.msgid)
                        self.to_send = msgpack.packb((1, self.msgid, cmd, args))

                if self.to_send:
                    try:
                        self.to_send = self.to_send[os.write(self.stdin_fd, self.to_send):]
                    except OSError as e:
                        # io.write might raise EAGAIN even though select indicates
                        # that the fd should be writable
                        if e.errno != errno.EAGAIN:
                            raise
                if not self.to_send and not (calls or self.preload_ids):
                    w_fds = []
        self.ignore_responses |= set(waiting_for)

    def check(self, repair=False, save_space=False):
        return self.call('check', repair, save_space)

    def commit(self, save_space=False):
        return self.call('commit', save_space)

    def rollback(self, *args):
        return self.call('rollback')

    def destroy(self):
        return self.call('destroy')

    def __len__(self):
        return self.call('__len__')

    def list(self, limit=None, marker=None):
        return self.call('list', limit, marker)

    def get(self, id_):
        for resp in self.get_many([id_]):
            return resp

    def get_many(self, ids, is_preloaded=False):
        for resp in self.call_many('get', [(id_,) for id_ in ids], is_preloaded=is_preloaded):
            yield resp

    def put(self, id_, data, wait=True):
        return self.call('put', id_, data, wait=wait)

    def delete(self, id_, wait=True):
        return self.call('delete', id_, wait=wait)

    def save_key(self, keydata):
        return self.call('save_key', keydata)

    def load_key(self):
        return self.call('load_key')

    def break_lock(self):
        return self.call('break_lock')

    def close(self):
        if self.p:
            self.p.stdin.close()
            self.p.stdout.close()
            self.p.wait()
            self.p = None

    def preload(self, ids):
        self.preload_ids += ids


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

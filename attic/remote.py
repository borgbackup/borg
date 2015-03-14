import errno
import fcntl
import msgpack
import os
import select
import shutil
from subprocess import Popen, PIPE
import sys
import tempfile

from .hashindex import NSIndex
from .helpers import Error, IntegrityError
from .repository import Repository

BUFSIZE = 10 * 1024 * 1024


class ConnectionClosed(Error):
    """Connection closed by remote host"""


class PathNotAllowed(Error):
    """Repository path not allowed"""


class RepositoryServer(object):

    def __init__(self, restrict_to_paths):
        self.repository = None
        self.restrict_to_paths = restrict_to_paths

    def serve(self):
        stdin_fd = sys.stdin.fileno()
        stdout_fd = sys.stdout.fileno()
        # Make stdin non-blocking
        fl = fcntl.fcntl(stdin_fd, fcntl.F_GETFL)
        fcntl.fcntl(stdin_fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        # Make stdout blocking
        fl = fcntl.fcntl(stdout_fd, fcntl.F_GETFL)
        fcntl.fcntl(stdout_fd, fcntl.F_SETFL, fl & ~os.O_NONBLOCK)
        unpacker = msgpack.Unpacker(use_list=False)
        while True:
            r, w, es = select.select([stdin_fd], [], [], 10)
            if r:
                data = os.read(stdin_fd, BUFSIZE)
                if not data:
                    return
                unpacker.feed(data)
                for type, msgid, method, args in unpacker:
                    method = method.decode('ascii')
                    try:
                        try:
                            f = getattr(self, method)
                        except AttributeError:
                            f = getattr(self.repository, method)
                        res = f(*args)
                    except Exception as e:
                        os.write(stdout_fd, msgpack.packb((1, msgid, e.__class__.__name__, e.args)))
                    else:
                        os.write(stdout_fd, msgpack.packb((1, msgid, None, res)))
            if es:
                return

    def negotiate(self, versions):
        return 1

    def open(self, path, create=False):
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
        self.repository = Repository(path, create)
        return self.repository.id


class RemoteRepository(object):
    extra_test_args = []

    class RPCError(Exception):

        def __init__(self, name):
            self.name = name

    def __init__(self, location, create=False):
        self.location = location
        self.preload_ids = []
        self.msgid = 0
        self.to_send = b''
        self.cache = {}
        self.ignore_responses = set()
        self.responses = {}
        self.unpacker = msgpack.Unpacker(use_list=False)
        self.p = None
        if location.host == '__testsuite__':
            args = [sys.executable, '-m', 'attic.archiver', 'serve'] + self.extra_test_args
        else:
            args = ['ssh']
            if location.port:
                args += ['-p', str(location.port)]
            if location.user:
                args.append('%s@%s' % (location.user, location.host))
            else:
                args.append('%s' % location.host)
            args += ['attic', 'serve']
        self.p = Popen(args, bufsize=0, stdin=PIPE, stdout=PIPE)
        self.stdin_fd = self.p.stdin.fileno()
        self.stdout_fd = self.p.stdout.fileno()
        fcntl.fcntl(self.stdin_fd, fcntl.F_SETFL, fcntl.fcntl(self.stdin_fd, fcntl.F_GETFL) | os.O_NONBLOCK)
        fcntl.fcntl(self.stdout_fd, fcntl.F_SETFL, fcntl.fcntl(self.stdout_fd, fcntl.F_GETFL) | os.O_NONBLOCK)
        self.r_fds = [self.stdout_fd]
        self.x_fds = [self.stdin_fd, self.stdout_fd]

        version = self.call('negotiate', 1)
        if version != 1:
            raise Exception('Server insisted on using unsupported protocol version %d' % version)
        self.id = self.call('open', location.path, create)

    def __del__(self):
        self.close()

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
                        if error == b'ObjectNotFound':
                            raise Repository.ObjectNotFound(res[0], self.location.orig)
                        raise self.RPCError(error)
                    else:
                        yield res
                        if not waiting_for and not calls:
                            return
                except KeyError:
                    break
            r, w, x = select.select(self.r_fds, w_fds, self.x_fds, 1)
            if x:
                raise Exception('FD exception occured')
            if r:
                data = os.read(self.stdout_fd, BUFSIZE)
                if not data:
                    raise ConnectionClosed()
                self.unpacker.feed(data)
                for type, msgid, error, res in self.unpacker:
                    if msgid in self.ignore_responses:
                        self.ignore_responses.remove(msgid)
                    else:
                        self.responses[msgid] = error, res
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

    def check(self, repair=False):
        return self.call('check', repair)

    def commit(self, *args):
        return self.call('commit')

    def rollback(self, *args):
        return self.call('rollback')

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

    def close(self):
        if self.p:
            self.p.stdin.close()
            self.p.stdout.close()
            self.p.wait()
            self.p = None

    def preload(self, ids):
        self.preload_ids += ids


class RepositoryCache:
    """A caching Repository wrapper

    Caches Repository GET operations using a temporary file
    """
    def __init__(self, repository):
        self.tmppath = None
        self.index = None
        self.data_fd = None
        self.repository = repository
        self.entries = {}
        self.initialize()

    def __del__(self):
        self.cleanup()

    def initialize(self):
        self.tmppath = tempfile.mkdtemp()
        self.index = NSIndex()
        self.data_fd = open(os.path.join(self.tmppath, 'data'), 'a+b')

    def cleanup(self):
        del self.index
        if self.data_fd:
            self.data_fd.close()
        if self.tmppath:
            shutil.rmtree(self.tmppath)

    def load_object(self, offset, size):
        self.data_fd.seek(offset)
        data = self.data_fd.read(size)
        assert len(data) == size
        return data

    def store_object(self, key, data):
        self.data_fd.seek(0, os.SEEK_END)
        self.data_fd.write(data)
        offset = self.data_fd.tell()
        self.index[key] = offset - len(data), len(data)

    def get(self, key):
        return next(self.get_many([key]))

    def get_many(self, keys):
        unknown_keys = [key for key in keys if not key in self.index]
        repository_iterator = zip(unknown_keys, self.repository.get_many(unknown_keys))
        for key in keys:
            try:
                yield self.load_object(*self.index[key])
            except KeyError:
                for key_, data in repository_iterator:
                    if key_ == key:
                        self.store_object(key, data)
                        yield data
                        break
        # Consume any pending requests
        for _ in repository_iterator:
            pass


def cache_if_remote(repository):
    if isinstance(repository, RemoteRepository):
        return RepositoryCache(repository)
    return repository

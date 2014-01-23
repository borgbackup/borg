import fcntl
import msgpack
import os
import select
from subprocess import Popen, PIPE
import sys

from .helpers import Error
from .repository import Repository

BUFSIZE = 10 * 1024 * 1024


class ConnectionClosed(Error):
    """Connection closed by remote host"""


class RepositoryServer(object):

    def __init__(self):
        self.repository = None

    def serve(self):
        # Make stdin non-blocking
        fl = fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL)
        fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, fl | os.O_NONBLOCK)
        # Make stdout blocking
        fl = fcntl.fcntl(sys.stdout.fileno(), fcntl.F_GETFL)
        fcntl.fcntl(sys.stdout.fileno(), fcntl.F_SETFL, fl & ~os.O_NONBLOCK)
        unpacker = msgpack.Unpacker(use_list=False)
        while True:
            r, w, es = select.select([sys.stdin], [], [], 10)
            if r:
                data = os.read(sys.stdin.fileno(), BUFSIZE)
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
                        sys.stdout.buffer.write(msgpack.packb((1, msgid, e.__class__.__name__, e.args)))
                    else:
                        sys.stdout.buffer.write(msgpack.packb((1, msgid, None, res)))
                    sys.stdout.flush()
            if es:
                return

    def negotiate(self, versions):
        return 1

    def open(self, path, create=False):
        path = os.fsdecode(path)
        if path.startswith('/~'):
            path = path[1:]
        self.repository = Repository(os.path.expanduser(path), create)
        return self.repository.id


class RemoteRepository(object):

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
            args = [sys.executable, '-m', 'attic.archiver', 'serve']
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
                    self.to_send = self.to_send[os.write(self.stdin_fd, self.to_send):]
                if not self.to_send and not (calls or self.preload_ids):
                    w_fds = []
        self.ignore_responses |= set(waiting_for)

    def commit(self, *args):
        return self.call('commit')

    def rollback(self, *args):
        return self.call('rollback')

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

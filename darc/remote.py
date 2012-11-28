from __future__ import with_statement
import fcntl
import msgpack
import os
import select
from subprocess import Popen, PIPE
import sys
import getpass

from .store import Store
from .lrucache import LRUCache

BUFSIZE = 10 * 1024 * 1024


class StoreServer(object):

    def __init__(self):
        self.store = None

    def serve(self):
        # Make stdin non-blocking
        fl = fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL)
        fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, fl | os.O_NONBLOCK)
        # Make stdout blocking
        fl = fcntl.fcntl(sys.stdout.fileno(), fcntl.F_GETFL)
        fcntl.fcntl(sys.stdout.fileno(), fcntl.F_SETFL, fl & ~os.O_NONBLOCK)
        unpacker = msgpack.Unpacker()
        while True:
            r, w, es = select.select([sys.stdin], [], [], 10)
            if r:
                data = os.read(sys.stdin.fileno(), BUFSIZE)
                if not data:
                    return
                unpacker.feed(data)
                for type, msgid, method, args in unpacker:
                    try:
                        try:
                            f = getattr(self, method)
                        except AttributeError:
                            f = getattr(self.store, method)
                        res = f(*args)
                    except Exception, e:
                        sys.stdout.write(msgpack.packb((1, msgid, e.__class__.__name__, None)))
                    else:
                        sys.stdout.write(msgpack.packb((1, msgid, None, res)))
                    sys.stdout.flush()
            if es:
                return

    def negotiate(self, versions):
        return 1

    def open(self, path, create=False):
        if path.startswith('/~'):
            path = path[1:]
        self.store = Store(os.path.expanduser(path), create)
        return self.store.id


class RemoteStore(object):

    class DoesNotExist(Exception):
        pass

    class AlreadyExists(Exception):
        pass

    class RPCError(Exception):

        def __init__(self, name):
            self.name = name

    def __init__(self, location, create=False):
        self.cache = LRUCache(200)
        self.to_send = ''
        self.extra = {}
        self.pending = {}
        self.unpacker = msgpack.Unpacker()
        self.msgid = 0
        self.received_msgid = 0
        args = ['ssh', '-p', str(location.port), '%s@%s' % (location.user or getpass.getuser(), location.host), 'darc', 'serve']
        self.p = Popen(args, bufsize=0, stdin=PIPE, stdout=PIPE)
        self.stdin_fd = self.p.stdin.fileno()
        self.stdout_fd = self.p.stdout.fileno()
        self.r_fds = [self.stdout_fd]
        self.x_fds = [self.stdin_fd, self.stdout_fd]

        version = self.call('negotiate', (1,))
        if version != 1:
            raise Exception('Server insisted on using unsupported protocol version %d' % version)
        self.id = self.call('open', (location.path, create))

    def __del__(self):
        self.p.stdin.close()
        self.p.stdout.close()
        self.p.wait()

    def _read(self):
        data = os.read(self.stdout_fd, BUFSIZE)
        if not data:
            raise Exception('EOF')
        self.unpacker.feed(data)
        to_yield = []
        for type, msgid, error, res in self.unpacker:
            self.received_msgid = msgid
            if error:
                raise self.RPCError(error)
            args = self.pending.pop(msgid)
            self.cache[args] = msgid, res
            for args, resp in self.extra.pop(msgid, []):
                to_yield.append(resp or self.cache[args][1])
        for res in to_yield:
            yield res

    def call(self, cmd, args, wait=True):
        for res in self.call_multi(cmd, [args], wait=wait):
            return res

    def gen_request(self, cmd, argsv):
        data = []
        m = self.received_msgid
        for args in argsv:
            if not args in self.cache:
                self.msgid += 1
                msgid = self.msgid
                self.pending[msgid] = args
                self.cache[args] = msgid, None
                data.append(msgpack.packb((1, msgid, cmd, args)))
            msgid, resp = self.cache[args]
            m = max(m, msgid)
            self.extra.setdefault(m, []).append((args, resp))
        return ''.join(data)

    def gen_cache_requests(self, cmd, peek):
        data = []
        while True:
            try:
                args = (peek()[0],)
            except StopIteration:
                break
            if args in self.cache:
                continue
            self.msgid += 1
            msgid = self.msgid
            self.pending[msgid] = args
            self.cache[args] = msgid, None
            data.append(msgpack.packb((1, msgid, cmd, args)))
        return ''.join(data)

    def call_multi(self, cmd, argsv, wait=True, peek=None):
        w_fds = [self.stdin_fd]
        left = len(argsv)
        data = self.gen_request(cmd, argsv)
        self.to_send += data
        for args, resp in self.extra.pop(self.received_msgid, []):
            left -= 1
            yield resp or self.cache[args][1]
        while left:
            r, w, x = select.select(self.r_fds, w_fds, self.x_fds, 1)
            if x:
                raise Exception('FD exception occured')
            if r:
                for res in self._read():
                    left -= 1
                    yield res
            if w:
                if not self.to_send and peek:
                    self.to_send = self.gen_cache_requests(cmd, peek)
                if self.to_send:
                    n = os.write(self.stdin_fd, self.to_send)
                    assert n > 0
                    self.to_send = self.to_send[n:]
                else:
                    w_fds = []

    def commit(self, *args):
        self.call('commit', args)

    def rollback(self, *args):
        return self.call('rollback', args)

    def get(self, id):
        try:
            return self.call('get', (id, ))
        except self.RPCError, e:
            if e.name == 'DoesNotExist':
                raise self.DoesNotExist
            raise

    def get_many(self, ids, peek=None):
        return self.call_multi('get', [(id, ) for id in ids], peek=peek)

    def put(self, id, data, wait=True):
        try:
            return self.call('put', (id, data), wait=wait)
        except self.RPCError, e:
            if e.name == 'AlreadyExists':
                raise self.AlreadyExists

    def delete(self, id, wait=True):
        return self.call('delete', (id, ), wait=wait)

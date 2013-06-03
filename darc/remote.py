import fcntl
import msgpack
import os
import select
from subprocess import Popen, PIPE
import sys
import getpass
import unittest

from .store import Store, StoreTestCase
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
                            f = getattr(self.store, method)
                        res = f(*args)
                    except Exception as e:
                        sys.stdout.buffer.write(msgpack.packb((1, msgid, e.__class__.__name__, None)))
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
        self.store = Store(os.path.expanduser(path), create)
        return self.store.id


class RemoteStore(object):

    class RPCError(Exception):

        def __init__(self, name):
            self.name = name

    def __init__(self, location, create=False):
        self.p = None
        self.cache = LRUCache(256)
        self.to_send = b''
        self.extra = {}
        self.pending = {}
        self.unpacker = msgpack.Unpacker(use_list=False)
        self.msgid = 0
        self.received_msgid = 0
        args = ['ssh', '-p', str(location.port), '%s@%s' % (location.user or getpass.getuser(), location.host), 'darc', 'serve']
        self.p = Popen(args, bufsize=0, stdin=PIPE, stdout=PIPE)
        self.stdin_fd = self.p.stdin.fileno()
        self.stdout_fd = self.p.stdout.fileno()
        fcntl.fcntl(self.stdin_fd, fcntl.F_SETFL, fcntl.fcntl(self.stdin_fd, fcntl.F_GETFL) | os.O_NONBLOCK)
        fcntl.fcntl(self.stdout_fd, fcntl.F_SETFL, fcntl.fcntl(self.stdout_fd, fcntl.F_GETFL) | os.O_NONBLOCK)
        self.r_fds = [self.stdout_fd]
        self.x_fds = [self.stdin_fd, self.stdout_fd]

        version = self.call('negotiate', (1,))
        if version != 1:
            raise Exception('Server insisted on using unsupported protocol version %d' % version)
        try:
            self.id = self.call('open', (location.path, create))
        except self.RPCError as e:
            if e.name == b'DoesNotExist':
                raise Store.DoesNotExist
            elif e.name == b'AlreadyExists':
                raise Store.AlreadyExists

    def __del__(self):
        self.close()

    def call(self, cmd, args, wait=True):
        self.msgid += 1
        to_send = msgpack.packb((1, self.msgid, cmd, args))
        w_fds = [self.stdin_fd]
        while wait or to_send:
            r, w, x = select.select(self.r_fds, w_fds, self.x_fds, 1)
            if x:
                raise Exception('FD exception occured')
            if r:
                data = os.read(self.stdout_fd, BUFSIZE)
                if not data:
                    raise Exception('Remote host closed connection')
                self.unpacker.feed(data)
                for type, msgid, error, res in self.unpacker:
                    if msgid == self.msgid:
                        assert msgid == self.msgid
                        self.received_msgid = msgid
                        if error:
                            raise self.RPCError(error)
                        else:
                            return res
                    else:
                        args = self.pending.pop(msgid, None)
                        if args is not None:
                            self.cache[args] = msgid, res, error
            if w:
                if to_send:
                    n = os.write(self.stdin_fd, to_send)
                    assert n > 0
                    to_send = memoryview(to_send)[n:]
                else:
                    w_fds = []

    def _read(self):
        data = os.read(self.stdout_fd, BUFSIZE)
        if not data:
            raise Exception('Remote host closed connection')
        self.unpacker.feed(data)
        to_yield = []
        for type, msgid, error, res in self.unpacker:
            self.received_msgid = msgid
            args = self.pending.pop(msgid, None)
            if args is not None:
                self.cache[args] = msgid, res, error
                for args, resp, error in self.extra.pop(msgid, []):
                    if not resp and not error:
                        resp, error = self.cache[args][1:]
                    to_yield.append((resp, error))
        for res, error in to_yield:
            if error:
                raise self.RPCError(error)
            else:
                yield res

    def gen_request(self, cmd, argsv, wait):
        data = []
        m = self.received_msgid
        for args in argsv:
            # Make sure to invalidate any existing cache entries for non-get requests
            if not args in self.cache:
                self.msgid += 1
                msgid = self.msgid
                self.pending[msgid] = args
                self.cache[args] = msgid, None, None
                data.append(msgpack.packb((1, msgid, cmd, args)))
            if wait:
                msgid, resp, error = self.cache[args]
                m = max(m, msgid)
                self.extra.setdefault(m, []).append((args, resp, error))
        return b''.join(data)

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
            self.cache[args] = msgid, None, None
            data.append(msgpack.packb((1, msgid, cmd, args)))
        return b''.join(data)

    def call_multi(self, cmd, argsv, wait=True, peek=None):
        w_fds = [self.stdin_fd]
        left = len(argsv)
        data = self.gen_request(cmd, argsv, wait)
        self.to_send += data
        for args, resp, error in self.extra.pop(self.received_msgid, []):
            left -= 1
            if not resp and not error:
                resp, error = self.cache[args][1:]
            if error:
                raise self.RPCError(error)
            else:
                yield resp
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
#                    self.to_send = memoryview(self.to_send)[n:]
                    self.to_send = self.to_send[n:]
                else:
                    w_fds = []
                    if not wait:
                        return

    def commit(self, *args):
        self.call('commit', args)

    def rollback(self, *args):
        self.cache.clear()
        self.pending.clear()
        self.extra.clear()
        return self.call('rollback', args)

    def get(self, id):
        try:
            for res in self.call_multi('get', [(id, )]):
                return res
        except self.RPCError as e:
            if e.name == b'DoesNotExist':
                raise Store.DoesNotExist
            raise

    def get_many(self, ids, peek=None):
        return self.call_multi('get', [(id, ) for id in ids], peek=peek)

    def _invalidate(self, id):
        key = (id, )
        if key in self.cache:
            self.pending.pop(self.cache.pop(key)[0], None)

    def put(self, id, data, wait=True):
        resp = self.call('put', (id, data), wait=wait)
        self._invalidate(id)
        return resp

    def delete(self, id, wait=True):
        resp = self.call('delete', (id, ), wait=wait)
        self._invalidate(id)
        return resp

    def close(self):
        if self.p:
            self.p.stdin.close()
            self.p.stdout.close()
            self.p.wait()
            self.p = None


class RemoteStoreTestCase(StoreTestCase):

    def open(self, create=False):
        from .helpers import Location
        return RemoteStore(Location('localhost:' + os.path.join(self.tmppath, 'store')), create=create)


def suite():
    return unittest.TestLoader().loadTestsFromTestCase(RemoteStoreTestCase)

if __name__ == '__main__':
    unittest.main()


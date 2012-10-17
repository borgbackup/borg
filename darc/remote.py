from __future__ import with_statement
import fcntl
import msgpack
import os
import select
from subprocess import Popen, PIPE
import sys
import getpass

from .store import Store

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
        self.unpacker = msgpack.Unpacker()
        self.msgid = 0
        args = ['ssh', '-p', str(location.port), '%s@%s' % (location.user or getpass.getuser(), location.host), 'darc', 'serve']
        self.p = Popen(args, bufsize=0, stdin=PIPE, stdout=PIPE)
        self.stdout_fd = self.p.stdout.fileno()
        version = self.call('negotiate', (1,))
        if version != 1:
            raise Exception('Server insisted on using unsupported protocol version %d' % version)
        self.id = self.call('open', (location.path, create))

    def __del__(self):
        self.p.stdin.close()
        self.p.stdout.close()
        self.p.wait()

    def _read(self, msgids):
        data = os.read(self.stdout_fd, BUFSIZE)
        self.unpacker.feed(data)
        for type, msgid, error, res in self.unpacker:
            if error:
                raise self.RPCError(error)
            if msgid in msgids:
                msgids.remove(msgid)
                yield res

    def call(self, cmd, args, wait=True):
        for res in self.call_multi(cmd, [args], wait=wait):
            return res

    def call_multi(self, cmd, argsv, wait=True):
        msgids = set()
        for args in argsv:
            if select.select([self.stdout_fd], [], [], 0)[0]:
                for res in self._read(msgids):
                    yield res
            self.msgid += 1
            msgid = self.msgid
            msgids.add(msgid)
            self.p.stdin.write(msgpack.packb((1, msgid, cmd, args)))
        while msgids and wait:
            for res in self._read(msgids):
                yield res

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

    def get_many(self, ids):
        return self.call_multi('get', [(id, ) for id in ids])

    def put(self, id, data, wait=True):
        try:
            return self.call('put', (id, data), wait=wait)
        except self.RPCError, e:
            if e.name == 'AlreadyExists':
                raise self.AlreadyExists

    def delete(self, id, wait=True):
        return self.call('delete', (id, ), wait=wait)

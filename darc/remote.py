import fcntl
import msgpack
import os
import paramiko
import select
import sys
import getpass

from .store import Store


BUFSIZE = 1024 * 1024


class StoreServer(object):

    def __init__(self):
        self.store = None

    def serve(self):
        # Make stdin non-blocking
        fl = fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL)
        fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, fl | os.O_NONBLOCK)
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

    def open(self, path, create=False):
        if path.startswith('/~'):
            path = path[1:]
        self.store = Store(os.path.expanduser(path), create)
        return self.store.id, self.store.tid


class RemoteStore(object):

    class DoesNotExist(Exception):
        pass

    class AlreadyExists(Exception):
        pass

    class RPCError(Exception):

        def __init__(self, name):
            self.name = name


    def __init__(self, location, create=False):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        params = {'username': location.user or getpass.getuser(),
                  'hostname': location.host, 'port': location.port}
        while True:
            try:
                self.client.connect(**params)
                break
            except (paramiko.PasswordRequiredException,
		    paramiko.AuthenticationException,
		    paramiko.SSHException):
		if not 'password' in params:
			params['password'] = getpass.getpass('Password for %(username)s@%(hostname)s:' % params)
		else:
		    raise

        self.unpacker = msgpack.Unpacker()
        self.transport = self.client.get_transport()
        self.channel = self.transport.open_session()
        self.channel.exec_command('darc serve')
        self.msgid = 0
        self.id, self.tid = self._cmd('open', (location.path, create))

    def _cmd(self, cmd, args):
        self.msgid += 1
        self.channel.sendall(msgpack.packb((0, self.msgid, cmd, args)))
        while True:
            r, w, e = select.select([self.channel], [], [self.channel], 10)
            if r:
                if self.channel.closed:
                    raise Exception('Connection closed')
                if self.channel.recv_stderr_ready():
                    print >> sys.stderr, 'remote stderr:', self.channel.recv_stderr(BUFSIZE)
                elif self.channel.recv_ready():
                    self.unpacker.feed(self.channel.recv(BUFSIZE))
                    for type, msgid, error, res in self.unpacker:
                        if error:
                            raise self.RPCError(error)
                        return res
            if e:
                raise Exception('ssh channel error')

    def commit(self, *args):
        self._cmd('commit', args)
        self.tid += 1

    def rollback(self, *args):
        return self._cmd('rollback', args)

    def get(self, *args):
        try:
            return self._cmd('get', args)
        except self.RPCError, e:
            if e.name == 'DoesNotExist':
                raise self.DoesNotExist
            raise

    def put(self, *args):
        try:
            return self._cmd('put', args)
        except self.RPCError, e:
            if e.name == 'AlreadyExists':
                raise self.AlreadyExists

    def delete(self, *args):
        return self._cmd('delete', args)

    def list(self, *args):
        return self._cmd('list', args)


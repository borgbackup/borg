import fcntl
import msgpack
import os
import paramiko
import select
import sys
import getpass

from .store import Store


BUFSIZE = 1024 * 1024


class ChannelNotifyer(object):

    def __init__(self, channel):
        self.channel = channel
        self.enabled = 0

    def set(self):
        if self.enabled:
            with self.channel.lock:
                self.channel.out_buffer_cv.notifyAll()

    def clear(self):
        pass


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
        self.notifier = ChannelNotifyer(self.channel)
        self.channel.in_buffer.set_event(self.notifier)
        self.channel.in_stderr_buffer.set_event(self.notifier)
        self.channel.exec_command('darc serve')
        self.callbacks = {}
        self.msgid = 0
        self.id, self.tid = self.cmd('open', (location.path, create))

    def wait(self, write=True):
        with self.channel.lock:
            if ((not write or self.channel.out_window_size == 0) and
                len(self.channel.in_buffer._buffer) == 0 and
                len(self.channel.in_stderr_buffer._buffer) == 0):
                self.channel.out_buffer_cv.wait(10)

    def cmd(self, cmd, args, callback=None, callback_data=None):
        self.msgid += 1
        self.notifier.enabled += 1
        odata = msgpack.packb((0, self.msgid, cmd, args))
        if callback:
            self.callbacks[self.msgid] = callback, callback_data
        while True:
            if self.channel.closed:
                raise Exception('Connection closed')
            elif self.channel.recv_stderr_ready():
                print >> sys.stderr, 'remote stderr:', self.channel.recv_stderr(BUFSIZE)
            elif self.channel.recv_ready():
                self.unpacker.feed(self.channel.recv(BUFSIZE))
                for type, msgid, error, res in self.unpacker:
                    self.notifier.enabled -= 1
                    if msgid == self.msgid:
                        if error:
                            raise self.RPCError(error)
                        return res
                    else:
                        c, d = self.callbacks.pop(msgid, (None, None))
                        if c:
                            c(res, error, d)
            elif odata and self.channel.send_ready():
                n = self.channel.send(odata)
                if n > 0:
                    odata = odata[n:]
                if not odata and callback:
                    return
            else:
                self.wait(odata)

    def commit(self, *args):
        self.cmd('commit', args)
        self.tid += 1

    def rollback(self, *args):
        return self.cmd('rollback', args)

    def get(self, ns, id, callback=None, callback_data=None):
        try:
            return self.cmd('get', (ns, id), callback, callback_data)
        except self.RPCError, e:
            print e.name
            if e.name == 'DoesNotExist':
                raise self.DoesNotExist
            raise

    def put(self, ns, id, data, callback=None, callback_data=None):
        try:
            return self.cmd('put', (ns, id, data), callback, callback_data)
        except self.RPCError, e:
            if e.name == 'AlreadyExists':
                raise self.AlreadyExists

    def delete(self, ns, id, callback=None, callback_data=None):
        return self.cmd('delete', (ns, id), callback, callback_data)

    def list(self, *args):
        return self.cmd('list', args)

    def flush_rpc(self):
        while True:
            if self.channel.closed:
                raise Exception('Connection closed')
            elif self.channel.recv_stderr_ready():
                print >> sys.stderr, 'remote stderr:', self.channel.recv_stderr(BUFSIZE)
            elif self.channel.recv_ready():
                self.unpacker.feed(self.channel.recv(BUFSIZE))
                for type, msgid, error, res in self.unpacker:
                    self.notifier.enabled -= 1
                    c, d = self.callbacks.pop(msgid, (None, None))
                    if c:
                        c(res, error, d)
                    if msgid == self.msgid:
                        return
            else:
                self.wait()

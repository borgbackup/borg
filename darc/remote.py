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
                        if method not in ('put', 'delete'):
                            if hasattr(res, 'next'):
                                for r in res:
                                    sys.stdout.write(msgpack.packb((1, msgid, None, r)))
                                sys.stdout.write(msgpack.packb((2, msgid, None, None)))
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
        self.msgid = 0
        self.id, self.tid = self.cmd('open', (location.path, create))

    def cmd(self, cmd, args, defer=False):
        self.msgid += 1
        odata = msgpack.packb((0, self.msgid, cmd, args))
        self.notifier.enabled += 1
        while True:
            if self.channel.closed:
                raise Exception('Connection closed')
            if odata and self.channel.send_ready():
                n = self.channel.send(odata)
                if n > 0:
                    odata = odata[n:]
                if not odata and defer:
                    self.notifier.enabled -= 1
                    return
            elif self.channel.recv_stderr_ready():
                print >> sys.stderr, 'remote stderr:', self.channel.recv_stderr(BUFSIZE)
            elif self.channel.recv_ready():
                self.unpacker.feed(self.channel.recv(BUFSIZE))
                for type, msgid, error, res in self.unpacker:
                    if error:
                        raise self.RPCError(error)
                    self.notifier.enabled -= 1
                    return res
            else:
                with self.channel.lock:
                    self.channel.out_buffer_cv.wait(10)

    def cmd_iter(self, cmd, args):
        self.msgid += 1
        odata = msgpack.packb((0, self.msgid, cmd, args))
        self.notifier.enabled += 1
        try:
            while True:
                if self.channel.closed:
                    raise Exception('Connection closed')
                if odata and self.channel.send_ready():
                    n = self.channel.send(odata)
                    if n > 0:
                        odata = odata[n:]
                if self.channel.recv_stderr_ready():
                    print >> sys.stderr, 'remote stderr:', self.channel.recv_stderr(BUFSIZE)
                elif self.channel.recv_ready():
                    self.unpacker.feed(self.channel.recv(BUFSIZE))
                    for type, msgid, error, res in self.unpacker:
                        if msgid < self.msgid:
                            continue
                        if error:
                            raise self.RPCError(error)
                        if type == 1:
                            yield res
                        else:
                            return
                else:
                    with self.channel.lock:
                        self.channel.out_buffer_cv.wait(10)
        finally:
            self.notifier.enabled -= 1

    def commit(self, *args):
        self.cmd('commit', args)
        self.tid += 1

    def rollback(self, *args):
        return self.cmd('rollback', args)

    def get(self, *args):
        try:
            return self.cmd('get', args)
        except self.RPCError, e:
            print e.name
            if e.name == 'DoesNotExist':
                raise self.DoesNotExist
            raise

    def get_many(self, *args):
        try:
            return self.cmd_iter('get_many', args)
        except self.RPCError, e:
            if e.name == 'DoesNotExist':
                raise self.DoesNotExist
            raise

    def put(self, *args):
        try:
            return self.cmd('put', args, defer=True)
        except self.RPCError, e:
            if e.name == 'AlreadyExists':
                raise self.AlreadyExists

    def delete(self, *args):
        return self.cmd('delete', args, defer=True)

    def list(self, *args):
        return self.cmd('list', args)


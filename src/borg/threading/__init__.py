import os
import faulthandler
import signal
import sys
import threading
import traceback

import zmq

import borg
from ..logger import create_logger

logger = create_logger(__name__)


def abort(where=''):
    # Leading newline to clear any progress output
    message = '\n--- Critical error %s---\n%s--- Aborting application ---\n' % (where, traceback.format_exc())
    if borg.testing and os.path.exists('/dev/tty') and not sys.platform.startswith('darwin'):
        # When running under py.test, the output is usually wrapped under two-levels of output capturing
        # (one level by py.test itself, which is easily disabled, and another level by exec_cmd).
        # This makes it kinda annoying to get at this information; so in this case just dump it on the TTY.
        with open('/dev/tty', 'w') as fd:
            fd.write(message)
            faulthandler.dump_traceback(fd)
            # Disable faulthandler now to avoid doubling the traceback
            faulthandler.disable()
    else:
        logger.error(message)
    # Abort! Abort! Abort!
    os.kill(os.getpid(), signal.SIGABRT)


class ThreadedService(threading.Thread):
    """
    A threaded service using ZeroMQ for in-process communication.

    Each service has a request-reply control socket based on its thread ID.
    This socket uses multi-part messages where the first part is the opcode,
    and the later parts are parameters. Services can implement their own opcodes by
    implementing *handle_control*.
    """

    CONTROL_DIE = b'DIE'

    def __init__(self, zmq_context=None):
        super().__init__()
        self.context = zmq_context or zmq.Context().instance()
        self.running = True
        self._sockets = []

    def control(self, opcode, *args):
        """
        Send *opcode* and *args* over the control socket.
        """
        socket = self.context.socket(zmq.REQ)
        socket.connect(self._control_url)
        socket.send_multipart([opcode] + list(args))
        return socket.recv_multipart()

    def run(self):
        try:
            self.init()
            self.loop()
            self.exit()
        except Exception:
            abort('in thread %s ' % self.name)

    def init(self):
        """
        Perform initialization of the thread, before entering the main loop.
        """
        self.name = '%s-%x' % (self.__class__.__name__, self.ident)
        self.poller = zmq.Poller()
        self.control_sock = self.socket(zmq.REP, self._control_url)

    def loop(self):
        while self.running:
            events = dict(self.poller.poll())
            if self.control_sock in events:
                opcode, *args = self.control_sock.recv_multipart()
                self.handle_control(opcode, args)
                events.pop(self.control_sock)
            self.events(events)

    def exit(self):
        for socket in self._sockets:
            socket.close()

    def handle_control(self, opcode, args):
        if opcode == self.CONTROL_DIE:
            self.running = False
        else:
            raise ValueError('Unknown %s opcode: %s' % (self.__class__.__name__, repr(opcode)))
        self.control_sock.send_multipart([b'ok'])

    def events(self, poll_events):
        pass

    def socket(self, type, url) -> zmq.Socket:
        socket = self.context.socket(type)
        self._sockets.append(socket)
        poll = type in [zmq.PULL, zmq.REP]
        if poll:
            self.poller.register(socket, zmq.POLLIN)
            socket.bind(url)
        else:
            socket.connect(url)
        return socket

    @property
    def _control_url(self):
        assert self.ident is not None, 'service hasn\'t been started yet - can\'t control it'
        return 'inproc://thread-control/%s' % self.ident

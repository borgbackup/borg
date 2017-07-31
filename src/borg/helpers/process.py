import contextlib
import os
import os.path
import shlex
import signal
import subprocess
import sys

from ..logger import create_logger
logger = create_logger()


def daemonize():
    """Detach process from controlling terminal and run in background"""
    pid = os.fork()
    if pid:
        os._exit(0)
    os.setsid()
    pid = os.fork()
    if pid:
        os._exit(0)
    os.chdir('/')
    os.close(0)
    os.close(1)
    os.close(2)
    fd = os.open(os.devnull, os.O_RDWR)
    os.dup2(fd, 0)
    os.dup2(fd, 1)
    os.dup2(fd, 2)


class SignalException(BaseException):
    """base class for all signal-based exceptions"""


class SigHup(SignalException):
    """raised on SIGHUP signal"""


class SigTerm(SignalException):
    """raised on SIGTERM signal"""


@contextlib.contextmanager
def signal_handler(sig, handler):
    """
    when entering context, set up signal handler <handler> for signal <sig>.
    when leaving context, restore original signal handler.

    <sig> can bei either a str when giving a signal.SIGXXX attribute name (it
    won't crash if the attribute name does not exist as some names are platform
    specific) or a int, when giving a signal number.

    <handler> is any handler value as accepted by the signal.signal(sig, handler).
    """
    if isinstance(sig, str):
        sig = getattr(signal, sig, None)
    if sig is not None:
        orig_handler = signal.signal(sig, handler)
    try:
        yield
    finally:
        if sig is not None:
            signal.signal(sig, orig_handler)


def raising_signal_handler(exc_cls):
    def handler(sig_no, frame):
        # setting SIG_IGN avoids that an incoming second signal of this
        # kind would raise a 2nd exception while we still process the
        # exception handler for exc_cls for the 1st signal.
        signal.signal(sig_no, signal.SIG_IGN)
        raise exc_cls

    return handler


def popen_with_error_handling(cmd_line: str, log_prefix='', **kwargs):
    """
    Handle typical errors raised by subprocess.Popen. Return None if an error occurred,
    otherwise return the Popen object.

    *cmd_line* is split using shlex (e.g. 'gzip -9' => ['gzip', '-9']).

    Log messages will be prefixed with *log_prefix*; if set, it should end with a space
    (e.g. log_prefix='--some-option: ').

    Does not change the exit code.
    """
    assert not kwargs.get('shell'), 'Sorry pal, shell mode is a no-no'
    try:
        command = shlex.split(cmd_line)
        if not command:
            raise ValueError('an empty command line is not permitted')
    except ValueError as ve:
        logger.error('%s%s', log_prefix, ve)
        return
    logger.debug('%scommand line: %s', log_prefix, command)
    try:
        return subprocess.Popen(command, **kwargs)
    except FileNotFoundError:
        logger.error('%sexecutable not found: %s', log_prefix, command[0])
        return
    except PermissionError:
        logger.error('%spermission denied: %s', log_prefix, command[0])
        return


def is_terminal(fd=sys.stdout):
    return hasattr(fd, 'isatty') and fd.isatty() and (sys.platform != 'win32' or 'ANSICON' in os.environ)

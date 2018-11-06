import contextlib
import os
import os.path
import re
import shlex
import signal
import subprocess
import sys

from .. import __version__

from ..platformflags import is_win32, is_linux, is_freebsd, is_darwin
from ..logger import create_logger
logger = create_logger()


def daemonize():
    """Detach process from controlling terminal and run in background

    Returns: old and new get_process_id tuples
    """
    from ..platform import get_process_id
    old_id = get_process_id()
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
    new_id = get_process_id()
    return old_id, new_id


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
    return hasattr(fd, 'isatty') and fd.isatty() and (not is_win32 or 'ANSICON' in os.environ)


def prepare_subprocess_env(system, env=None):
    """
    Prepare the environment for a subprocess we are going to create.

    :param system: True for preparing to invoke system-installed binaries,
                   False for stuff inside the pyinstaller environment (like borg, python).
    :param env: optionally give a environment dict here. if not given, default to os.environ.
    :return: a modified copy of the environment
    """
    env = dict(env if env is not None else os.environ)
    if system:
        # a pyinstaller binary's bootloader modifies LD_LIBRARY_PATH=/tmp/_MEIXXXXXX,
        # but we do not want that system binaries (like ssh or other) pick up
        # (non-matching) libraries from there.
        # thus we install the original LDLP, before pyinstaller has modified it:
        lp_key = 'LD_LIBRARY_PATH'
        lp_orig = env.get(lp_key + '_ORIG')  # pyinstaller >= 20160820 / v3.2.1 has this
        if lp_orig is not None:
            env[lp_key] = lp_orig
        else:
            # We get here in 2 cases:
            # 1. when not running a pyinstaller-made binary.
            #    in this case, we must not kill LDLP.
            # 2. when running a pyinstaller-made binary and there was no LDLP
            #    in the original env (in this case, the pyinstaller bootloader
            #    does *not* put ..._ORIG into the env either).
            #    in this case, we must kill LDLP.
            # The directory used by pyinstaller is created by mkdtemp("_MEIXXXXXX"),
            # we can use that to differentiate between the cases.
            lp = env.get(lp_key)
            if lp is not None and re.search(r'/_MEI......', lp):
                env.pop(lp_key)
    # security: do not give secrets to subprocess
    env.pop('BORG_PASSPHRASE', None)
    # for information, give borg version to the subprocess
    env['BORG_VERSION'] = __version__
    return env

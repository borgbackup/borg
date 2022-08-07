import contextlib
import os
import os.path
import re
import shlex
import signal
import subprocess
import sys
import time
import traceback

from .. import __version__

from ..platformflags import is_win32, is_linux, is_freebsd, is_darwin
from ..logger import create_logger

logger = create_logger()

from ..helpers import EXIT_SUCCESS, EXIT_WARNING, EXIT_SIGNAL_BASE, Error


@contextlib.contextmanager
def _daemonize():
    from ..platform import get_process_id

    old_id = get_process_id()
    pid = os.fork()
    if pid:
        exit_code = EXIT_SUCCESS
        try:
            yield old_id, None
        except _ExitCodeException as e:
            exit_code = e.exit_code
        finally:
            logger.debug("Daemonizing: Foreground process (%s, %s, %s) is now dying." % old_id)
            os._exit(exit_code)
    os.setsid()
    pid = os.fork()
    if pid:
        os._exit(0)
    os.chdir("/")
    os.close(0)
    os.close(1)
    fd = os.open(os.devnull, os.O_RDWR)
    os.dup2(fd, 0)
    os.dup2(fd, 1)
    new_id = get_process_id()
    try:
        yield old_id, new_id
    finally:
        # Close / redirect stderr to /dev/null only now
        # for the case that we want to log something before yield returns.
        os.close(2)
        os.dup2(fd, 2)


def daemonize():
    """Detach process from controlling terminal and run in background

    Returns: old and new get_process_id tuples
    """
    with _daemonize() as (old_id, new_id):
        return old_id, new_id


@contextlib.contextmanager
def daemonizing(*, timeout=5):
    """Like daemonize(), but as context manager.

    The with-body is executed in the background process,
    while the foreground process survives until the body is left
    or the given timeout is exceeded. In the latter case a warning is
    reported by the foreground.
    Context variable is (old_id, new_id) get_process_id tuples.
    An exception raised in the body is reported by the foreground
    as a warning as well as propagated outside the body in the background.
    In case of a warning, the foreground exits with exit code EXIT_WARNING
    instead of EXIT_SUCCESS.
    """
    with _daemonize() as (old_id, new_id):
        if new_id is None:
            # The original / parent process, waiting for a signal to die.
            logger.debug("Daemonizing: Foreground process (%s, %s, %s) is waiting for background process..." % old_id)
            exit_code = EXIT_SUCCESS
            # Indeed, SIGHUP and SIGTERM handlers should have been set on archiver.run(). Just in case...
            with signal_handler("SIGINT", raising_signal_handler(KeyboardInterrupt)), signal_handler(
                "SIGHUP", raising_signal_handler(SigHup)
            ), signal_handler("SIGTERM", raising_signal_handler(SigTerm)):
                try:
                    if timeout > 0:
                        time.sleep(timeout)
                except SigTerm:
                    # Normal termination; expected from grandchild, see 'os.kill()' below
                    pass
                except SigHup:
                    # Background wants to indicate a problem; see 'os.kill()' below,
                    # log message will come from grandchild.
                    exit_code = EXIT_WARNING
                except KeyboardInterrupt:
                    # Manual termination.
                    logger.debug("Daemonizing: Foreground process (%s, %s, %s) received SIGINT." % old_id)
                    exit_code = EXIT_SIGNAL_BASE + 2
                except BaseException as e:
                    # Just in case...
                    logger.warning(
                        "Daemonizing: Foreground process received an exception while waiting:\n"
                        + "".join(traceback.format_exception(e.__class__, e, e.__traceback__))
                    )
                    exit_code = EXIT_WARNING
                else:
                    logger.warning("Daemonizing: Background process did not respond (timeout). Is it alive?")
                    exit_code = EXIT_WARNING
                finally:
                    # Don't call with-body, but die immediately!
                    # return would be sufficient, but we want to pass the exit code.
                    raise _ExitCodeException(exit_code)

        # The background / grandchild process.
        sig_to_foreground = signal.SIGTERM
        logger.debug("Daemonizing: Background process (%s, %s, %s) is starting..." % new_id)
        try:
            yield old_id, new_id
        except BaseException as e:
            sig_to_foreground = signal.SIGHUP
            logger.warning(
                "Daemonizing: Background process raised an exception while starting:\n"
                + "".join(traceback.format_exception(e.__class__, e, e.__traceback__))
            )
            raise e
        else:
            logger.debug("Daemonizing: Background process (%s, %s, %s) has started." % new_id)
        finally:
            try:
                os.kill(old_id[1], sig_to_foreground)
            except BaseException as e:
                logger.error(
                    "Daemonizing: Trying to kill the foreground process raised an exception:\n"
                    + "".join(traceback.format_exception(e.__class__, e, e.__traceback__))
                )


class _ExitCodeException(BaseException):
    def __init__(self, exit_code):
        self.exit_code = exit_code


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


class SigIntManager:
    def __init__(self):
        self._sig_int_triggered = False
        self._action_triggered = False
        self._action_done = False
        self.ctx = signal_handler("SIGINT", self.handler)

    def __bool__(self):
        # this will be True (and stay True) after the first Ctrl-C/SIGINT
        return self._sig_int_triggered

    def action_triggered(self):
        # this is True to indicate that the action shall be done
        return self._action_triggered

    def action_done(self):
        # this will be True after the action has completed
        return self._action_done

    def action_completed(self):
        # this must be called when the action triggered is completed,
        # to avoid that the action is repeatedly triggered.
        self._action_triggered = False
        self._action_done = True

    def handler(self, sig_no, stack):
        # handle the first ctrl-c / SIGINT.
        self.__exit__(None, None, None)
        self._sig_int_triggered = True
        self._action_triggered = True

    def __enter__(self):
        self.ctx.__enter__()

    def __exit__(self, exception_type, exception_value, traceback):
        # restore the original ctrl-c handler, so the next ctrl-c / SIGINT does the normal thing:
        if self.ctx:
            self.ctx.__exit__(exception_type, exception_value, traceback)
            self.ctx = None


# global flag which might trigger some special behaviour on first ctrl-c / SIGINT,
# e.g. if this is interrupting "borg create", it shall try to create a checkpoint.
sig_int = SigIntManager()


def ignore_sigint():
    """
    Ignore SIGINT, see also issue #6912.

    Ctrl-C will send a SIGINT to both the main process (borg) and subprocesses
    (e.g. ssh for remote ssh:// repos), but often we do not want the subprocess
    getting killed (e.g. because it is still needed to cleanly shut down borg).

    To avoid that: Popen(..., preexec_fn=ignore_sigint)
    """
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def popen_with_error_handling(cmd_line: str, log_prefix="", **kwargs):
    """
    Handle typical errors raised by subprocess.Popen. Return None if an error occurred,
    otherwise return the Popen object.

    *cmd_line* is split using shlex (e.g. 'gzip -9' => ['gzip', '-9']).

    Log messages will be prefixed with *log_prefix*; if set, it should end with a space
    (e.g. log_prefix='--some-option: ').

    Does not change the exit code.
    """
    assert not kwargs.get("shell"), "Sorry pal, shell mode is a no-no"
    try:
        command = shlex.split(cmd_line)
        if not command:
            raise ValueError("an empty command line is not permitted")
    except ValueError as ve:
        logger.error("%s%s", log_prefix, ve)
        return
    logger.debug("%scommand line: %s", log_prefix, command)
    try:
        return subprocess.Popen(command, **kwargs)
    except FileNotFoundError:
        logger.error("%sexecutable not found: %s", log_prefix, command[0])
        return
    except PermissionError:
        logger.error("%spermission denied: %s", log_prefix, command[0])
        return


def is_terminal(fd=sys.stdout):
    return hasattr(fd, "isatty") and fd.isatty() and (not is_win32 or "ANSICON" in os.environ)


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
        lp_key = "LD_LIBRARY_PATH"
        lp_orig = env.get(lp_key + "_ORIG")  # pyinstaller >= 20160820 / v3.2.1 has this
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
            #    We can recognize this via sys.frozen and sys._MEIPASS being set.
            lp = env.get(lp_key)
            if lp is not None and getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
                env.pop(lp_key)
    # security: do not give secrets to subprocess
    env.pop("BORG_PASSPHRASE", None)
    # for information, give borg version to the subprocess
    env["BORG_VERSION"] = __version__
    return env


@contextlib.contextmanager
def create_filter_process(cmd, stream, stream_close, inbound=True):
    if cmd:
        # put a filter process between stream and us (e.g. a [de]compression command)
        # inbound: <stream> --> filter --> us
        # outbound: us --> filter --> <stream>
        filter_stream = stream
        filter_stream_close = stream_close
        env = prepare_subprocess_env(system=True)
        # There is no deadlock potential here (the subprocess docs warn about this), because
        # communication with the process is a one-way road, i.e. the process can never block
        # for us to do something while we block on the process for something different.
        if inbound:
            proc = popen_with_error_handling(
                cmd,
                stdout=subprocess.PIPE,
                stdin=filter_stream,
                log_prefix="filter-process: ",
                env=env,
                preexec_fn=ignore_sigint,
            )
        else:
            proc = popen_with_error_handling(
                cmd,
                stdin=subprocess.PIPE,
                stdout=filter_stream,
                log_prefix="filter-process: ",
                env=env,
                preexec_fn=ignore_sigint,
            )
        if not proc:
            raise Error(f"filter {cmd}: process creation failed")
        stream = proc.stdout if inbound else proc.stdin
        # inbound: do not close the pipe (this is the task of the filter process [== writer])
        # outbound: close the pipe, otherwise the filter process would not notice when we are done.
        stream_close = not inbound

    try:
        yield stream

    except Exception:
        # something went wrong with processing the stream by borg
        logger.debug("Exception, killing the filter...")
        if cmd:
            proc.kill()
        borg_succeeded = False
        raise
    else:
        borg_succeeded = True
    finally:
        if stream_close:
            stream.close()

        if cmd:
            logger.debug("Done, waiting for filter to die...")
            rc = proc.wait()
            logger.debug("filter cmd exited with code %d", rc)
            if filter_stream_close:
                filter_stream.close()
            if borg_succeeded and rc:
                # if borg did not succeed, we know that we killed the filter process
                raise Error("filter %s failed, rc=%d" % (cmd, rc))

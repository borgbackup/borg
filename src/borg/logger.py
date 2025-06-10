"""logging facilities

The way to use this is as follows:

* each module declares its own logger, using:

    from .logger import create_logger
    logger = create_logger()

* then each module uses logger.info/warning/debug/etc according to the
  level it believes is appropriate:

    logger.debug('debugging info for developers or power users')
    logger.info('normal, informational output')
    logger.warning('warn about a non-fatal error or sth else')
    logger.error('a fatal error')

  ... and so on. see the `logging documentation
  <https://docs.python.org/3/howto/logging.html#when-to-use-logging>`_
  for more information

* console interaction happens on stderr, that includes interactive
  reporting functions like `help`, `info` and `list`

* ...except ``input()`` is special, because we can't control the
  stream it is using, unfortunately. we assume that it won't clutter
  stdout, because interaction would be broken then anyways

* what is output on INFO level is additionally controlled by commandline
  flags

Logging setup is a bit complicated in borg, as it needs to work under misc. conditions:
- purely local, not client/server (easy)
- client/server: RemoteRepository ("borg serve" process) writes log records into a global
  queue, which is then sent to the client side by the main serve loop (via the RPC protocol,
  either over ssh stdout, more directly via process stdout without ssh [used in the tests]
  or via a socket. On the client side, the log records are fed into the clientside logging
  system. When remote_repo.close() is called, server side must send all queued log records
  via the RPC channel before returning the close() call's return value (as the client will
  then shut down the connection).
- progress output is always given as json to the logger (including the plain text inside
  the json), but then formatted by the logging system's formatter as either plain text or
  json depending on the cli args given (--log-json?).
- tests: potentially running in parallel via pytest-xdist, capturing borg output into a
  given stream.
- logging might be short-lived (e.g. when invoking a single borg command via the cli)
  or long-lived (e.g. borg serve --socket or when running the tests)
- logging is global and exists only once per process.
"""

import inspect
import json
import logging
import logging.config
import logging.handlers  # needed for handlers defined there being configurable in logging.conf file
import os
import queue
import sys
import time
import warnings
from pathlib import Path

logging_debugging_path: Path | None = None  # if set, write borg.logger debugging log to thatpath/borg-*.log

configured = False
borg_serve_log_queue: queue.SimpleQueue = queue.SimpleQueue()


class BorgQueueHandler(logging.handlers.QueueHandler):
    """borg serve writes log record dicts to a borg_serve_log_queue"""

    def prepare(self, record: logging.LogRecord) -> dict:
        return dict(
            # kwargs needed for LogRecord constructor:
            name=record.name,
            level=record.levelno,
            pathname=record.pathname,
            lineno=record.lineno,
            msg=record.msg,
            args=record.args,
            exc_info=record.exc_info,
            func=record.funcName,
            sinfo=record.stack_info,
        )


class StderrHandler(logging.StreamHandler):
    """
    This class is like a StreamHandler using sys.stderr, but always uses
    whatever sys.stderr is currently set to rather than the value of
    sys.stderr at handler construction time.
    """

    def __init__(self, stream=None):
        logging.Handler.__init__(self)

    @property
    def stream(self):
        return sys.stderr


class TextProgressFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        # record.msg contains json (because we always do json for progress log)
        j = json.loads(record.msg)
        # inside the json, the text log line can be found under "message"
        return f"{j['message']}"


class JSONProgressFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        # record.msg contains json (because we always do json for progress log)
        return f"{record.msg}"


# use something like this to ignore warnings:
# warnings.filterwarnings('ignore', r'... regex for warning message to ignore ...')


# we do not want that urllib spoils test output with LibreSSL related warnings on OpenBSD.
# NotOpenSSLWarning: urllib3 v2 only supports OpenSSL 1.1.1+,
#                    currently the 'ssl' module is compiled with 'LibreSSL 3.8.2'.
warnings.filterwarnings("ignore", message=r".*urllib3 v2 only supports OpenSSL.*")


def _log_warning(message, category, filename, lineno, file=None, line=None):
    # for warnings, we just want to use the logging system, not stderr or other files
    msg = f"{filename}:{lineno}: {category.__name__}: {message}"
    logger = create_logger(__name__)
    # Note: the warning will look like coming from here,
    # but msg contains info about where it really comes from
    logger.warning(msg)


def remove_handlers(logger):
    for handler in logger.handlers[:]:
        handler.flush()
        handler.close()
        logger.removeHandler(handler)


def flush_logging():
    # make sure all log output is flushed,
    # this is especially important for the "borg serve" RemoteRepository logging:
    # all log output needs to be sent via the ssh / socket connection before closing it.
    for logger_name in "borg.output.progress", "":
        logger = logging.getLogger(logger_name)
        for handler in logger.handlers:
            handler.flush()


def setup_logging(
    stream=None, conf_fname=None, env_var="BORG_LOGGING_CONF", level="info", is_serve=False, log_json=False, func=None
):
    """setup logging module according to the arguments provided

    if conf_fname is given (or the config file name can be determined via
    the env_var, if given): load this logging configuration.

    otherwise, set up a stream handler logger on stderr (by default, if no
    stream is provided).

    is_serve: are we setting up the logging for "borg serve"?
    """
    global configured
    err_msg = None
    if env_var:
        conf_fname = os.environ.get(env_var, conf_fname)
    if conf_fname:
        try:
            conf_path = Path(conf_fname).absolute()
            # we open the conf file here to be able to give a reasonable
            # error message in case of failure (if we give the filename to
            # fileConfig(), it silently ignores unreadable files and gives
            # unhelpful error msgs like "No section: 'formatters'"):
            with conf_path.open() as f:
                logging.config.fileConfig(f)
            configured = True
            logger = logging.getLogger(__name__)
            logger.debug(f'using logging configuration read from "{conf_fname}"')
            warnings.showwarning = _log_warning
            return None
        except Exception as err:  # XXX be more precise
            err_msg = str(err)

    # if we did not / not successfully load a logging configuration, fallback to this:
    level = level.upper()
    fmt = "%(message)s"
    formatter = JsonFormatter(fmt) if log_json else logging.Formatter(fmt)
    SHandler = StderrHandler if stream is None else logging.StreamHandler
    handler = BorgQueueHandler(borg_serve_log_queue) if is_serve else SHandler(stream)
    handler.setFormatter(formatter)
    logger = logging.getLogger()
    remove_handlers(logger)
    logger.setLevel(level)

    if logging_debugging_path is not None:
        # add an addtl. root handler for debugging purposes
        log_path = logging_debugging_path / (f"borg-{'serve' if is_serve else 'client'}-root.log")
        handler2 = logging.StreamHandler(log_path.open("a"))
        handler2.setFormatter(formatter)
        logger.addHandler(handler2)
        logger.warning(f"--- {func} ---")  # only handler2 shall get this

    logger.addHandler(handler)  # do this late, so handler is not added while debug handler is set up

    bop_formatter = JSONProgressFormatter() if log_json else TextProgressFormatter()
    bop_handler = BorgQueueHandler(borg_serve_log_queue) if is_serve else SHandler(stream)
    bop_handler.setFormatter(bop_formatter)
    bop_logger = logging.getLogger("borg.output.progress")
    remove_handlers(bop_logger)
    bop_logger.setLevel("INFO")
    bop_logger.propagate = False

    if logging_debugging_path is not None:
        # add an addtl. progress handler for debugging purposes
        log_path = logging_debugging_path / (f"borg-{'serve' if is_serve else 'client'}-progress.log")
        bop_handler2 = logging.StreamHandler(log_path.open("a"))
        bop_handler2.setFormatter(bop_formatter)
        bop_logger.addHandler(bop_handler2)
        json_dict = dict(
            message=f"--- {func} ---", operation=0, msgid="", type="progress_message", finished=False, time=time.time()
        )
        bop_logger.warning(json.dumps(json_dict))  # only bop_handler2 shall get this

    bop_logger.addHandler(bop_handler)  # do this late, so bop_handler is not added while debug handler is set up

    configured = True

    logger = logging.getLogger(__name__)
    if err_msg:
        logger.warning(f'setup_logging for "{conf_fname}" failed with "{err_msg}".')
    logger.debug("using builtin fallback logging configuration")
    warnings.showwarning = _log_warning
    return handler


def find_parent_module():
    """find the name of the first module calling this module

    if we cannot find it, we return the current module's name
    (__name__) instead.
    """
    try:
        frame = inspect.currentframe().f_back
        module = inspect.getmodule(frame)
        while module is None or module.__name__ == __name__:
            frame = frame.f_back
            module = inspect.getmodule(frame)
        return module.__name__
    except AttributeError:
        # somehow we failed to find our module
        # return the logger module name by default
        return __name__


class LazyLogger:
    def __init__(self, name=None):
        self.__name = name or find_parent_module()
        self.__real_logger = None

    @property
    def __logger(self):
        if self.__real_logger is None:
            if not configured:
                raise Exception("tried to call a logger before setup_logging() was called")
            self.__real_logger = logging.getLogger(self.__name)
            if self.__name.startswith("borg.debug.") and self.__real_logger.level == logging.NOTSET:
                self.__real_logger.setLevel("WARNING")
        return self.__real_logger

    def getChild(self, suffix):
        return LazyLogger(self.__name + "." + suffix)

    def setLevel(self, level):
        return self.__logger.setLevel(level)

    def log(self, level, msg, *args, **kwargs):
        if "msgid" in kwargs:
            kwargs.setdefault("extra", {})["msgid"] = kwargs.pop("msgid")
        return self.__logger.log(level, msg, *args, **kwargs)

    def exception(self, msg, *args, exc_info=True, **kwargs):
        if "msgid" in kwargs:
            kwargs.setdefault("extra", {})["msgid"] = kwargs.pop("msgid")
        return self.__logger.exception(msg, *args, exc_info=exc_info, **kwargs)

    def debug(self, msg, *args, **kwargs):
        if "msgid" in kwargs:
            kwargs.setdefault("extra", {})["msgid"] = kwargs.pop("msgid")
        return self.__logger.debug(msg, *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        if "msgid" in kwargs:
            kwargs.setdefault("extra", {})["msgid"] = kwargs.pop("msgid")
        return self.__logger.info(msg, *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        if "msgid" in kwargs:
            kwargs.setdefault("extra", {})["msgid"] = kwargs.pop("msgid")
        return self.__logger.warning(msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        if "msgid" in kwargs:
            kwargs.setdefault("extra", {})["msgid"] = kwargs.pop("msgid")
        return self.__logger.error(msg, *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        if "msgid" in kwargs:
            kwargs.setdefault("extra", {})["msgid"] = kwargs.pop("msgid")
        return self.__logger.critical(msg, *args, **kwargs)


def create_logger(name: str = None) -> LazyLogger:
    """lazily create a Logger object with the proper path, which is returned by
    find_parent_module() by default, or is provided via the commandline

    this is really a shortcut for:

        logger = logging.getLogger(__name__)

    we use it to avoid errors and provide a more standard API.

    We must create the logger lazily, because this is usually called from
    module level (and thus executed at import time - BEFORE setup_logging()
    was called). By doing it lazily we can do the setup first, we just have to
    be careful not to call any logger methods before the setup_logging() call.
    If you try, you'll get an exception.
    """

    return LazyLogger(name)


class JsonFormatter(logging.Formatter):
    RECORD_ATTRIBUTES = (
        "levelname",
        "name",
        "message",
        # msgid is an attribute we made up in Borg to expose a non-changing handle for log messages
        "msgid",
    )

    # Other attributes that are not very useful but do exist:
    # processName, process, relativeCreated, stack_info, thread, threadName
    # msg == message
    # *args* are the unformatted arguments passed to the logger function, not useful now,
    # become useful if sanitized properly (must be JSON serializable) in the code +
    # fixed message IDs are assigned.
    # exc_info, exc_text are generally uninteresting because the message will have that

    def format(self, record):
        super().format(record)
        data = {"type": "log_message", "time": record.created, "message": "", "levelname": "CRITICAL"}
        for attr in self.RECORD_ATTRIBUTES:
            value = getattr(record, attr, None)
            if value:
                data[attr] = value
        return json.dumps(data)

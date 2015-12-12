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
"""

import inspect
import logging
import logging.config
import logging.handlers  # needed for handlers defined there being configurable in logging.conf file
import os
import warnings

configured = False

# use something like this to ignore warnings:
# warnings.filterwarnings('ignore', r'... regex for warning message to ignore ...')


def _log_warning(message, category, filename, lineno, file=None, line=None):
    # for warnings, we just want to use the logging system, not stderr or other files
    msg = "{0}:{1}: {2}: {3}".format(filename, lineno, category.__name__, message)
    logger = create_logger(__name__)
    # Note: the warning will look like coming from here,
    # but msg contains info about where it really comes from
    logger.warning(msg)


def setup_logging(stream=None, conf_fname=None, env_var='BORG_LOGGING_CONF', level='info', is_serve=False):
    """setup logging module according to the arguments provided

    if conf_fname is given (or the config file name can be determined via
    the env_var, if given): load this logging configuration.

    otherwise, set up a stream handler logger on stderr (by default, if no
    stream is provided).

    if is_serve == True, we configure a special log format as expected by
    the borg client log message interceptor.
    """
    global configured
    err_msg = None
    if env_var:
        conf_fname = os.environ.get(env_var, conf_fname)
    if conf_fname:
        try:
            conf_fname = os.path.abspath(conf_fname)
            # we open the conf file here to be able to give a reasonable
            # error message in case of failure (if we give the filename to
            # fileConfig(), it silently ignores unreadable files and gives
            # unhelpful error msgs like "No section: 'formatters'"):
            with open(conf_fname) as f:
                logging.config.fileConfig(f)
            configured = True
            logger = logging.getLogger(__name__)
            logger.debug('using logging configuration read from "{0}"'.format(conf_fname))
            warnings.showwarning = _log_warning
            return None
        except Exception as err:  # XXX be more precise
            err_msg = str(err)
    # if we did not / not successfully load a logging configuration, fallback to this:
    logger = logging.getLogger('')
    handler = logging.StreamHandler(stream)
    if is_serve:
        fmt = '$LOG %(levelname)s Remote: %(message)s'
    else:
        fmt = '%(message)s'
    handler.setFormatter(logging.Formatter(fmt))
    logger.addHandler(handler)
    logger.setLevel(level.upper())
    configured = True
    logger = logging.getLogger(__name__)
    if err_msg:
        logger.warning('setup_logging for "{0}" failed with "{1}".'.format(conf_fname, err_msg))
    logger.debug('using builtin fallback logging configuration')
    warnings.showwarning = _log_warning
    return handler


def find_parent_module():
    """find the name of a the first module calling this module

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


def create_logger(name=None):
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
            return self.__real_logger

        def setLevel(self, *args, **kw):
            return self.__logger.setLevel(*args, **kw)

        def log(self, *args, **kw):
            return self.__logger.log(*args, **kw)

        def exception(self, *args, **kw):
            return self.__logger.exception(*args, **kw)

        def debug(self, *args, **kw):
            return self.__logger.debug(*args, **kw)

        def info(self, *args, **kw):
            return self.__logger.info(*args, **kw)

        def warning(self, *args, **kw):
            return self.__logger.warning(*args, **kw)

        def error(self, *args, **kw):
            return self.__logger.error(*args, **kw)

        def critical(self, *args, **kw):
            return self.__logger.critical(*args, **kw)

    return LazyLogger(name)

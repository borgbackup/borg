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
import sys


def setup_logging(stream=None):
    """setup logging module according to the arguments provided

    this sets up a stream handler logger on stderr (by default, if no
    stream is provided).
    """
    logging.raiseExceptions = False
    l = logging.getLogger('')
    sh = logging.StreamHandler(stream)
    # other formatters will probably want this, but let's remove
    # clutter on stderr
    # example:
    # sh.setFormatter(logging.Formatter('%(name)s: %(message)s'))
    l.addHandler(sh)
    l.setLevel(logging.INFO)
    return sh


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
    """create a Logger object with the proper path, which is returned by
    find_parent_module() by default, or is provided via the commandline

    this is really a shortcut for:

        logger = logging.getLogger(__name__)

    we use it to avoid errors and provide a more standard API.
    """
    return logging.getLogger(name or find_parent_module())

import inspect
import logging
import sys

def setup_logging(args, stream=None):
    logging.raiseExceptions = False
    l = logging.getLogger('')
    sh = logging.StreamHandler(stream)
    # other formatters will probably want this, but let's remove
    # clutter on stderr
    #sh.setFormatter(logging.Formatter('%(name)s: %(message)s'))
    l.addHandler(sh)
    levels = { None: logging.WARNING,
       0: logging.WARNING,
       1: logging.INFO,
       2: logging.DEBUG }
    # default to WARNING, -v goes to INFO and -vv to DEBUG
    l.setLevel(levels[args.verbose])
    return sh,

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
    return logging.getLogger(name or find_parent_module())

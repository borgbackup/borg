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


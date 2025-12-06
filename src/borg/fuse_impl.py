"""
Loads the library for the FUSE implementation.
"""

import os

from .platform import ENOATTR  # noqa

BORG_FUSE_IMPL = os.environ.get("BORG_FUSE_IMPL", "mfusepy,pyfuse3,llfuse")

for FUSE_IMPL in BORG_FUSE_IMPL.split(","):
    FUSE_IMPL = FUSE_IMPL.strip()
    if FUSE_IMPL == "pyfuse3":
        try:
            import pyfuse3 as llfuse
        except ImportError:
            pass
        else:
            has_llfuse = False
            has_pyfuse3 = True
            has_mfusepy = False
            has_any_fuse = True
            break
    elif FUSE_IMPL == "llfuse":
        try:
            import llfuse
        except ImportError:
            pass
        else:
            has_llfuse = True
            has_pyfuse3 = False
            has_mfusepy = False
            has_any_fuse = True
            break
    elif FUSE_IMPL == "mfusepy":
        try:
            from .fuse2 import mfuse  # noqa
        except ImportError:
            pass
        else:
            llfuse = None  # noqa
            has_llfuse = False
            has_pyfuse3 = False
            has_mfusepy = True
            has_any_fuse = True
            break
    elif FUSE_IMPL == "none":
        pass
    else:
        raise RuntimeError("Unknown FUSE implementation in BORG_FUSE_IMPL: '%s'." % BORG_FUSE_IMPL)
else:
    llfuse = None  # noqa
    has_llfuse = False
    has_pyfuse3 = False
    has_mfusepy = False
    has_any_fuse = False

"""
Loads the library for the FUSE implementation.
"""

import os
import types

from .platform import ENOATTR  # noqa

BORG_FUSE_IMPL = os.environ.get("BORG_FUSE_IMPL", "mfusepy,pyfuse3,llfuse")

hlfuse: types.ModuleType | None = None
llfuse: types.ModuleType | None = None

for FUSE_IMPL in BORG_FUSE_IMPL.split(","):
    FUSE_IMPL = FUSE_IMPL.strip()
    if FUSE_IMPL == "pyfuse3":
        try:
            import pyfuse3
        except ImportError:
            pass
        else:
            llfuse = pyfuse3
            has_llfuse = False
            has_pyfuse3 = True
            has_mfusepy = False
            has_any_fuse = True
            hlfuse = None  # noqa
            break
    elif FUSE_IMPL == "llfuse":
        try:
            import llfuse as llfuse_module
        except ImportError:
            pass
        else:
            llfuse = llfuse_module
            has_llfuse = True
            has_pyfuse3 = False
            has_mfusepy = False
            has_any_fuse = True
            hlfuse = None  # noqa
            break
    elif FUSE_IMPL == "mfusepy":
        try:
            import mfusepy
        except ImportError:
            pass
        else:
            hlfuse = mfusepy
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
    has_llfuse = False
    has_pyfuse3 = False
    has_mfusepy = False
    has_any_fuse = False

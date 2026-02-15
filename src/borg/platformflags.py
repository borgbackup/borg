"""
Flags for platform-specific APIs.

Use these flags instead of sys.platform.startswith('<os>') or try/except.
"""

import os
import sys

is_win32 = sys.platform.startswith("win32")
is_cygwin = sys.platform.startswith("cygwin")

is_linux = sys.platform.startswith("linux")
is_freebsd = sys.platform.startswith("freebsd")
is_netbsd = sys.platform.startswith("netbsd")
is_openbsd = sys.platform.startswith("openbsd")
is_darwin = sys.platform.startswith("darwin")
is_haiku = sys.platform.startswith("haiku")

# MSYS2 (on Windows)
is_msystem = is_win32 and "MSYSTEM" in os.environ

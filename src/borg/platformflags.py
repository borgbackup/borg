"""
Flags for platform-specific APIs.

Use these flags instead of sys.platform.startswith('<os>') or try/except.
"""

import sys

is_win32 = sys.platform.startswith("win32")
is_cygwin = sys.platform.startswith("cygwin")
is_msys = sys.platform.startswith("msys")
is_windows = is_win32 or is_cygwin or is_msys

is_linux = sys.platform.startswith("linux")
is_freebsd = sys.platform.startswith("freebsd")
is_darwin = sys.platform.startswith("darwin")

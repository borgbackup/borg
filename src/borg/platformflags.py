"""
Flags for Platform-specific APIs.

Use these Flags instead of sys.platform.startswith('<OS>') or try/except.
"""

import sys

is_win32 = sys.platform.startswith("win32")
is_linux = sys.platform.startswith("linux")
is_freebsd = sys.platform.startswith("freebsd")
is_darwin = sys.platform.startswith("darwin")

"""
Flags for Platform-specific APIs.

Use this Flags instead of sys.platform.startswith('<OS>') and try except
"""

import sys

is_win32 = sys.platform.startswith('win32')
is_linux = sys.platform.startswith('linux')
is_freebsd = sys.platform.startswith('freebsd')
is_darwin = sys.platform.startswith('darwin')

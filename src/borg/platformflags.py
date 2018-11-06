"""
Flags for Platform-specific APIs.

Use this Flags instead of sys.platform.startswith('<OS>') and try except
"""

import sys

IsWin32 = sys.platform.startswith('win32')
IsLinux = sys.platform.startswith('linux')
IsFreeBsd = sys.platform.startswith('freebsd')
IsDarwin = sys.platform.startswith('darwin')

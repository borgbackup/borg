import sys

from .platform_base import acl_get, acl_set, SyncFile, sync_dir, set_flags, get_flags, swidth, API_VERSION

if sys.platform.startswith('linux'):  # pragma: linux only
    from .platform_linux import acl_get, acl_set, SyncFile, set_flags, get_flags, swidth, API_VERSION
elif sys.platform.startswith('freebsd'):  # pragma: freebsd only
    from .platform_freebsd import acl_get, acl_set, swidth, API_VERSION
elif sys.platform == 'darwin':  # pragma: darwin only
    from .platform_darwin import acl_get, acl_set, swidth, API_VERSION
elif sys.platform == 'win32':  # pragma: windows only
    from .platform_windows import acl_get, acl_set, API_VERSION, get_owner, set_owner, sync_dir, SyncFile

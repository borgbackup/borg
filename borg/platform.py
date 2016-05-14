import sys

from .platform_base import acl_get, acl_set, SyncFile, sync_dir, API_VERSION

if sys.platform.startswith('linux'):  # pragma: linux only
    from .platform_linux import acl_get, acl_set, SyncFile, API_VERSION
elif sys.platform.startswith('freebsd'):  # pragma: freebsd only
    from .platform_freebsd import acl_get, acl_set, API_VERSION
elif sys.platform == 'darwin':  # pragma: darwin only
    from .platform_darwin import acl_get, acl_set, API_VERSION

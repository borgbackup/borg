import sys

if sys.platform.startswith('linux'):  # pragma: linux only
    from .platform_linux import acl_get, acl_set, API_VERSION
elif sys.platform.startswith('freebsd'):  # pragma: freebsd only
    from .platform_freebsd import acl_get, acl_set, API_VERSION
elif sys.platform == 'darwin':  # pragma: darwin only
    from .platform_darwin import acl_get, acl_set, API_VERSION
elif sys.platform == 'win32':  # pragma: windows only
    from .platform_windows import acl_get, acl_set, API_VERSION, get_owner, set_owner
else:  # pragma: unknown platform only
    API_VERSION = 2

    def acl_get(path, item, st, numeric_owner=False):
        pass

    def acl_set(path, item, numeric_owner=False):
        pass

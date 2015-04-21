import sys

if sys.platform.startswith('linux'):
    from attic.platform_linux import acl_get, acl_set, API_VERSION
elif sys.platform.startswith('freebsd'):
    from attic.platform_freebsd import acl_get, acl_set, API_VERSION
elif sys.platform == 'darwin':
    from attic.platform_darwin import acl_get, acl_set, API_VERSION
else:
    API_VERSION = 2

    def acl_get(path, item, st, numeric_owner=False):
        pass

    def acl_set(path, item, numeric_owner=False):
        pass

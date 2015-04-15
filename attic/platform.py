import os

platform = os.uname()[0]

if platform == 'Linux':
    from attic.platform_linux import acl_get, acl_set, API_VERSION
elif platform == 'FreeBSD':
    from attic.platform_freebsd import acl_get, acl_set, API_VERSION
elif platform == 'Darwin':
    from attic.platform_darwin import acl_get, acl_set, API_VERSION
else:
    API_VERSION = 2

    def acl_get(path, item, st, numeric_owner=False):
        pass
    def acl_set(path, item, numeric_owner=False):
        pass

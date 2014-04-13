import os

platform = os.uname().sysname

if platform == 'Linux':
    from attic.platform_linux import acl_get, acl_set, API_VERSION
else:
    API_VERSION = 1

    def acl_get(path, item, numeric_owner=False):
        pass
    def acl_set(path, item, numeric_owner=False):
        pass

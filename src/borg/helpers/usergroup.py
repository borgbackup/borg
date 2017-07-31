import grp
import pwd
from functools import lru_cache


@lru_cache(maxsize=None)
def uid2user(uid, default=None):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return default


@lru_cache(maxsize=None)
def user2uid(user, default=None):
    try:
        return user and pwd.getpwnam(user).pw_uid
    except KeyError:
        return default


@lru_cache(maxsize=None)
def gid2group(gid, default=None):
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return default


@lru_cache(maxsize=None)
def group2gid(group, default=None):
    try:
        return group and grp.getgrnam(group).gr_gid
    except KeyError:
        return default


def posix_acl_use_stored_uid_gid(acl):
    """Replace the user/group field with the stored uid/gid
    """
    from .parseformat import safe_decode, safe_encode
    entries = []
    for entry in safe_decode(acl).split('\n'):
        if entry:
            fields = entry.split(':')
            if len(fields) == 4:
                entries.append(':'.join([fields[0], fields[3], fields[2]]))
            else:
                entries.append(entry)
    return safe_encode('\n'.join(entries))

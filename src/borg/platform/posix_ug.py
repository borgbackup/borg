import grp
import pwd
from functools import lru_cache


@lru_cache(maxsize=None)
def _uid2user(uid, default=None):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return default


@lru_cache(maxsize=None)
def _user2uid(user, default=None):
    if not user:
        return default
    try:
        return pwd.getpwnam(user).pw_uid
    except KeyError:
        return default


@lru_cache(maxsize=None)
def _gid2group(gid, default=None):
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return default


@lru_cache(maxsize=None)
def _group2gid(group, default=None):
    if not group:
        return default
    try:
        return grp.getgrnam(group).gr_gid
    except KeyError:
        return default

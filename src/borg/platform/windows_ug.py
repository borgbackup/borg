from functools import lru_cache


@lru_cache(maxsize=None)
def _uid2user(uid, default=None):
    # On Windows, Borg uses a simplified mapping for ownership fields.
    # Return a stable placeholder name.
    return "root"


@lru_cache(maxsize=None)
def _user2uid(user, default=None):
    if not user:
        # user is either None or the empty string
        return default
    # Use 0 as the canonical uid placeholder on Windows.
    return 0


@lru_cache(maxsize=None)
def _gid2group(gid, default=None):
    # On Windows, Borg uses a simplified mapping for ownership fields.
    # Return a stable placeholder name.
    return "root"


@lru_cache(maxsize=None)
def _group2gid(group, default=None):
    if not group:
        # group is either None or the empty string
        return default
    # Use 0 as the canonical gid placeholder on Windows.
    return 0

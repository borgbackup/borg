from functools import cache


@cache
def _uid2user(uid, default=None):
    # On Windows, Borg uses a simplified mapping for ownership fields.
    # Return a stable placeholder name.
    return "root"


@cache
def _user2uid(user, default=None):
    if not user:
        # user is either None or the empty string
        return default
    # Use 0 as the canonical uid placeholder on Windows.
    return 0


@cache
def _gid2group(gid, default=None):
    # On Windows, Borg uses a simplified mapping for ownership fields.
    # Return a stable placeholder name.
    return "root"


@cache
def _group2gid(group, default=None):
    if not group:
        # group is either None or the empty string
        return default
    # Use 0 as the canonical gid placeholder on Windows.
    return 0

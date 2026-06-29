"""borg 1.x directory layout, kept only so borg transfer can read v1 repos.

The borg2 directory functions live in helpers.fs. This module keeps the old
home/base, config, cache, keys and security dir resolution. borg.security is
the only caller, and only when repository.version == 1. It goes away with the
rest of the borg 1.x transfer support.
"""

import os
import textwrap
from pathlib import Path

from ..constants import *  # NOQA
from ..helpers.fs import ensure_dir

try:
    import pwd  # POSIX only
except ImportError:
    pwd = None  # win32?


def get_base_dir():
    """Get home directory / base directory for borg 1.x.

    Preference order (while being robust against misleading environment when invoked via mount helpers):

    - BORG_BASE_DIR, if set.
    - HOME, if it refers to the current (effective) user's home.
    - ~$USER, if USER is set.
    - The home directory of the current (effective) user from the password database (POSIX).
    - ~ (platform default expansion).
    """
    # 1. Explicit override always wins.
    base_dir = os.environ.get("BORG_BASE_DIR")
    if base_dir:
        return base_dir

    # 2. Prefer HOME, but be robust against mount helpers that set HOME to root's home for non-root users.
    home_env = os.environ.get("HOME")
    if home_env and pwd is not None:  # POSIX only
        try:
            # If HOME points to root's home but we are not root, prefer the invoking user's home.
            root_home = pwd.getpwuid(0).pw_dir
            uid = getattr(os, "geteuid", os.getuid)()
            if uid != 0 and os.path.abspath(home_env) == os.path.abspath(root_home):
                try:
                    user_home = pwd.getpwuid(uid).pw_dir
                except Exception:
                    user_home = None
                if user_home:
                    return user_home
                # if we couldn't figure out the user's home, ignore HOME and continue with fallbacks
                home_env = None
        except Exception:  # nosec B110
            # If anything goes wrong determining root's home, keep HOME as-is.
            pass

    if home_env:
        return home_env

    # 3. Fall back to ~$USER if set (keeps previous behavior and existing tests).
    user = os.environ.get("USER")
    if user:
        return os.path.expanduser("~%s" % user)

    # 4. POSIX: use pw_home for the current uid; otherwise finally fallback to ~.
    if pwd is not None:
        try:
            uid = getattr(os, "geteuid", os.getuid)()
            return pwd.getpwuid(uid).pw_dir
        except Exception:  # nosec B110
            pass

    return os.path.expanduser("~")


def join_base_dir(*paths):
    base_dir = get_base_dir()
    return None if base_dir is None else str(Path(base_dir).joinpath(*paths))


def get_config_dir(*, create=True):
    """Determine where borg 1.x stored the configuration."""
    config_home = join_base_dir(".config")
    # Try to use XDG_CONFIG_HOME instead if BORG_BASE_DIR isn't explicitly set
    if not os.environ.get("BORG_BASE_DIR"):
        config_home = os.environ.get("XDG_CONFIG_HOME", config_home)
    # Use BORG_CONFIG_DIR if set, otherwise assemble final path from config home path
    config_dir = os.environ.get("BORG_CONFIG_DIR", str(Path(config_home) / "borg"))
    if create:
        ensure_dir(config_dir)
    return config_dir


def get_cache_dir(*, create=True):
    """Determine where borg 1.x stored cache data."""
    cache_home = join_base_dir(".cache")
    # Try to use XDG_CACHE_HOME instead if BORG_BASE_DIR isn't explicitly set
    if not os.environ.get("BORG_BASE_DIR"):
        cache_home = os.environ.get("XDG_CACHE_HOME", cache_home)
    # Use BORG_CACHE_DIR if set, otherwise assemble final path from cache home path
    cache_dir = os.environ.get("BORG_CACHE_DIR", str(Path(cache_home) / "borg"))
    if create:
        ensure_dir(cache_dir)
        cache_tag_fn = Path(cache_dir) / CACHE_TAG_NAME
        if not cache_tag_fn.exists():
            cache_tag_contents = (
                CACHE_TAG_CONTENTS
                + textwrap.dedent(
                    """
            # This file is a cache directory tag created by Borg.
            # For information about cache directory tags, see:
            #       https://www.bford.info/cachedir/spec.html
            """
                ).encode("ascii")
            )
            from ..platform import SaveFile

            with SaveFile(cache_tag_fn, binary=True) as fd:
                fd.write(cache_tag_contents)
    return cache_dir


def get_keys_dir(*, create=True):
    """Determine where borg 1.x stored repository keys."""
    keys_dir = os.environ.get("BORG_KEYS_DIR")
    if keys_dir is None:
        # note: do not just give this as default to the environment.get(), see issue #5979.
        keys_dir = str(Path(get_config_dir()) / "keys")
    if create:
        ensure_dir(keys_dir)
    return keys_dir


def get_security_dir(repository_id=None, *, create=True):
    """Determine where borg 1.x stored local security information."""
    security_dir = os.environ.get("BORG_SECURITY_DIR")
    if security_dir is None:
        # note: do not just give this as default to the environment.get(), see issue #5979.
        security_dir = str(Path(get_config_dir()) / "security")
    if repository_id:
        security_dir = str(Path(security_dir) / repository_id)
    if create:
        ensure_dir(security_dir)
    return security_dir

import errno
import hashlib
import os
import posixpath
import re
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import platformdirs

from .errors import Error

from .process import prepare_subprocess_env
from ..platformflags import is_win32

from ..constants import *  # NOQA

from ..logger import create_logger

logger = create_logger()


def ensure_dir(path, mode=stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO, pretty_deadly=True):
    """
    Ensures that the dir exists with the right permissions.
    1) Make sure the directory exists in a race-free operation
    2) If mode is not None and the directory has been created, give the right
    permissions to the leaf directory. The current umask value is masked out first.
    3) If pretty_deadly is True, catch exceptions, reraise them with a pretty
    message.
    Returns if the directory has been created and has the right permissions,
    An exception otherwise. If a deadly exception happened it is reraised.
    """
    try:
        Path(path).mkdir(mode=mode, parents=True, exist_ok=True)
    except OSError as e:
        if pretty_deadly:
            raise Error(str(e))
        else:
            raise


def get_base_dir(*, legacy=False):
    """Get home directory / base directory for borg:

    - BORG_BASE_DIR, if set
    - HOME, if set
    - ~$USER, if USER is set
    - ~
    """
    if legacy:
        base_dir = os.environ.get("BORG_BASE_DIR") or os.environ.get("HOME")
        # Path.expanduser() behaves differently for '~' and '~someuser' as
        # parameters: when called with an explicit username, the possibly set
        # environment variable HOME is no longer respected. So we have to check if
        # it is set and only expand the user's home directory if HOME is unset.
        if not base_dir:
            base_dir = str(Path(f"~{os.environ.get('USER', '')}").expanduser())
    else:
        # we only care for BORG_BASE_DIR here, as it can be used to override the base dir
        # and not use any more or less platform specific way to determine the base dir.
        base_dir = os.environ.get("BORG_BASE_DIR")
    return base_dir


def join_base_dir(*paths, **kw):
    legacy = kw.get("legacy", True)
    base_dir = get_base_dir(legacy=legacy)
    return None if base_dir is None else str(Path(base_dir).joinpath(*paths))


def get_keys_dir(*, legacy=False, create=True):
    """Determine where to repository keys and cache"""
    keys_dir = os.environ.get("BORG_KEYS_DIR")
    if keys_dir is None:
        # note: do not just give this as default to the environment.get(), see issue #5979.
        keys_dir = str(Path(get_config_dir(legacy=legacy)) / "keys")
    if create:
        ensure_dir(keys_dir)
    return keys_dir


def get_security_dir(repository_id=None, *, legacy=False, create=True):
    """Determine where to store local security information."""
    security_dir = os.environ.get("BORG_SECURITY_DIR")
    if security_dir is None:
        get_dir = get_config_dir if legacy else get_data_dir
        # note: do not just give this as default to the environment.get(), see issue #5979.
        security_dir = str(Path(get_dir(legacy=legacy)) / "security")
    if repository_id:
        security_dir = str(Path(security_dir) / repository_id)
    if create:
        ensure_dir(security_dir)
    return security_dir


def get_data_dir(*, legacy=False, create=True):
    """Determine where to store borg changing data on the client"""
    assert legacy is False, "there is no legacy variant of the borg data dir"
    data_dir = os.environ.get(
        "BORG_DATA_DIR", join_base_dir(".local", "share", "borg", legacy=legacy) or platformdirs.user_data_dir("borg")
    )
    if create:
        ensure_dir(data_dir)
    return data_dir


def get_runtime_dir(*, legacy=False, create=True):
    """Determine where to store runtime files, like sockets, PID files, ..."""
    assert legacy is False, "there is no legacy variant of the borg runtime dir"
    runtime_dir = os.environ.get(
        "BORG_RUNTIME_DIR", join_base_dir(".cache", "borg", legacy=legacy) or platformdirs.user_runtime_dir("borg")
    )
    if create:
        ensure_dir(runtime_dir)
    return runtime_dir


def get_socket_filename():
    return str(Path(get_runtime_dir()) / "borg.sock")


def get_cache_dir(*, legacy=False, create=True):
    """Determine where to repository keys and cache"""

    if legacy:
        # Get cache home path
        cache_home = join_base_dir(".cache", legacy=legacy)
        # Try to use XDG_CACHE_HOME instead if BORG_BASE_DIR isn't explicitly set
        if not os.environ.get("BORG_BASE_DIR"):
            cache_home = os.environ.get("XDG_CACHE_HOME", cache_home)
        # Use BORG_CACHE_DIR if set, otherwise assemble final path from cache home path
        cache_dir = os.environ.get("BORG_CACHE_DIR", str(Path(cache_home) / "borg"))
    else:
        cache_dir = os.environ.get(
            "BORG_CACHE_DIR", join_base_dir(".cache", "borg", legacy=legacy) or platformdirs.user_cache_dir("borg")
        )
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
            #       http://www.bford.info/cachedir/spec.html
            """
                ).encode("ascii")
            )
            from ..platform import SaveFile

            with SaveFile(cache_tag_fn, binary=True) as fd:
                fd.write(cache_tag_contents)
    return cache_dir


def get_config_dir(*, legacy=False, create=True):
    """Determine where to store whole config"""

    # Get config home path
    if legacy:
        config_home = join_base_dir(".config", legacy=legacy)
        # Try to use XDG_CONFIG_HOME instead if BORG_BASE_DIR isn't explicitly set
        if not os.environ.get("BORG_BASE_DIR"):
            config_home = os.environ.get("XDG_CONFIG_HOME", config_home)
        # Use BORG_CONFIG_DIR if set, otherwise assemble final path from config home path
        config_dir = os.environ.get("BORG_CONFIG_DIR", str(Path(config_home) / "borg"))
    else:
        config_dir = os.environ.get(
            "BORG_CONFIG_DIR", join_base_dir(".config", "borg", legacy=legacy) or platformdirs.user_config_dir("borg")
        )
    if create:
        ensure_dir(config_dir)
    return config_dir


def dir_is_cachedir(path=None, dir_fd=None):
    """Determines whether the specified directory is a cache directory (and
    therefore should potentially be excluded from the backup) according to
    the CACHEDIR.TAG protocol (http://www.bford.info/cachedir/spec.html).

    If dir_fd is provided, operations will be based on the directory file descriptor.
    Otherwise (path is provided), operations will be based on the directory path.
    """
    tag_fd = None
    try:
        if dir_fd is not None:
            tag_fd = os.open(CACHE_TAG_NAME, os.O_RDONLY, dir_fd=dir_fd)
        else:
            tag_fd = os.open(str(Path(path) / CACHE_TAG_NAME), os.O_RDONLY)
        return os.read(tag_fd, len(CACHE_TAG_CONTENTS)) == CACHE_TAG_CONTENTS
    except (FileNotFoundError, OSError):
        return False
    finally:
        if tag_fd is not None:
            os.close(tag_fd)


def dir_is_tagged(path=None, exclude_caches=None, exclude_if_present=None, dir_fd=None):
    """Determines whether the specified path is excluded by being a cache
    directory or containing user-specified tag files/directories. Returns a
    list of the names of the tag files/directories (either CACHEDIR.TAG or the
    matching user-specified files/directories).

    If dir_fd is provided, operations will be based on the directory file descriptor.
    Otherwise (path is provided), operations will be based on the directory path.
    """
    tag_names = []

    if dir_fd is not None:
        # Use file descriptor-based operations
        if exclude_caches and dir_is_cachedir(dir_fd=dir_fd):
            tag_names.append(CACHE_TAG_NAME)
        if exclude_if_present is not None:
            for tag in exclude_if_present:
                try:
                    os.stat(tag, dir_fd=dir_fd)
                    tag_names.append(tag)
                except FileNotFoundError:
                    pass
    else:
        # Use path-based operations (for backward compatibility)
        if exclude_caches and dir_is_cachedir(path=path):
            tag_names.append(CACHE_TAG_NAME)
        if exclude_if_present is not None:
            for tag in exclude_if_present:
                tag_path = Path(path) / tag
                if tag_path.exists():
                    tag_names.append(tag)

    return tag_names


def make_path_safe(path):
    """
    Make path safe by making it relative and normalized.

    `path` is sanitized by making it relative, removing
    consecutive slashes (e.g. '//'), removing '.' elements,
    and removing trailing slashes.

    For reasons of security, a ValueError is raised should
    `path` contain any '..' elements.
    """
    path = path.lstrip("/")
    if path.startswith("../") or "/../" in path or path.endswith("/..") or path == "..":
        raise ValueError(f"unexpected '..' element in path {path!r}")
    path = posixpath.normpath(path)
    return path


def get_strip_prefix(path):
    # similar to how rsync does it, we allow users to give paths like:
    # /this/gets/stripped/./this/is/kept
    # the whole path is what is used to read from the fs,
    # the strip_prefix will be /this/gets/stripped/ and
    # this/is/kept is the path being archived.
    pos = path.find("/./")  # detect slashdot hack
    if pos > 0:
        # found a prefix to strip! make sure it ends with one "/"!
        return os.path.normpath(path[:pos]) + os.sep
    else:
        # no or empty prefix, nothing to strip!
        return None


_dotdot_re = re.compile(r"^(\.\./)+")


def remove_dotdot_prefixes(path):
    """
    Remove '../'s at the beginning of `path`. Additionally,
    the path is made relative.

    `path` is expected to be normalized already (e.g. via `os.path.normpath()`).
    """
    if is_win32:
        if len(path) > 1 and path[1] == ":":
            path = path.replace(":", "", 1)
        path = path.replace("\\", "/")

    path = path.lstrip("/")
    path = _dotdot_re.sub("", path)
    if path in ["", ".."]:
        return "."
    return path


def assert_sanitized_path(path):
    assert isinstance(path, str)
    # `path` should have been sanitized earlier. Some features,
    # like pattern matching rely on a sanitized path. As a
    # precaution we check here again.
    if make_path_safe(path) != path:
        raise ValueError(f"path {path!r} is not sanitized")
    return path


def to_sanitized_path(path):
    assert isinstance(path, str)
    # Legacy versions of Borg still allowed non-sanitized paths
    # to be stored. So, we sanitize them when reading.
    #
    # Borg 2 ensures paths are safe before storing them. Thus, when
    # support for reading Borg 1 archives is dropped, this should be
    # changed to a simple check to verify paths aren't malicious.
    # Namely, absolute paths and paths containing '..' elements must
    # be rejected.
    #
    # Also checks for '..' elements in `path` for reasons of security.
    return make_path_safe(path)


class HardLinkManager:
    """
    Manage hardlinks (and avoid code duplication doing so).

    A) When creating a borg2 archive from the filesystem, we have to maintain a mapping like:
       (dev, ino) -> (hlid, chunks)  # for fs_hl_targets
       If we encounter the same (dev, ino) again later, we'll just re-use the hlid and chunks list.

    B) When extracting a borg2 archive to the filesystem, we have to maintain a mapping like:
       hlid -> path
       If we encounter the same hlid again later, we hardlink to the path of the already extracted content of same hlid.

    C) When transferring from a borg1 archive, we need:
       path -> chunks_correct  # for borg1_hl_targets, chunks_correct must be either from .chunks_healthy or .chunks.
       If we encounter a regular file item with source == path later, we reuse chunks_correct
       and create the same hlid = hardlink_id_from_path(source).

    D) When importing a tar file (simplified 1-pass way for now, not creating borg hardlink items):
       path -> chunks
       If we encounter a LNK tar entry later with linkname==path, we re-use the chunks and create a regular file item.
       For better hardlink support (including the very first hardlink item for each group of same-target hardlinks),
       we would need a 2-pass processing, which is not yet implemented.
    """

    def __init__(self, *, id_type, info_type):
        self._map = {}
        self.id_type = id_type
        self.info_type = info_type

    def borg1_hardlinkable(self, mode):  # legacy
        return stat.S_ISREG(mode) or stat.S_ISBLK(mode) or stat.S_ISCHR(mode) or stat.S_ISFIFO(mode)

    def borg1_hardlink_master(self, item):  # legacy
        return item.get("hardlink_master", False) and "source" not in item and self.borg1_hardlinkable(item.mode)

    def borg1_hardlink_slave(self, item):  # legacy
        return "source" in item and self.borg1_hardlinkable(item.mode)

    def hardlink_id_from_path(self, path):
        """compute a hardlink id from a path"""
        assert isinstance(path, str)
        return hashlib.sha256(path.encode("utf-8", errors="surrogateescape")).digest()

    def hardlink_id_from_inode(self, *, ino, dev):
        """compute a hardlink id from an inode"""
        assert isinstance(ino, int)
        assert isinstance(dev, int)
        return hashlib.sha256(f"{ino}/{dev}".encode()).digest()

    def remember(self, *, id, info):
        """
        remember stuff from a (usually contentful) item.

        :param id: some id used to reference to the contentful item, could be:
                   a path (tar style, old borg style) [bytes]
                   a hlid (new borg style) [bytes]
                   a (dev, inode) tuple (filesystem)
        :param info: information to remember, could be:
                     chunks list
                     hlid
        """
        assert isinstance(id, self.id_type), f"id is {id!r}, not of type {self.id_type}"
        assert isinstance(info, self.info_type), f"info is {info!r}, not of type {self.info_type}"
        self._map[id] = info

    def retrieve(self, id, *, default=None):
        """
        retrieve stuff to use it in a (usually contentless) item.
        """
        assert isinstance(id, self.id_type), f"id is {id!r}, not of type {self.id_type}"
        return self._map.get(id, default)


def scandir_keyfunc(dirent):
    try:
        return (0, dirent.inode())
    except OSError as e:
        # maybe a permission denied error while doing a stat() on the dirent
        logger.debug("scandir_inorder: Unable to stat %s: %s", dirent.path, e)
        # order this dirent after all the others lexically by file name
        # we may not break the whole scandir just because of an exception in one dirent
        # ignore the exception for now, since another stat will be done later anyways
        # (or the entry will be skipped by an exclude pattern)
        return (1, dirent.name)


def scandir_inorder(*, path, fd=None):
    arg = fd if fd is not None else path
    return sorted(os.scandir(arg), key=scandir_keyfunc)


def secure_erase(path, *, avoid_collateral_damage):
    """Attempt to erase a file securely by writing random data over it before deleting it.

    If avoid_collateral_damage is True, we only secure erase if the total link count is 1,
    otherwise we just do a normal "delete" (unlink) without first overwriting it with random.
    This avoids other hardlinks pointing to same inode as <path> getting damaged, but might be less secure.
    A typical scenario where this is useful are quick "hardlink copies" of bigger directories.

    If avoid_collateral_damage is False, we always secure erase.
    If there are hardlinks pointing to the same inode as <path>, they will contain random garbage afterwards.
    """
    path_obj = Path(path)
    with path_obj.open("r+b") as fd:
        st = os.stat(fd.fileno())
        if not (st.st_nlink > 1 and avoid_collateral_damage):
            fd.write(os.urandom(st.st_size))
            fd.flush()
            os.fsync(fd.fileno())
    path_obj.unlink()


def safe_unlink(path):
    """
    Safely unlink (delete) *path*.

    If we run out of space while deleting the file, we try truncating it first.
    BUT we truncate only if path is the only hardlink referring to this content.

    Use this when deleting potentially large files when recovering
    from a VFS error such as ENOSPC. It can help a full file system
    recover. Refer to the "File system interaction" section
    in legacyrepository.py for further explanations.
    """
    path_obj = Path(path)
    try:
        path_obj.unlink()
    except OSError as unlink_err:
        if unlink_err.errno != errno.ENOSPC:
            # not free space related, give up here.
            raise
        # we ran out of space while trying to delete the file.
        st = path_obj.stat()
        if st.st_nlink > 1:
            # rather give up here than cause collateral damage to the other hardlink.
            raise
        # no other hardlink! try to recover free space by truncating this file.
        try:
            # Do not create *path* if it does not exist, open for truncation in r+b mode (=O_RDWR|O_BINARY).
            with open(path, "r+b") as fd:
                fd.truncate()
        except OSError:
            # truncate didn't work, so we still have the original unlink issue - give up:
            raise unlink_err
        else:
            # successfully truncated the file, try again deleting it:
            path_obj.unlink()


def dash_open(path, mode):
    assert "+" not in mode  # the streams are either r or w, but never both
    if path == "-":
        stream = sys.stdin if "r" in mode else sys.stdout
        return stream.buffer if "b" in mode else stream
    else:
        return open(path, mode)


def O_(*flags):
    result = 0
    for flag in flags:
        result |= getattr(os, "O_" + flag, 0)
    return result


flags_base = O_("BINARY", "NOCTTY", "RDONLY")
flags_special = flags_base | O_("NOFOLLOW")  # BLOCK == wait when reading devices or fifos
flags_special_follow = flags_base  # BLOCK == wait when reading symlinked devices or fifos
flags_normal = flags_base | O_("NONBLOCK", "NOFOLLOW")
flags_noatime = flags_normal | O_("NOATIME")
flags_dir = O_("DIRECTORY", "RDONLY", "NOFOLLOW")


def os_open(*, flags, path=None, parent_fd=None, name=None, noatime=False):
    """
    Use os.open to open a fs item.

    If parent_fd and name are given, they are preferred and openat will be used,
    path is not used in this case.

    :param path: full (but not necessarily absolute) path
    :param parent_fd: open directory file descriptor
    :param name: name relative to parent_fd
    :param flags: open flags for os.open() (int)
    :param noatime: True if access time shall be preserved
    :return: file descriptor
    """
    if name and parent_fd is not None:
        # name is neither None nor empty, parent_fd given.
        fname = name  # use name relative to parent_fd
    else:
        fname, parent_fd = path, None  # just use the path
    if is_win32 and os.path.isdir(fname):
        # Directories can not be opened on Windows.
        return None
    _flags_normal = flags
    if noatime:
        _flags_noatime = _flags_normal | O_("NOATIME")
        try:
            # if we have O_NOATIME, this likely will succeed if we are root or owner of file:
            fd = os.open(fname, _flags_noatime, dir_fd=parent_fd)
        except PermissionError:
            if _flags_noatime == _flags_normal:
                # we do not have O_NOATIME, no need to try again:
                raise
            # Was this EPERM due to the O_NOATIME flag? Try again without it:
            fd = os.open(fname, _flags_normal, dir_fd=parent_fd)
        except OSError as exc:
            # O_NOATIME causes EROFS when accessing a volume shadow copy in WSL1
            from . import workarounds

            if "retry_erofs" in workarounds and exc.errno == errno.EROFS and _flags_noatime != _flags_normal:
                fd = os.open(fname, _flags_normal, dir_fd=parent_fd)
            else:
                raise
    else:
        fd = os.open(fname, _flags_normal, dir_fd=parent_fd)
    return fd


def os_stat(*, path=None, parent_fd=None, name=None, follow_symlinks=False):
    """
    Use os.stat to open a fs item.

    If parent_fd and name are given, they are preferred and statat will be used,
    path is not used in this case.

    :param path: full (but not necessarily absolute) path
    :param parent_fd: open directory file descriptor
    :param name: name relative to parent_fd
    :return: stat info
    """
    if name and parent_fd is not None:
        # name is neither None nor empty, parent_fd given.
        fname = name  # use name relative to parent_fd
    else:
        fname, parent_fd = path, None  # just use the path
    return os.stat(fname, dir_fd=parent_fd, follow_symlinks=follow_symlinks)


def umount(mountpoint):
    from . import set_ec

    env = prepare_subprocess_env(system=True)
    try:
        rc = subprocess.call(["fusermount", "-u", mountpoint], env=env)  # nosec B603, B607
    except FileNotFoundError:
        rc = subprocess.call(["umount", mountpoint], env=env)  # nosec B603, B607
    set_ec(rc)


# below is a slightly modified tempfile.mkstemp that has an additional mode parameter.
# see https://github.com/borgbackup/borg/issues/6933 and https://github.com/borgbackup/borg/issues/6400

import os as _os  # NOQA
import sys as _sys  # NOQA
import errno as _errno  # NOQA
from tempfile import _sanitize_params, _get_candidate_names  # type: ignore[attr-defined] # NOQA
from tempfile import TMP_MAX, _text_openflags, _bin_openflags  # type: ignore[attr-defined] # NOQA


def _mkstemp_inner(dir, pre, suf, flags, output_type, mode=0o600):
    """Code common to mkstemp, TemporaryFile, and NamedTemporaryFile."""

    dir = _os.path.abspath(dir)
    names = _get_candidate_names()
    if output_type is bytes:
        names = map(_os.fsencode, names)

    for seq in range(TMP_MAX):
        name = next(names)
        file = _os.path.join(dir, pre + name + suf)
        _sys.audit("tempfile.mkstemp", file)
        try:
            fd = _os.open(file, flags, mode)
        except FileExistsError:
            continue  # try again
        except PermissionError:
            # This exception is thrown when a directory with the chosen name
            # already exists on windows.
            if _os.name == "nt" and _os.path.isdir(dir) and _os.access(dir, _os.W_OK):
                continue
            else:
                raise
        return fd, file

    raise FileExistsError(_errno.EEXIST, "No usable temporary file name found")


def mkstemp_mode(suffix=None, prefix=None, dir=None, text=False, mode=0o600):
    """User-callable function to create and return a unique temporary
    file.  The return value is a pair (fd, name) where fd is the
    file descriptor returned by os.open, and name is the filename.
    If 'suffix' is not None, the file name will end with that suffix,
    otherwise there will be no suffix.
    If 'prefix' is not None, the file name will begin with that prefix,
    otherwise a default prefix is used.
    If 'dir' is not None, the file will be created in that directory,
    otherwise a default directory is used.
    If 'text' is specified and true, the file is opened in text
    mode.  Else (the default) the file is opened in binary mode.
    If any of 'suffix', 'prefix' and 'dir' are not None, they must be the
    same type.  If they are bytes, the returned name will be bytes; str
    otherwise.
    The file is readable and writable only by the creating user ID.
    If the operating system uses permission bits to indicate whether a
    file is executable, the file is executable by no one. The file
    descriptor is not inherited by children of this process.
    Caller is responsible for deleting the file when done with it.
    """

    prefix, suffix, dir, output_type = _sanitize_params(prefix, suffix, dir)

    if text:
        flags = _text_openflags
    else:
        flags = _bin_openflags

    return _mkstemp_inner(dir, prefix, suffix, flags, output_type, mode)

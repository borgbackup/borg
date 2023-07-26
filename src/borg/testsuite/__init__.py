from contextlib import contextmanager
import functools
import os

try:
    import posix
except ImportError:
    posix = None

import stat
import sys
import sysconfig
import tempfile
import unittest

# Note: this is used by borg.selftest, do not *require* pytest functionality here.
try:
    from pytest import raises
except:  # noqa
    raises = None

from ..fuse_impl import llfuse, has_llfuse, has_pyfuse3  # NOQA
from .. import platform
from ..platformflags import is_win32

# Does this version of llfuse support ns precision?
have_fuse_mtime_ns = hasattr(llfuse.EntryAttributes, "st_mtime_ns") if llfuse else False

has_lchflags = hasattr(os, "lchflags") or sys.platform.startswith("linux")
try:
    with tempfile.NamedTemporaryFile() as file:
        platform.set_flags(file.name, stat.UF_NODUMP)
except OSError:
    has_lchflags = False

# The mtime get/set precision varies on different OS and Python versions
if posix and "HAVE_FUTIMENS" in getattr(posix, "_have_functions", []):
    st_mtime_ns_round = 0  # 1ns resolution
elif "HAVE_UTIMES" in sysconfig.get_config_vars():
    st_mtime_ns_round = -3  # 1us resolution
else:
    st_mtime_ns_round = -9  # 1s resolution

if sys.platform.startswith("netbsd"):
    st_mtime_ns_round = -4  # 10us - strange: only >1 microsecond resolution here?


def same_ts_ns(ts_ns1, ts_ns2):
    """compare 2 timestamps (both in nanoseconds) whether they are (roughly) equal"""
    diff_ts = int(abs(ts_ns1 - ts_ns2))
    diff_max = 10 ** (-st_mtime_ns_round)
    return diff_ts <= diff_max


rejected_dotdot_paths = (
    "..",
    "../",
    "../etc/shadow",
    "/..",
    "/../",
    "/../etc",
    "/../etc/",
    "etc/..",
    "/etc/..",
    "/etc/../etc/shadow",
    "//etc/..",
    "etc//..",
    "etc/..//",
    "foo/../bar",
)


@contextmanager
def unopened_tempfile():
    with tempfile.TemporaryDirectory() as tempdir:
        yield os.path.join(tempdir, "file")


@contextmanager
def changedir(dir):
    cwd = os.getcwd()
    os.chdir(dir)
    yield
    os.chdir(cwd)


def is_root():
    """return True if running with high privileges, like as root"""
    if is_win32:
        return False  # TODO
    else:
        return os.getuid() == 0


@functools.lru_cache
def are_symlinks_supported():
    with unopened_tempfile() as filepath:
        try:
            os.symlink("somewhere", filepath)
            if os.stat(filepath, follow_symlinks=False) and os.readlink(filepath) == "somewhere":
                return True
        except OSError:
            pass
    return False


@functools.lru_cache
def are_hardlinks_supported():
    if not hasattr(os, "link"):
        # some pythons do not have os.link
        return False

    with unopened_tempfile() as file1path, unopened_tempfile() as file2path:
        open(file1path, "w").close()
        try:
            os.link(file1path, file2path)
            stat1 = os.stat(file1path)
            stat2 = os.stat(file2path)
            if stat1.st_nlink == stat2.st_nlink == 2 and stat1.st_ino == stat2.st_ino:
                return True
        except OSError:
            pass
    return False


@functools.lru_cache
def are_fifos_supported():
    with unopened_tempfile() as filepath:
        try:
            os.mkfifo(filepath)
            return True
        except OSError:
            pass
        except NotImplementedError:
            pass
        except AttributeError:
            pass
        return False


@functools.lru_cache
def is_utime_fully_supported():
    with unopened_tempfile() as filepath:
        # Some filesystems (such as SSHFS) don't support utime on symlinks
        if are_symlinks_supported():
            os.symlink("something", filepath)
        else:
            open(filepath, "w").close()
        try:
            os.utime(filepath, (1000, 2000), follow_symlinks=False)
            new_stats = os.stat(filepath, follow_symlinks=False)
            if new_stats.st_atime == 1000 and new_stats.st_mtime == 2000:
                return True
        except OSError:
            pass
        except NotImplementedError:
            pass
        return False


@functools.lru_cache
def is_birthtime_fully_supported():
    if not hasattr(os.stat_result, "st_birthtime"):
        return False
    with unopened_tempfile() as filepath:
        # Some filesystems (such as SSHFS) don't support utime on symlinks
        if are_symlinks_supported():
            os.symlink("something", filepath)
        else:
            open(filepath, "w").close()
        try:
            birthtime, mtime, atime = 946598400, 946684800, 946771200
            os.utime(filepath, (atime, birthtime), follow_symlinks=False)
            os.utime(filepath, (atime, mtime), follow_symlinks=False)
            new_stats = os.stat(filepath, follow_symlinks=False)
            if new_stats.st_birthtime == birthtime and new_stats.st_mtime == mtime and new_stats.st_atime == atime:
                return True
        except OSError:
            pass
        except NotImplementedError:
            pass
        return False


def no_selinux(x):
    # selinux fails our FUSE tests, thus ignore selinux xattrs
    SELINUX_KEY = b"security.selinux"
    if isinstance(x, dict):
        return {k: v for k, v in x.items() if k != SELINUX_KEY}
    if isinstance(x, list):
        return [k for k in x if k != SELINUX_KEY]


class BaseTestCase(unittest.TestCase):
    assert_in = unittest.TestCase.assertIn
    assert_not_in = unittest.TestCase.assertNotIn
    assert_equal = unittest.TestCase.assertEqual
    assert_not_equal = unittest.TestCase.assertNotEqual
    assert_raises = staticmethod(raises) if raises else unittest.TestCase.assertRaises  # type: ignore


class FakeInputs:
    """Simulate multiple user inputs, can be used as input() replacement"""

    def __init__(self, inputs):
        self.inputs = inputs

    def __call__(self, prompt=None):
        if prompt is not None:
            print(prompt, end="")
        try:
            return self.inputs.pop(0)
        except IndexError:
            raise EOFError from None

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
import time
import unittest

# Note: this is used by borg.selftest, do not *require* pytest functionality here.
try:
    from pytest import raises
except:  # noqa
    raises = None

from ..fuse_impl import llfuse, has_any_fuse, has_llfuse, has_pyfuse3, has_mfusepy, ENOATTR  # NOQA
from .. import platform
from ..platformflags import is_win32, is_darwin

# Does this version of llfuse support ns precision?
have_fuse_mtime_ns = hasattr(llfuse.EntryAttributes, "st_mtime_ns") if llfuse else False

has_mknod = hasattr(os, "mknod")

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

if is_win32:
    st_mtime_ns_round = -7  # 10ms resolution


def same_ts_ns(ts_ns1, ts_ns2):
    """Compare two timestamps (both in nanoseconds) to determine whether they are (roughly) equal."""
    diff_ts = int(abs(ts_ns1 - ts_ns2))
    diff_max = 10 ** (-st_mtime_ns_round)
    return diff_ts <= diff_max


def granularity_sleep(*, ctime_quirk=False):
    """Sleep long enough to overcome filesystem timestamp granularity and related platform quirks.

    Purpose
    - Ensure that successive file operations land on different timestamp "ticks" across filesystems
      and operating systems, so tests that compare mtime/ctime are reliable.

    Default rationale (ctime_quirk=False)
    - macOS: Some volumes may still be HFS+ (1 s timestamp granularity). To be safe across APFS and HFS+,
      sleep 1.0 s on Darwin.
    - Windows/NTFS: Although NTFS stores timestamps with 100 ns units, actual updates can be delayed by
      scheduling/metadata behavior. Sleep a short but noticeable amount (0.2 s).
    - Linux/BSD and others: Modern filesystems (ext4, XFS, Btrfs, ZFS, UFS2, etc.) typically have
      sub-second granularity; a small delay (0.02 s) is sufficient in practice.

    Windows ctime quirk (ctime_quirk=True)
    - On Windows, ``stat().st_ctime`` is the file creation time, not "metadata change time" as on Unix.
    - NTFS implements a feature called "file system tunneling" that preserves certain metadata — including
      creation time — for short intervals when a file is deleted and a new file with the same name is
      created in the same directory. The default tunneling window is about 15 seconds.
    - Consequence: If a test deletes a file and quickly recreates it with the same name, the creation time
      (st_ctime) may remain unchanged for up to ~15 s, causing flakiness when tests expect a changed ctime.
    - When ``ctime_quirk=True`` this helper sleeps long enough on Windows (15.0 s) to exceed the tunneling
      window so the new file receives a fresh creation time. On non-Windows platforms this flag has no
      special effect beyond the normal, short sleep.

    Parameters
    - ctime_quirk: bool (default False)
      If True, apply the Windows NTFS tunneling workaround (15 s sleep on Windows). Ignored elsewhere.
    """
    if is_darwin:
        duration = 1.0
    elif is_win32:
        duration = 0.2 if not ctime_quirk else 15.0
    else:
        # Default for Linux/BSD and others with fine-grained timestamps
        duration = 0.02
    time.sleep(duration)


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
    """Return True if running with high privileges (e.g., as root)."""
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
            try:
                os.utime(filepath, (1000, 2000), follow_symlinks=False)
                new_stats = os.stat(filepath, follow_symlinks=False)
                if new_stats.st_atime == 1000 and new_stats.st_mtime == 2000:
                    return True
            except OSError:
                pass
            except NotImplementedError:
                pass
        else:
            open(filepath, "w").close()
            try:
                os.utime(filepath, (1000, 2000))
                new_stats = os.stat(filepath)
                if new_stats.st_atime == 1000 and new_stats.st_mtime == 2000:
                    return True
            except OSError:
                pass
    return False


@functools.lru_cache
def is_birthtime_fully_supported():
    with unopened_tempfile() as filepath:
        # Some filesystems (such as SSHFS) don't support utime on symlinks
        if are_symlinks_supported():
            os.symlink("something", filepath)
        else:
            open(filepath, "w").close()
        try:
            birthtime_ns, mtime_ns, atime_ns = 946598400 * 10**9, 946684800 * 10**9, 946771200 * 10**9
            platform.set_birthtime(filepath, birthtime_ns)
            os.utime(filepath, ns=(atime_ns, mtime_ns))
            new_stats = os.stat(filepath)
            bt = platform.get_birthtime_ns(new_stats, filepath)
            if (
                bt is not None
                and same_ts_ns(bt, birthtime_ns)
                and same_ts_ns(new_stats.st_mtime_ns, mtime_ns)
                and same_ts_ns(new_stats.st_atime_ns, atime_ns)
            ):
                return True
        except (OSError, NotImplementedError, AttributeError):
            pass
        return False


def filter_xattrs(x):
    # selinux and com.apple.provenance fail our FUSE tests, thus ignore them
    UNWANTED_KEYS = {b"security.selinux", b"com.apple.provenance"}
    if isinstance(x, dict):
        return {k: v for k, v in x.items() if k not in UNWANTED_KEYS}
    if isinstance(x, list):
        return [k for k in x if k not in UNWANTED_KEYS]
    raise ValueError("Unsupported type: %s" % type(x))


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

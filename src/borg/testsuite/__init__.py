from contextlib import contextmanager
import filecmp
import functools
import os
import posix
import stat
import sys
import sysconfig
import tempfile
import time
import uuid
import unittest

from ..xattr import get_all
from ..platform import get_flags, umount
from .. import platform

# Note: this is used by borg.selftest, do not use or import py.test functionality here.

try:
    import llfuse
    # Does this version of llfuse support ns precision?
    have_fuse_mtime_ns = hasattr(llfuse.EntryAttributes, 'st_mtime_ns')
except ImportError:
    have_fuse_mtime_ns = False

try:
    from pytest import raises
except ImportError:
    raises = None

has_lchflags = hasattr(os, 'lchflags') or sys.platform.startswith('linux')
try:
    with tempfile.NamedTemporaryFile() as file:
        platform.set_flags(file.name, stat.UF_NODUMP)
except OSError:
    has_lchflags = False

try:
    import llfuse
    has_llfuse = True or llfuse  # avoids "unused import"
except ImportError:
    has_llfuse = False

# The mtime get/set precision varies on different OS and Python versions
if 'HAVE_FUTIMENS' in getattr(posix, '_have_functions', []):
    st_mtime_ns_round = 0
elif 'HAVE_UTIMES' in sysconfig.get_config_vars():
    st_mtime_ns_round = -6
else:
    st_mtime_ns_round = -9

if sys.platform.startswith('netbsd'):
    st_mtime_ns_round = -4  # only >1 microsecond resolution here?


@contextmanager
def unopened_tempfile():
    with tempfile.TemporaryDirectory() as tempdir:
        yield os.path.join(tempdir, "file")


@functools.lru_cache()
def are_symlinks_supported():
    with unopened_tempfile() as filepath:
        try:
            os.symlink('somewhere', filepath)
            if os.stat(filepath, follow_symlinks=False) and os.readlink(filepath) == 'somewhere':
                return True
        except OSError:
            pass
    return False


@functools.lru_cache()
def are_hardlinks_supported():
    with unopened_tempfile() as file1path, unopened_tempfile() as file2path:
        open(file1path, 'w').close()
        try:
            os.link(file1path, file2path)
            stat1 = os.stat(file1path)
            stat2 = os.stat(file2path)
            if stat1.st_nlink == stat2.st_nlink == 2 and stat1.st_ino == stat2.st_ino:
                return True
        except OSError:
            pass
    return False


@functools.lru_cache()
def are_fifos_supported():
    with unopened_tempfile() as filepath:
        try:
            os.mkfifo(filepath)
            return True
        except OSError:
            return False


@functools.lru_cache()
def is_utime_fully_supported():
    with unopened_tempfile() as filepath:
        # Some filesystems (such as SSHFS) don't support utime on symlinks
        if are_symlinks_supported():
            os.symlink('something', filepath)
        else:
            open(filepath, 'w').close()
        try:
            os.utime(filepath, (1000, 2000), follow_symlinks=False)
            new_stats = os.stat(filepath, follow_symlinks=False)
            if new_stats.st_atime == 1000 and new_stats.st_mtime == 2000:
                return True
        except OSError as err:
            pass
        return False


def no_selinux(x):
    # selinux fails our FUSE tests, thus ignore selinux xattrs
    SELINUX_KEY = 'security.selinux'
    if isinstance(x, dict):
        return {k: v for k, v in x.items() if k != SELINUX_KEY}
    if isinstance(x, list):
        return [k for k in x if k != SELINUX_KEY]


class BaseTestCase(unittest.TestCase):
    """
    """
    assert_in = unittest.TestCase.assertIn
    assert_not_in = unittest.TestCase.assertNotIn
    assert_equal = unittest.TestCase.assertEqual
    assert_not_equal = unittest.TestCase.assertNotEqual
    assert_true = unittest.TestCase.assertTrue

    if raises:
        assert_raises = staticmethod(raises)
    else:
        assert_raises = unittest.TestCase.assertRaises

    @contextmanager
    def assert_creates_file(self, path):
        self.assert_true(not os.path.exists(path), '{} should not exist'.format(path))
        yield
        self.assert_true(os.path.exists(path), '{} should exist'.format(path))

    def assert_dirs_equal(self, dir1, dir2, **kwargs):
        diff = filecmp.dircmp(dir1, dir2)
        self._assert_dirs_equal_cmp(diff, **kwargs)

    def _assert_dirs_equal_cmp(self, diff, ignore_bsdflags=False, ignore_xattrs=False, ignore_ns=False):
        self.assert_equal(diff.left_only, [])
        self.assert_equal(diff.right_only, [])
        self.assert_equal(diff.diff_files, [])
        self.assert_equal(diff.funny_files, [])
        for filename in diff.common:
            path1 = os.path.join(diff.left, filename)
            path2 = os.path.join(diff.right, filename)
            s1 = os.stat(path1, follow_symlinks=False)
            s2 = os.stat(path2, follow_symlinks=False)
            # Assume path2 is on FUSE if st_dev is different
            fuse = s1.st_dev != s2.st_dev
            attrs = ['st_uid', 'st_gid', 'st_rdev']
            if not fuse or not os.path.isdir(path1):
                # dir nlink is always 1 on our fuse filesystem
                attrs.append('st_nlink')
            d1 = [filename] + [getattr(s1, a) for a in attrs]
            d2 = [filename] + [getattr(s2, a) for a in attrs]
            d1.insert(1, oct(s1.st_mode))
            d2.insert(1, oct(s2.st_mode))
            if not ignore_bsdflags:
                d1.append(get_flags(path1, s1))
                d2.append(get_flags(path2, s2))
            # ignore st_rdev if file is not a block/char device, fixes #203
            if not stat.S_ISCHR(s1.st_mode) and not stat.S_ISBLK(s1.st_mode):
                d1[4] = None
            if not stat.S_ISCHR(s2.st_mode) and not stat.S_ISBLK(s2.st_mode):
                d2[4] = None
            # If utime isn't fully supported, borg can't set mtime.
            # Therefore, we shouldn't test it in that case.
            if is_utime_fully_supported():
                # Older versions of llfuse do not support ns precision properly
                if ignore_ns:
                    d1.append(int(s1.st_mtime_ns / 1e9))
                    d2.append(int(s2.st_mtime_ns / 1e9))
                elif fuse and not have_fuse_mtime_ns:
                    d1.append(round(s1.st_mtime_ns, -4))
                    d2.append(round(s2.st_mtime_ns, -4))
                else:
                    d1.append(round(s1.st_mtime_ns, st_mtime_ns_round))
                    d2.append(round(s2.st_mtime_ns, st_mtime_ns_round))
            if not ignore_xattrs:
                d1.append(no_selinux(get_all(path1, follow_symlinks=False)))
                d2.append(no_selinux(get_all(path2, follow_symlinks=False)))
            self.assert_equal(d1, d2)
        for sub_diff in diff.subdirs.values():
            self._assert_dirs_equal_cmp(sub_diff, ignore_bsdflags=ignore_bsdflags, ignore_xattrs=ignore_xattrs, ignore_ns=ignore_ns)

    @contextmanager
    def fuse_mount(self, location, mountpoint, *options):
        os.mkdir(mountpoint)
        args = ['mount', location, mountpoint] + list(options)
        self.cmd(*args, fork=True)
        self.wait_for_mount(mountpoint)
        yield
        umount(mountpoint)
        os.rmdir(mountpoint)
        # Give the daemon some time to exit
        time.sleep(.2)

    def wait_for_mount(self, path, timeout=5):
        """Wait until a filesystem is mounted on `path`
        """
        timeout += time.time()
        while timeout > time.time():
            if os.path.ismount(path):
                return
            time.sleep(.1)
        raise Exception('wait_for_mount(%s) timeout' % path)


class changedir:
    def __init__(self, dir):
        self.dir = dir

    def __enter__(self):
        self.old = os.getcwd()
        os.chdir(self.dir)

    def __exit__(self, *args, **kw):
        os.chdir(self.old)


class environment_variable:
    def __init__(self, **values):
        self.values = values
        self.old_values = {}

    def __enter__(self):
        for k, v in self.values.items():
            self.old_values[k] = os.environ.get(k)
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def __exit__(self, *args, **kw):
        for k, v in self.old_values.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


class FakeInputs:
    """Simulate multiple user inputs, can be used as input() replacement"""
    def __init__(self, inputs):
        self.inputs = inputs

    def __call__(self, prompt=None):
        if prompt is not None:
            print(prompt, end='')
        try:
            return self.inputs.pop(0)
        except IndexError:
            raise EOFError from None

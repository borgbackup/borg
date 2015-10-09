from contextlib import contextmanager
import filecmp
import os
import posix
import stat
import sys
import sysconfig
import time
import unittest
from ..helpers import st_mtime_ns
from ..xattr import get_all

try:
    import llfuse
    # Does this version of llfuse support ns precision?
    have_fuse_mtime_ns = hasattr(llfuse.EntryAttributes, 'st_mtime_ns')
except ImportError:
    have_fuse_mtime_ns = False

has_lchflags = hasattr(os, 'lchflags')


# The mtime get/set precision varies on different OS and Python versions
if 'HAVE_FUTIMENS' in getattr(posix, '_have_functions', []):
    st_mtime_ns_round = 0
elif 'HAVE_UTIMES' in sysconfig.get_config_vars():
    st_mtime_ns_round = -6
else:
    st_mtime_ns_round = -9

if sys.platform.startswith('netbsd'):
    st_mtime_ns_round = -4  # only >1 microsecond resolution here?

has_mtime_ns = sys.version >= '3.3'
utime_supports_fd = os.utime in getattr(os, 'supports_fd', {})


class BaseTestCase(unittest.TestCase):
    """
    """
    assert_in = unittest.TestCase.assertIn
    assert_not_in = unittest.TestCase.assertNotIn
    assert_equal = unittest.TestCase.assertEqual
    assert_not_equal = unittest.TestCase.assertNotEqual
    assert_raises = unittest.TestCase.assertRaises
    assert_true = unittest.TestCase.assertTrue

    @contextmanager
    def assert_creates_file(self, path):
        self.assert_true(not os.path.exists(path), '{} should not exist'.format(path))
        yield
        self.assert_true(os.path.exists(path), '{} should exist'.format(path))

    def assert_dirs_equal(self, dir1, dir2):
        diff = filecmp.dircmp(dir1, dir2)
        self._assert_dirs_equal_cmp(diff)

    def _assert_dirs_equal_cmp(self, diff):
        self.assert_equal(diff.left_only, [])
        self.assert_equal(diff.right_only, [])
        self.assert_equal(diff.diff_files, [])
        self.assert_equal(diff.funny_files, [])
        for filename in diff.common:
            path1 = os.path.join(diff.left, filename)
            path2 = os.path.join(diff.right, filename)
            s1 = os.lstat(path1)
            s2 = os.lstat(path2)
            # Assume path2 is on FUSE if st_dev is different
            fuse = s1.st_dev != s2.st_dev
            attrs = ['st_mode', 'st_uid', 'st_gid', 'st_rdev']
            if has_lchflags:
                attrs.append('st_flags')
            if not fuse or not os.path.isdir(path1):
                # dir nlink is always 1 on our fuse filesystem
                attrs.append('st_nlink')
            d1 = [filename] + [getattr(s1, a) for a in attrs]
            d2 = [filename] + [getattr(s2, a) for a in attrs]
            # ignore st_rdev if file is not a block/char device, fixes #203
            if not stat.S_ISCHR(d1[1]) and not stat.S_ISBLK(d1[1]):
                d1[4] = None
            if not stat.S_ISCHR(d2[1]) and not stat.S_ISBLK(d2[1]):
                d2[4] = None
            if not os.path.islink(path1) or utime_supports_fd:
                # Older versions of llfuse do not support ns precision properly
                if fuse and not have_fuse_mtime_ns:
                    d1.append(round(st_mtime_ns(s1), -4))
                    d2.append(round(st_mtime_ns(s2), -4))
                d1.append(round(st_mtime_ns(s1), st_mtime_ns_round))
                d2.append(round(st_mtime_ns(s2), st_mtime_ns_round))
            d1.append(get_all(path1, follow_symlinks=False))
            d2.append(get_all(path2, follow_symlinks=False))
            self.assert_equal(d1, d2)
        for sub_diff in diff.subdirs.values():
            self._assert_dirs_equal_cmp(sub_diff)

    def wait_for_mount(self, path, timeout=5):
        """Wait until a filesystem is mounted on `path`
        """
        timeout += time.time()
        while timeout > time.time():
            if os.path.ismount(path):
                return
            time.sleep(.1)
        raise Exception('wait_for_mount(%s) timeout' % path)

import re
import unittest
from datetime import datetime

from ...constants import *  # NOQA
from . import (
    ArchiverTestCaseBase,
    RemoteArchiverTestCaseBase,
    ArchiverTestCaseBinaryBase,
    RK_ENCRYPTION,
    src_dir,
    BORG_EXES,
)


class ArchiverTestCase(ArchiverTestCaseBase):
    def test_prune_repository(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test1", src_dir)
        self.cmd(f"--repo={self.repository_location}", "create", "test2", src_dir)
        # these are not really a checkpoints, but they look like some:
        self.cmd(f"--repo={self.repository_location}", "create", "test3.checkpoint", src_dir)
        self.cmd(f"--repo={self.repository_location}", "create", "test3.checkpoint.1", src_dir)
        self.cmd(f"--repo={self.repository_location}", "create", "test4.checkpoint", src_dir)
        output = self.cmd(f"--repo={self.repository_location}", "prune", "--list", "--dry-run", "--keep-daily=1")
        assert re.search(r"Would prune:\s+test1", output)
        # must keep the latest non-checkpoint archive:
        assert re.search(r"Keeping archive \(rule: daily #1\):\s+test2", output)
        # must keep the latest checkpoint archive:
        assert re.search(r"Keeping checkpoint archive:\s+test4.checkpoint", output)
        output = self.cmd(f"--repo={self.repository_location}", "rlist", "--consider-checkpoints")
        self.assert_in("test1", output)
        self.assert_in("test2", output)
        self.assert_in("test3.checkpoint", output)
        self.assert_in("test3.checkpoint.1", output)
        self.assert_in("test4.checkpoint", output)
        self.cmd(f"--repo={self.repository_location}", "prune", "--keep-daily=1")
        output = self.cmd(f"--repo={self.repository_location}", "rlist", "--consider-checkpoints")
        self.assert_not_in("test1", output)
        # the latest non-checkpoint archive must be still there:
        self.assert_in("test2", output)
        # only the latest checkpoint archive must still be there:
        self.assert_not_in("test3.checkpoint", output)
        self.assert_not_in("test3.checkpoint.1", output)
        self.assert_in("test4.checkpoint", output)
        # now we supersede the latest checkpoint by a successful backup:
        self.cmd(f"--repo={self.repository_location}", "create", "test5", src_dir)
        self.cmd(f"--repo={self.repository_location}", "prune", "--keep-daily=2")
        output = self.cmd(f"--repo={self.repository_location}", "rlist", "--consider-checkpoints")
        # all checkpoints should be gone now:
        self.assert_not_in("checkpoint", output)
        # the latest archive must be still there
        self.assert_in("test5", output)

    def _create_archive_ts(self, name, y, m, d, H=0, M=0, S=0):
        self.cmd(
            f"--repo={self.repository_location}",
            "create",
            "--timestamp",
            datetime(y, m, d, H, M, S, 0).strftime(ISO_FORMAT_NO_USECS),  # naive == local time / local tz
            name,
            src_dir,
        )

    # This test must match docs/misc/prune-example.txt
    def test_prune_repository_example(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        # Archives that will be kept, per the example
        # Oldest archive
        self._create_archive_ts("test01", 2015, 1, 1)
        # 6 monthly archives
        self._create_archive_ts("test02", 2015, 6, 30)
        self._create_archive_ts("test03", 2015, 7, 31)
        self._create_archive_ts("test04", 2015, 8, 31)
        self._create_archive_ts("test05", 2015, 9, 30)
        self._create_archive_ts("test06", 2015, 10, 31)
        self._create_archive_ts("test07", 2015, 11, 30)
        # 14 daily archives
        self._create_archive_ts("test08", 2015, 12, 17)
        self._create_archive_ts("test09", 2015, 12, 18)
        self._create_archive_ts("test10", 2015, 12, 20)
        self._create_archive_ts("test11", 2015, 12, 21)
        self._create_archive_ts("test12", 2015, 12, 22)
        self._create_archive_ts("test13", 2015, 12, 23)
        self._create_archive_ts("test14", 2015, 12, 24)
        self._create_archive_ts("test15", 2015, 12, 25)
        self._create_archive_ts("test16", 2015, 12, 26)
        self._create_archive_ts("test17", 2015, 12, 27)
        self._create_archive_ts("test18", 2015, 12, 28)
        self._create_archive_ts("test19", 2015, 12, 29)
        self._create_archive_ts("test20", 2015, 12, 30)
        self._create_archive_ts("test21", 2015, 12, 31)
        # Additional archives that would be pruned
        # The second backup of the year
        self._create_archive_ts("test22", 2015, 1, 2)
        # The next older monthly backup
        self._create_archive_ts("test23", 2015, 5, 31)
        # The next older daily backup
        self._create_archive_ts("test24", 2015, 12, 16)
        output = self.cmd(
            f"--repo={self.repository_location}",
            "prune",
            "--list",
            "--dry-run",
            "--keep-daily=14",
            "--keep-monthly=6",
            "--keep-yearly=1",
        )
        # Prune second backup of the year
        assert re.search(r"Would prune:\s+test22", output)
        # Prune next older monthly and daily backups
        assert re.search(r"Would prune:\s+test23", output)
        assert re.search(r"Would prune:\s+test24", output)
        # Must keep the other 21 backups
        # Yearly is kept as oldest archive
        assert re.search(r"Keeping archive \(rule: yearly\[oldest\] #1\):\s+test01", output)
        for i in range(1, 7):
            assert re.search(r"Keeping archive \(rule: monthly #" + str(i) + r"\):\s+test" + ("%02d" % (8 - i)), output)
        for i in range(1, 15):
            assert re.search(r"Keeping archive \(rule: daily #" + str(i) + r"\):\s+test" + ("%02d" % (22 - i)), output)
        output = self.cmd(f"--repo={self.repository_location}", "rlist")
        # Nothing pruned after dry run
        for i in range(1, 25):
            self.assert_in("test%02d" % i, output)
        self.cmd(
            f"--repo={self.repository_location}", "prune", "--keep-daily=14", "--keep-monthly=6", "--keep-yearly=1"
        )
        output = self.cmd(f"--repo={self.repository_location}", "rlist")
        # All matching backups plus oldest kept
        for i in range(1, 22):
            self.assert_in("test%02d" % i, output)
        # Other backups have been pruned
        for i in range(22, 25):
            self.assert_not_in("test%02d" % i, output)

    # With an initial and daily backup, prune daily until oldest is replaced by a monthly backup
    def test_prune_retain_and_expire_oldest(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        # Initial backup
        self._create_archive_ts("original_archive", 2020, 9, 1, 11, 15)
        # Archive and prune daily for 30 days
        for i in range(1, 31):
            self._create_archive_ts("september%02d" % i, 2020, 9, i, 12)
            self.cmd(f"--repo={self.repository_location}", "prune", "--keep-daily=7", "--keep-monthly=1")
        # Archive and prune 6 days into the next month
        for i in range(1, 7):
            self._create_archive_ts("october%02d" % i, 2020, 10, i, 12)
            self.cmd(f"--repo={self.repository_location}", "prune", "--keep-daily=7", "--keep-monthly=1")
        # Oldest backup is still retained
        output = self.cmd(
            f"--repo={self.repository_location}", "prune", "--list", "--dry-run", "--keep-daily=7", "--keep-monthly=1"
        )
        assert re.search(r"Keeping archive \(rule: monthly\[oldest\] #1" + r"\):\s+original_archive", output)
        # Archive one more day and prune.
        self._create_archive_ts("october07", 2020, 10, 7, 12)
        self.cmd(f"--repo={self.repository_location}", "prune", "--keep-daily=7", "--keep-monthly=1")
        # Last day of previous month is retained as monthly, and oldest is expired.
        output = self.cmd(
            f"--repo={self.repository_location}", "prune", "--list", "--dry-run", "--keep-daily=7", "--keep-monthly=1"
        )
        assert re.search(r"Keeping archive \(rule: monthly #1\):\s+september30", output)
        self.assert_not_in("original_archive", output)

    def test_prune_repository_save_space(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "test1", src_dir)
        self.cmd(f"--repo={self.repository_location}", "create", "test2", src_dir)
        output = self.cmd(f"--repo={self.repository_location}", "prune", "--list", "--dry-run", "--keep-daily=1")
        assert re.search(r"Keeping archive \(rule: daily #1\):\s+test2", output)
        assert re.search(r"Would prune:\s+test1", output)
        output = self.cmd(f"--repo={self.repository_location}", "rlist")
        self.assert_in("test1", output)
        self.assert_in("test2", output)
        self.cmd(f"--repo={self.repository_location}", "prune", "--save-space", "--keep-daily=1")
        output = self.cmd(f"--repo={self.repository_location}", "rlist")
        self.assert_not_in("test1", output)
        self.assert_in("test2", output)

    def test_prune_repository_prefix(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "foo-2015-08-12-10:00", src_dir)
        self.cmd(f"--repo={self.repository_location}", "create", "foo-2015-08-12-20:00", src_dir)
        self.cmd(f"--repo={self.repository_location}", "create", "bar-2015-08-12-10:00", src_dir)
        self.cmd(f"--repo={self.repository_location}", "create", "bar-2015-08-12-20:00", src_dir)
        output = self.cmd(
            f"--repo={self.repository_location}",
            "prune",
            "--list",
            "--dry-run",
            "--keep-daily=1",
            "--match-archives=sh:foo-*",
        )
        assert re.search(r"Keeping archive \(rule: daily #1\):\s+foo-2015-08-12-20:00", output)
        assert re.search(r"Would prune:\s+foo-2015-08-12-10:00", output)
        output = self.cmd(f"--repo={self.repository_location}", "rlist")
        self.assert_in("foo-2015-08-12-10:00", output)
        self.assert_in("foo-2015-08-12-20:00", output)
        self.assert_in("bar-2015-08-12-10:00", output)
        self.assert_in("bar-2015-08-12-20:00", output)
        self.cmd(f"--repo={self.repository_location}", "prune", "--keep-daily=1", "--match-archives=sh:foo-*")
        output = self.cmd(f"--repo={self.repository_location}", "rlist")
        self.assert_not_in("foo-2015-08-12-10:00", output)
        self.assert_in("foo-2015-08-12-20:00", output)
        self.assert_in("bar-2015-08-12-10:00", output)
        self.assert_in("bar-2015-08-12-20:00", output)

    def test_prune_repository_glob(self):
        self.cmd(f"--repo={self.repository_location}", "rcreate", RK_ENCRYPTION)
        self.cmd(f"--repo={self.repository_location}", "create", "2015-08-12-10:00-foo", src_dir)
        self.cmd(f"--repo={self.repository_location}", "create", "2015-08-12-20:00-foo", src_dir)
        self.cmd(f"--repo={self.repository_location}", "create", "2015-08-12-10:00-bar", src_dir)
        self.cmd(f"--repo={self.repository_location}", "create", "2015-08-12-20:00-bar", src_dir)
        output = self.cmd(
            f"--repo={self.repository_location}",
            "prune",
            "--list",
            "--dry-run",
            "--keep-daily=1",
            "--match-archives=sh:2015-*-foo",
        )
        assert re.search(r"Keeping archive \(rule: daily #1\):\s+2015-08-12-20:00-foo", output)
        assert re.search(r"Would prune:\s+2015-08-12-10:00-foo", output)
        output = self.cmd(f"--repo={self.repository_location}", "rlist")
        self.assert_in("2015-08-12-10:00-foo", output)
        self.assert_in("2015-08-12-20:00-foo", output)
        self.assert_in("2015-08-12-10:00-bar", output)
        self.assert_in("2015-08-12-20:00-bar", output)
        self.cmd(f"--repo={self.repository_location}", "prune", "--keep-daily=1", "--match-archives=sh:2015-*-foo")
        output = self.cmd(f"--repo={self.repository_location}", "rlist")
        self.assert_not_in("2015-08-12-10:00-foo", output)
        self.assert_in("2015-08-12-20:00-foo", output)
        self.assert_in("2015-08-12-10:00-bar", output)
        self.assert_in("2015-08-12-20:00-bar", output)


class RemoteArchiverTestCase(RemoteArchiverTestCaseBase, ArchiverTestCase):
    """run the same tests, but with a remote repository"""


@unittest.skipUnless("binary" in BORG_EXES, "no borg.exe available")
class ArchiverTestCaseBinary(ArchiverTestCaseBinaryBase, ArchiverTestCase):
    """runs the same tests, but via the borg binary"""

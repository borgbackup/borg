import re
from datetime import datetime

from ...constants import *  # NOQA
from . import cmd, RK_ENCRYPTION, src_dir, generate_archiver_tests

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def _create_archive_ts(archiver, name, y, m, d, H=0, M=0, S=0):
    cmd(
        archiver,
        "create",
        "--timestamp",
        datetime(y, m, d, H, M, S, 0).strftime(ISO_FORMAT_NO_USECS),  # naive == local time / local tz
        name,
        src_dir,
    )


def test_prune_repository(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    cmd(archiver, "create", "test1", src_dir)
    cmd(archiver, "create", "test2", src_dir)
    # these are not really a checkpoints, but they look like some:
    cmd(archiver, "create", "test3.checkpoint", src_dir)
    cmd(archiver, "create", "test3.checkpoint.1", src_dir)
    cmd(archiver, "create", "test4.checkpoint", src_dir)
    output = cmd(archiver, "prune", "--list", "--dry-run", "--keep-daily=1")
    assert re.search(r"Would prune:\s+test1", output)
    # must keep the latest non-checkpoint archive:
    assert re.search(r"Keeping archive \(rule: daily #1\):\s+test2", output)
    # must keep the latest checkpoint archive:
    assert re.search(r"Keeping checkpoint archive:\s+test4.checkpoint", output)
    output = cmd(archiver, "rlist", "--consider-checkpoints")
    assert "test1" in output
    assert "test2" in output
    assert "test3.checkpoint" in output
    assert "test3.checkpoint.1" in output
    assert "test4.checkpoint" in output
    cmd(archiver, "prune", "--keep-daily=1")
    output = cmd(archiver, "rlist", "--consider-checkpoints")
    assert "test1" not in output
    # the latest non-checkpoint archive must be still there:
    assert "test2" in output
    # only the latest checkpoint archive must still be there:
    assert "test3.checkpoint" not in output
    assert "test3.checkpoint.1" not in output
    assert "test4.checkpoint" in output
    # now we supersede the latest checkpoint by a successful backup:
    cmd(archiver, "create", "test5", src_dir)
    cmd(archiver, "prune", "--keep-daily=2")
    output = cmd(archiver, "rlist", "--consider-checkpoints")
    # all checkpoints should be gone now:
    assert "checkpoint" not in output
    # the latest archive must be still there
    assert "test5" in output


# This test must match docs/misc/prune-example.txt
def test_prune_repository_example(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    # Archives that will be kept, per the example
    # Oldest archive
    _create_archive_ts(archiver, "test01", 2015, 1, 1)
    # 6 monthly archives
    _create_archive_ts(archiver, "test02", 2015, 6, 30)
    _create_archive_ts(archiver, "test03", 2015, 7, 31)
    _create_archive_ts(archiver, "test04", 2015, 8, 31)
    _create_archive_ts(archiver, "test05", 2015, 9, 30)
    _create_archive_ts(archiver, "test06", 2015, 10, 31)
    _create_archive_ts(archiver, "test07", 2015, 11, 30)
    # 14 daily archives
    _create_archive_ts(archiver, "test08", 2015, 12, 17)
    _create_archive_ts(archiver, "test09", 2015, 12, 18)
    _create_archive_ts(archiver, "test10", 2015, 12, 20)
    _create_archive_ts(archiver, "test11", 2015, 12, 21)
    _create_archive_ts(archiver, "test12", 2015, 12, 22)
    _create_archive_ts(archiver, "test13", 2015, 12, 23)
    _create_archive_ts(archiver, "test14", 2015, 12, 24)
    _create_archive_ts(archiver, "test15", 2015, 12, 25)
    _create_archive_ts(archiver, "test16", 2015, 12, 26)
    _create_archive_ts(archiver, "test17", 2015, 12, 27)
    _create_archive_ts(archiver, "test18", 2015, 12, 28)
    _create_archive_ts(archiver, "test19", 2015, 12, 29)
    _create_archive_ts(archiver, "test20", 2015, 12, 30)
    _create_archive_ts(archiver, "test21", 2015, 12, 31)
    # Additional archives that would be pruned
    # The second backup of the year
    _create_archive_ts(archiver, "test22", 2015, 1, 2)
    # The next older monthly backup
    _create_archive_ts(archiver, "test23", 2015, 5, 31)
    # The next older daily backup
    _create_archive_ts(archiver, "test24", 2015, 12, 16)
    output = cmd(archiver, "prune", "--list", "--dry-run", "--keep-daily=14", "--keep-monthly=6", "--keep-yearly=1")
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
    output = cmd(archiver, "rlist")
    # Nothing pruned after dry run
    for i in range(1, 25):
        assert "test%02d" % i in output
    cmd(archiver, "prune", "--keep-daily=14", "--keep-monthly=6", "--keep-yearly=1")
    output = cmd(archiver, "rlist")
    # All matching backups plus oldest kept
    for i in range(1, 22):
        assert "test%02d" % i in output
    # Other backups have been pruned
    for i in range(22, 25):
        assert "test%02d" % i not in output


# With an initial and daily backup, prune daily until oldest is replaced by a monthly backup
def test_prune_retain_and_expire_oldest(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    # Initial backup
    _create_archive_ts(archiver, "original_archive", 2020, 9, 1, 11, 15)
    # Archive and prune daily for 30 days
    for i in range(1, 31):
        _create_archive_ts(archiver, "september%02d" % i, 2020, 9, i, 12)
        cmd(archiver, "prune", "--keep-daily=7", "--keep-monthly=1")
    # Archive and prune 6 days into the next month
    for i in range(1, 7):
        _create_archive_ts(archiver, "october%02d" % i, 2020, 10, i, 12)
        cmd(archiver, "prune", "--keep-daily=7", "--keep-monthly=1")
    # Oldest backup is still retained
    output = cmd(archiver, "prune", "--list", "--dry-run", "--keep-daily=7", "--keep-monthly=1")
    assert re.search(r"Keeping archive \(rule: monthly\[oldest\] #1" + r"\):\s+original_archive", output)
    # Archive one more day and prune.
    _create_archive_ts(archiver, "october07", 2020, 10, 7, 12)
    cmd(archiver, "prune", "--keep-daily=7", "--keep-monthly=1")
    # Last day of previous month is retained as monthly, and oldest is expired.
    output = cmd(archiver, "prune", "--list", "--dry-run", "--keep-daily=7", "--keep-monthly=1")
    assert re.search(r"Keeping archive \(rule: monthly #1\):\s+september30", output)
    assert "original_archive" not in output


def test_prune_repository_prefix(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    cmd(archiver, "create", "foo-2015-08-12-10:00", src_dir)
    cmd(archiver, "create", "foo-2015-08-12-20:00", src_dir)
    cmd(archiver, "create", "bar-2015-08-12-10:00", src_dir)
    cmd(archiver, "create", "bar-2015-08-12-20:00", src_dir)
    output = cmd(archiver, "prune", "--list", "--dry-run", "--keep-daily=1", "--match-archives=sh:foo-*")
    assert re.search(r"Keeping archive \(rule: daily #1\):\s+foo-2015-08-12-20:00", output)
    assert re.search(r"Would prune:\s+foo-2015-08-12-10:00", output)
    output = cmd(archiver, "rlist")
    assert "foo-2015-08-12-10:00" in output
    assert "foo-2015-08-12-20:00" in output
    assert "bar-2015-08-12-10:00" in output
    assert "bar-2015-08-12-20:00" in output
    cmd(archiver, "prune", "--keep-daily=1", "--match-archives=sh:foo-*")
    output = cmd(archiver, "rlist")
    assert "foo-2015-08-12-10:00" not in output
    assert "foo-2015-08-12-20:00" in output
    assert "bar-2015-08-12-10:00" in output
    assert "bar-2015-08-12-20:00" in output


def test_prune_repository_glob(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "rcreate", RK_ENCRYPTION)
    cmd(archiver, "create", "2015-08-12-10:00-foo", src_dir)
    cmd(archiver, "create", "2015-08-12-20:00-foo", src_dir)
    cmd(archiver, "create", "2015-08-12-10:00-bar", src_dir)
    cmd(archiver, "create", "2015-08-12-20:00-bar", src_dir)
    output = cmd(archiver, "prune", "--list", "--dry-run", "--keep-daily=1", "--match-archives=sh:2015-*-foo")
    assert re.search(r"Keeping archive \(rule: daily #1\):\s+2015-08-12-20:00-foo", output)
    assert re.search(r"Would prune:\s+2015-08-12-10:00-foo", output)
    output = cmd(archiver, "rlist")
    assert "2015-08-12-10:00-foo" in output
    assert "2015-08-12-20:00-foo" in output
    assert "2015-08-12-10:00-bar" in output
    assert "2015-08-12-20:00-bar" in output
    cmd(archiver, "prune", "--keep-daily=1", "--match-archives=sh:2015-*-foo")
    output = cmd(archiver, "rlist")
    assert "2015-08-12-10:00-foo" not in output
    assert "2015-08-12-20:00-foo" in output
    assert "2015-08-12-10:00-bar" in output
    assert "2015-08-12-20:00-bar" in output

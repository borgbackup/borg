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
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test1", src_dir)
    cmd(archiver, "create", "test2", src_dir)
    output = cmd(archiver, "prune", "--list", "--dry-run", "--keep-daily=1")
    assert re.search(r"Would prune:\s+test1", output)
    # must keep the latest archive:
    assert re.search(r"Keeping archive \(rule: daily #1\):\s+test2", output)
    output = cmd(archiver, "repo-list")
    assert "test1" in output
    assert "test2" in output
    cmd(archiver, "prune", "--keep-daily=1")
    output = cmd(archiver, "repo-list")
    assert "test1" not in output
    # the latest archive must be still there:
    assert "test2" in output


# This test must match docs/misc/prune-example.txt
def test_prune_repository_example(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
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
    output = cmd(archiver, "repo-list")
    # Nothing pruned after dry run
    for i in range(1, 25):
        assert "test%02d" % i in output
    cmd(archiver, "prune", "--keep-daily=14", "--keep-monthly=6", "--keep-yearly=1")
    output = cmd(archiver, "repo-list")
    # All matching backups plus oldest kept
    for i in range(1, 22):
        assert "test%02d" % i in output
    # Other backups have been pruned
    for i in range(22, 25):
        assert "test%02d" % i not in output


def test_prune_quarterly(archivers, request):
    # Example worked through by hand when developing quarterly
    # strategy, based upon existing backups where quarterly strategy
    # is desired. Weekly/monthly backups that don't affect results were
    # trimmed to speed up the test.
    #
    # Week number is shown in comment for every row in the below list.
    # Year is also shown when it doesn't match the year given in the
    # date tuple.
    archiver = request.getfixturevalue(archivers)
    test_dates = [
        (2020, 12, 6),
        (2021, 1, 3),  # 49, 2020-53
        (2021, 3, 28),
        (2021, 4, 25),  # 12, 16
        (2021, 6, 27),
        (2021, 7, 4),  # 25, 26
        (2021, 9, 26),
        (2021, 10, 3),  # 38, 39
        (2021, 12, 26),
        (2022, 1, 2),  # 51, 2021-52
    ]

    def mk_name(tup):
        (y, m, d) = tup
        suff = datetime(y, m, d).strftime("%Y-%m-%d")
        return f"test-{suff}"

    # The kept repos are based on working on an example by hand,
    # archives made on the following dates should be kept:
    EXPECTED_KEPT = {
        "13weekly": [(2020, 12, 6), (2021, 1, 3), (2021, 3, 28), (2021, 7, 4), (2021, 10, 3), (2022, 1, 2)],
        "3monthly": [(2020, 12, 6), (2021, 3, 28), (2021, 6, 27), (2021, 9, 26), (2021, 12, 26), (2022, 1, 2)],
    }

    for strat, to_keep in EXPECTED_KEPT.items():
        # Initialize our repo.
        cmd(archiver, "repo-create", RK_ENCRYPTION)
        for a, (y, m, d) in zip(map(mk_name, test_dates), test_dates):
            _create_archive_ts(archiver, a, y, m, d)

        to_prune = list(set(test_dates) - set(to_keep))

        # Use 99 instead of -1 to test that oldest backup is kept.
        output = cmd(archiver, "prune", "--list", "--dry-run", f"--keep-{strat}=99")
        for a in map(mk_name, to_prune):
            assert re.search(rf"Would prune:\s+{a}", output)

        oldest = r"\[oldest\]" if strat in ("13weekly") else ""
        assert re.search(rf"Keeping archive \(rule: quarterly_{strat}{oldest} #\d+\):\s+test-2020-12-06", output)
        for a in map(mk_name, to_keep[1:]):
            assert re.search(rf"Keeping archive \(rule: quarterly_{strat} #\d+\):\s+{a}", output)

        output = cmd(archiver, "repo-list")
        # Nothing pruned after dry run
        for a in map(mk_name, test_dates):
            assert a in output

        cmd(archiver, "prune", f"--keep-{strat}=99")
        output = cmd(archiver, "repo-list")
        # All matching backups plus oldest kept
        for a in map(mk_name, to_keep):
            assert a in output
        # Other backups have been pruned
        for a in map(mk_name, to_prune):
            assert a not in output

        # Delete repo and begin anew
        cmd(archiver, "repo-delete")


# With an initial and daily backup, prune daily until oldest is replaced by a monthly backup
def test_prune_retain_and_expire_oldest(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
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
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "foo-2015-08-12-10:00", src_dir)
    cmd(archiver, "create", "foo-2015-08-12-20:00", src_dir)
    cmd(archiver, "create", "bar-2015-08-12-10:00", src_dir)
    cmd(archiver, "create", "bar-2015-08-12-20:00", src_dir)
    output = cmd(archiver, "prune", "--list", "--dry-run", "--keep-daily=1", "--match-archives=sh:foo-*")
    assert re.search(r"Keeping archive \(rule: daily #1\):\s+foo-2015-08-12-20:00", output)
    assert re.search(r"Would prune:\s+foo-2015-08-12-10:00", output)
    output = cmd(archiver, "repo-list")
    assert "foo-2015-08-12-10:00" in output
    assert "foo-2015-08-12-20:00" in output
    assert "bar-2015-08-12-10:00" in output
    assert "bar-2015-08-12-20:00" in output
    cmd(archiver, "prune", "--keep-daily=1", "--match-archives=sh:foo-*")
    output = cmd(archiver, "repo-list")
    assert "foo-2015-08-12-10:00" not in output
    assert "foo-2015-08-12-20:00" in output
    assert "bar-2015-08-12-10:00" in output
    assert "bar-2015-08-12-20:00" in output


def test_prune_repository_glob(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "2015-08-12-10:00-foo", src_dir)
    cmd(archiver, "create", "2015-08-12-20:00-foo", src_dir)
    cmd(archiver, "create", "2015-08-12-10:00-bar", src_dir)
    cmd(archiver, "create", "2015-08-12-20:00-bar", src_dir)
    output = cmd(archiver, "prune", "--list", "--dry-run", "--keep-daily=1", "--match-archives=sh:2015-*-foo")
    assert re.search(r"Keeping archive \(rule: daily #1\):\s+2015-08-12-20:00-foo", output)
    assert re.search(r"Would prune:\s+2015-08-12-10:00-foo", output)
    output = cmd(archiver, "repo-list")
    assert "2015-08-12-10:00-foo" in output
    assert "2015-08-12-20:00-foo" in output
    assert "2015-08-12-10:00-bar" in output
    assert "2015-08-12-20:00-bar" in output
    cmd(archiver, "prune", "--keep-daily=1", "--match-archives=sh:2015-*-foo")
    output = cmd(archiver, "repo-list")
    assert "2015-08-12-10:00-foo" not in output
    assert "2015-08-12-20:00-foo" in output
    assert "2015-08-12-10:00-bar" in output
    assert "2015-08-12-20:00-bar" in output


def test_prune_ignore_protected(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "archive1", archiver.input_path)
    cmd(archiver, "tag", "--set=@PROT", "archive1")  # do not delete archive1!
    cmd(archiver, "create", "archive2", archiver.input_path)
    cmd(archiver, "create", "archive3", archiver.input_path)
    output = cmd(archiver, "prune", "--list", "--keep-last=1", "--match-archives=sh:archive*")
    assert "archive1" not in output  # @PROT archives are completely ignored.
    assert re.search(r"Keeping archive \(rule: secondly #1\):\s+archive3", output)
    assert re.search(r"Pruning archive \(.*?\):\s+archive2", output)
    output = cmd(archiver, "repo-list")
    assert "archive1" in output  # @PROT protected archive1 from deletion
    assert "archive3" in output  # last one

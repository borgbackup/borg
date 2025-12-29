import pytest
import re
from datetime import datetime, timezone
from freezegun import freeze_time

from ...constants import *  # NOQA
from ...archiver.prune_cmd import prune_split
from ...helpers import CommandError
from . import cmd, RK_ENCRYPTION, src_dir, generate_archiver_tests

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def _create_archive_dt(archiver, name, dt, tzinfo=None):
    cmd(archiver, "create", "--timestamp", dt.replace(tzinfo=tzinfo).strftime(ISO_FORMAT_ZONE), name, src_dir)


def _create_archive_ts(archiver, name, y, m, d, H=0, M=0, S=0, us=0, tzinfo=None):
    _create_archive_dt(archiver, name, datetime(y, m, d, H, M, S, us), tzinfo=tzinfo)


def test_prune_repository(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test1", src_dir)
    cmd(archiver, "create", "test2", src_dir)
    output = cmd(archiver, "prune", "--list", "--dry-run", "--keep-daily=1")
    assert re.search(r"Would prune:\s+test1", output)
    # Must keep the latest archive:
    assert re.search(r"Keeping archive \(rule: daily #1\):\s+test2", output)
    output = cmd(archiver, "repo-list")
    assert "test1" in output
    assert "test2" in output
    cmd(archiver, "prune", "--keep-daily=1")
    output = cmd(archiver, "repo-list")
    assert "test1" not in output
    # The latest archive must still be there:
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
    # Example worked through by hand when developing the quarterly
    # strategy, based on existing backups where the quarterly strategy
    # is desired. Weekly/monthly backups that do not affect results were
    # trimmed to speed up the test.
    #
    # The ISO week number is shown in a comment for each row in the list below.
    # The year is also shown when it does not match the year given in the
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
    assert re.search(r"Keeping archive \(rule: last #1\):\s+archive3", output)
    assert re.search(r"Pruning archive \(.*?\):\s+archive2", output)
    output = cmd(archiver, "repo-list")
    assert "archive1" in output  # @PROT protected archive1 from deletion
    assert "archive3" in output  # last one


class MockArchive:
    def __init__(self, ts, id):
        # Real archive objects have UTC zoned timestamps
        self.ts = ts.replace(tzinfo=timezone.utc)
        self.id = id

    def __repr__(self):
        return f"{self.id}: {self.ts.isoformat()}"


@pytest.mark.parametrize(
    "rule,num_to_keep,expected_ids",
    [
        ("yearly", 3, (13, 2, 1)),
        ("monthly", 3, (13, 8, 4)),
        ("weekly", 2, (13, 8)),
        ("daily", 3, (13, 8, 7)),
        ("hourly", 3, (13, 10, 8)),
        ("minutely", 3, (13, 10, 9)),
        ("secondly", 4, (13, 12, 11, 10)),
        ("daily", 0, []),
    ],
)
def test_prune_split(rule, num_to_keep, expected_ids):
    def subset(lst, ids):
        return {i for i in lst if i.id in ids}

    archives = [
        # years apart
        MockArchive(datetime(2015, 1, 1, 10, 0, 0), 1),
        MockArchive(datetime(2016, 1, 1, 10, 0, 0), 2),
        MockArchive(datetime(2017, 1, 1, 10, 0, 0), 3),
        # months apart
        MockArchive(datetime(2017, 2, 1, 10, 0, 0), 4),
        MockArchive(datetime(2017, 3, 1, 10, 0, 0), 5),
        # days apart
        MockArchive(datetime(2017, 3, 2, 10, 0, 0), 6),
        MockArchive(datetime(2017, 3, 3, 10, 0, 0), 7),
        MockArchive(datetime(2017, 3, 4, 10, 0, 0), 8),
        # minutes apart
        MockArchive(datetime(2017, 10, 1, 9, 45, 0), 9),
        MockArchive(datetime(2017, 10, 1, 9, 55, 0), 10),
        # seconds apart
        MockArchive(datetime(2017, 10, 1, 10, 0, 1), 11),
        MockArchive(datetime(2017, 10, 1, 10, 0, 3), 12),
        MockArchive(datetime(2017, 10, 1, 10, 0, 5), 13),
    ]
    kept_because = {}
    keep = prune_split(archives, rule, num_to_keep, None, kept_because)

    assert set(keep) == subset(archives, expected_ids)
    for item in keep:
        assert kept_because[item.id][0] == rule


def test_prune_split_keep_oldest():
    def subset(lst, ids):
        return {i for i in lst if i.id in ids}

    archives = [
        # oldest backup, but not last in its year
        MockArchive(datetime(2018, 1, 1, 10, 0, 0), 1),
        # an interim backup
        MockArchive(datetime(2018, 12, 30, 10, 0, 0), 2),
        # year-end backups
        MockArchive(datetime(2018, 12, 31, 10, 0, 0), 3),
        MockArchive(datetime(2019, 12, 31, 10, 0, 0), 4),
    ]

    # Keep oldest when retention target can't otherwise be met
    kept_because = {}
    keep = prune_split(archives, "yearly", 3, None, kept_because)

    assert set(keep) == subset(archives, [1, 3, 4])
    assert kept_because[1][0] == "yearly[oldest]"
    assert kept_because[3][0] == "yearly"
    assert kept_because[4][0] == "yearly"

    # Otherwise, prune it
    kept_because = {}
    keep = prune_split(archives, "yearly", 2, None, kept_because)

    assert set(keep) == subset(archives, [3, 4])
    assert kept_because[3][0] == "yearly"
    assert kept_because[4][0] == "yearly"


def test_prune_split_no_archives():
    archives = []

    kept_because = {}
    keep = prune_split(archives, "yearly", 3, None, kept_because)

    assert keep == []
    assert kept_because == {}


def test_prune_keep_last_same_second(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test1", src_dir)
    cmd(archiver, "create", "test2", src_dir)
    output = cmd(archiver, "prune", "--list", "--dry-run", "--keep-last=2")
    # Both archives are kept even though they have the same timestamp to the second. Would previously have failed with
    # old behavior of --keep-last. Archives sorted on seconds, order is undefined.
    assert re.search(r"Keeping archive \(rule: last #\d\):\s+test1", output)
    assert re.search(r"Keeping archive \(rule: last #\d\):\s+test2", output)


@freeze_time(datetime(2023, 12, 31, 23, 59, 59, tzinfo=None))  # Non-leap year ending on a Sunday
def test_prune_keep_int_or_flexibledelta(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    _create_archive_ts(archiver, "test-1", 2023, 12, 31, 23, 59, 59)
    _create_archive_ts(archiver, "test-2", 2023, 12, 31, 23, 59, 59)
    _create_archive_ts(archiver, "test-3", 2023, 12, 31, 23, 59, 58)
    for keep_arg in ["--keep=2", "--keep=1S"]:
        output = cmd(archiver, "prune", "--list", "--dry-run", keep_arg)
        assert re.search(r"Keeping archive \(rule: keep #\d\):\s+test-1", output)
        assert re.search(r"Keeping archive \(rule: keep #\d\):\s+test-2", output)
        assert re.search(r"Would prune:\s+test-3", output)


@freeze_time(datetime(2023, 12, 31, 23, 59, 59, tzinfo=None))
def test_prune_keep_int_or_flexibledelta_zero(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    _create_archive_ts(archiver, "test", 2023, 12, 31, 23, 59, 59)
    for keep_arg in ["--keep=0", "--keep=0S"]:
        output = cmd(archiver, "prune", "--list", "--dry-run", keep_arg)
        assert re.search(r"Would prune:\s+test", output)


@freeze_time(datetime(2023, 12, 31, 23, 59, 59, tzinfo=None))
def test_prune_keep_secondly_int_or_flexibledelta(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    _create_archive_ts(archiver, "test-1", 2023, 12, 31, 23, 59, 58)
    _create_archive_ts(archiver, "test-2", 2023, 12, 31, 23, 59, 57, 1)
    _create_archive_ts(archiver, "test-3", 2023, 12, 31, 23, 59, 57)
    _create_archive_ts(archiver, "test-4", 2023, 12, 31, 23, 59, 56, 999999)
    for keep_arg in ["--keep-secondly=2", "--keep-secondly=2S"]:
        output = cmd(archiver, "prune", "--list", "--dry-run", keep_arg).splitlines()
        assert re.search(r"Keeping archive \(rule: secondly #1\):\s+test-1", output.pop(0))
        assert re.search(r"Keeping archive \(rule: secondly #2\):\s+test-2", output.pop(0))
        assert re.search(r"Would prune:\s+test-3", output.pop(0))
        assert re.search(r"Would prune:\s+test-4", output.pop(0))


@freeze_time(datetime(2023, 12, 31, 23, 59, 0, tzinfo=None))
def test_prune_keep_minutely_int_or_flexibledelta(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    _create_archive_ts(archiver, "test-1", 2023, 12, 31, 23, 58)
    _create_archive_ts(archiver, "test-2", 2023, 12, 31, 23, 57, 1)
    _create_archive_ts(archiver, "test-3", 2023, 12, 31, 23, 57)
    _create_archive_ts(archiver, "test-4", 2023, 12, 31, 23, 56, 0, 1)  # Last possible microsecond
    _create_archive_ts(archiver, "test-5", 2023, 12, 31, 23, 56)
    for keep_arg in ["--keep-minutely=3", "--keep-minutely=3M"]:
        output = cmd(archiver, "prune", "--list", "--dry-run", keep_arg).splitlines()
        assert re.search(r"Keeping archive \(rule: minutely #1\):\s+test-1", output.pop(0))
        assert re.search(r"Keeping archive \(rule: minutely #2\):\s+test-2", output.pop(0))
        assert re.search(r"Would prune:\s+test-3", output.pop(0))
        assert re.search(r"Keeping archive \(rule: minutely #3\):\s+test-4", output.pop(0))
        assert re.search(r"Would prune:\s+test-5", output.pop(0))


@freeze_time(datetime(2023, 12, 31, 23, 0, 0, tzinfo=None))
def test_prune_keep_hourly_int_or_flexibledelta(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    _create_archive_ts(archiver, "test-1", 2023, 12, 31, 22)
    _create_archive_ts(archiver, "test-2", 2023, 12, 31, 21, us=1)
    _create_archive_ts(archiver, "test-3", 2023, 12, 31, 21)
    _create_archive_ts(archiver, "test-4", 2023, 12, 31, 20, us=1)  # Last possible microsecond
    _create_archive_ts(archiver, "test-5", 2023, 12, 31, 20)
    for keep_arg in ["--keep-hourly=3", "--keep-hourly=3H"]:
        output = cmd(archiver, "prune", "--list", "--dry-run", keep_arg).splitlines()
        assert re.search(r"Keeping archive \(rule: hourly #1\):\s+test-1", output.pop(0))
        assert re.search(r"Keeping archive \(rule: hourly #2\):\s+test-2", output.pop(0))
        assert re.search(r"Would prune:\s+test-3", output.pop(0))
        assert re.search(r"Keeping archive \(rule: hourly #3\):\s+test-4", output.pop(0))
        assert re.search(r"Would prune:\s+test-5", output.pop(0))


@freeze_time(datetime(2023, 12, 31, 12, 0, 0, tzinfo=None))
def test_prune_keep_daily_int_or_flexibledelta(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    _create_archive_ts(archiver, "test-1", 2023, 12, 30)
    _create_archive_ts(archiver, "test-2", 2023, 12, 29, S=1)
    _create_archive_ts(archiver, "test-3", 2023, 12, 29)
    _create_archive_ts(archiver, "test-4", 2023, 12, 28, 12, us=1)  # Last possible microsecond
    _create_archive_ts(archiver, "test-5", 2023, 12, 28, 12)
    for keep_arg in ["--keep-daily=3", "--keep-daily=3d"]:
        output = cmd(archiver, "prune", "--list", "--dry-run", keep_arg).splitlines()
        assert re.search(r"Keeping archive \(rule: daily #1\):\s+test-1", output.pop(0))
        assert re.search(r"Keeping archive \(rule: daily #2\):\s+test-2", output.pop(0))
        assert re.search(r"Would prune:\s+test-3", output.pop(0))
        assert re.search(r"Keeping archive \(rule: daily #3\):\s+test-4", output.pop(0))
        assert re.search(r"Would prune:\s+test-5", output.pop(0))


@freeze_time(datetime(2023, 12, 31, 0, 0, 0, tzinfo=None))
def test_prune_keep_weekly_int_or_flexibledelta(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    _create_archive_ts(archiver, "test-1", 2023, 12, 24)
    _create_archive_ts(archiver, "test-2", 2023, 12, 17, us=1)
    _create_archive_ts(archiver, "test-3", 2023, 12, 17)
    _create_archive_ts(archiver, "test-4", 2023, 12, 10, us=1)  # Last possible microsecond
    _create_archive_ts(archiver, "test-5", 2023, 12, 10)
    for keep_arg in ["--keep-weekly=3", "--keep-weekly=3w"]:
        output = cmd(archiver, "prune", "--list", "--dry-run", keep_arg).splitlines()
        assert re.search(r"Keeping archive \(rule: weekly #1\):\s+test-1", output.pop(0))
        assert re.search(r"Keeping archive \(rule: weekly #2\):\s+test-2", output.pop(0))
        assert re.search(r"Would prune:\s+test-3", output.pop(0))
        assert re.search(r"Keeping archive \(rule: weekly #3\):\s+test-4", output.pop(0))
        assert re.search(r"Would prune:\s+test-5", output.pop(0))


@freeze_time(datetime(2023, 12, 31, 0, 0, 0, tzinfo=None))
def test_prune_keep_monthly_int_or_flexibledelta(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    _create_archive_ts(archiver, "test-1", 2023, 11, 30)
    _create_archive_ts(archiver, "test-2", 2023, 10, 30, us=1)
    _create_archive_ts(archiver, "test-3", 2023, 10, 30)
    _create_archive_ts(archiver, "test-4", 2023, 9, 30, us=1)  # Last possible microsecond
    _create_archive_ts(archiver, "test-5", 2023, 9, 30)
    for keep_arg in ["--keep-monthly=3", "--keep-monthly=3m"]:
        output = cmd(archiver, "prune", "--list", "--dry-run", keep_arg).splitlines()
        assert re.search(r"Keeping archive \(rule: monthly #1\):\s+test-1", output.pop(0))
        assert re.search(r"Keeping archive \(rule: monthly #2\):\s+test-2", output.pop(0))
        assert re.search(r"Would prune:\s+test-3", output.pop(0))
        assert re.search(r"Keeping archive \(rule: monthly #3\):\s+test-4", output.pop(0))
        assert re.search(r"Would prune:\s+test-5", output.pop(0))


# 2023-12-31 is Sunday, week 52. Makes these week calculations a little easier.
@freeze_time(datetime(2023, 12, 31, 0, 0, 0, tzinfo=None))
def test_prune_keep_13weekly_int_or_flexibledelta(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    _create_archive_ts(archiver, "test-1", 2023, 10, 1)
    _create_archive_ts(archiver, "test-2", 2023, 7, 2, us=1)
    _create_archive_ts(archiver, "test-3", 2023, 7, 2)
    _create_archive_ts(archiver, "test-4", 2023, 4, 2, us=1)  # Last possible microsecond
    _create_archive_ts(archiver, "test-5", 2023, 4, 2)
    for keep_arg in ["--keep-13weekly=3", "--keep-13weekly=39w"]:
        output = cmd(archiver, "prune", "--list", "--dry-run", keep_arg).splitlines()
        assert re.search(r"Keeping archive \(rule: quarterly_13weekly #1\):\s+test-1", output.pop(0))
        assert re.search(r"Keeping archive \(rule: quarterly_13weekly #2\):\s+test-2", output.pop(0))
        assert re.search(r"Would prune:\s+test-3", output.pop(0))
        assert re.search(r"Keeping archive \(rule: quarterly_13weekly #3\):\s+test-4", output.pop(0))
        assert re.search(r"Would prune:\s+test-5", output.pop(0))


@freeze_time(datetime(2023, 12, 31, 0, 0, 0, tzinfo=None))
def test_prune_keep_3monthly_int_or_flexibledelta(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    _create_archive_ts(archiver, "test-1", 2023, 9, 30)  # 31st December - 3 calendar months
    _create_archive_ts(archiver, "test-2", 2023, 6, 30, us=1)
    _create_archive_ts(archiver, "test-3", 2023, 6, 30)
    _create_archive_ts(archiver, "test-4", 2023, 3, 31, us=1)  # Last possible microsecond
    _create_archive_ts(archiver, "test-5", 2023, 3, 31)
    for keep_arg in ["--keep-3monthly=3", f"--keep-3monthly={(datetime.now()-datetime(2023, 3, 31)).days}d"]:
        output = cmd(archiver, "prune", "--list", "--dry-run", keep_arg).splitlines()
        assert re.search(r"Keeping archive \(rule: quarterly_3monthly #1\):\s+test-1", output.pop(0))
        assert re.search(r"Keeping archive \(rule: quarterly_3monthly #2\):\s+test-2", output.pop(0))
        assert re.search(r"Would prune:\s+test-3", output.pop(0))
        assert re.search(r"Keeping archive \(rule: quarterly_3monthly #3\):\s+test-4", output.pop(0))
        assert re.search(r"Would prune:\s+test-5", output.pop(0))


@freeze_time(datetime(2023, 12, 31, 0, 0, 0, tzinfo=None))
def test_prune_keep_yearly_int_or_flexibledelta(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    _create_archive_ts(archiver, "test-1", 2022, 12, 31)
    _create_archive_ts(archiver, "test-2", 2021, 12, 31, us=1)
    _create_archive_ts(archiver, "test-3", 2021, 12, 31)
    _create_archive_ts(archiver, "test-4", 2020, 12, 31, us=1)  # Last possible microsecond
    _create_archive_ts(archiver, "test-5", 2020, 12, 31)
    for keep_arg in ["--keep-yearly=3", "--keep-yearly=3y"]:
        output = cmd(archiver, "prune", "--list", "--dry-run", keep_arg).splitlines()
        assert re.search(r"Keeping archive \(rule: yearly #1\):\s+test-1", output.pop(0))
        assert re.search(r"Keeping archive \(rule: yearly #2\):\s+test-2", output.pop(0))
        assert re.search(r"Would prune:\s+test-3", output.pop(0))
        assert re.search(r"Keeping archive \(rule: yearly #3\):\s+test-4", output.pop(0))
        assert re.search(r"Would prune:\s+test-5", output.pop(0))


@freeze_time(datetime(2025, 12, 24, 12, 0, 0, tzinfo=None))
def test_prune_fuzzy_days(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    _create_archive_ts(archiver, "test-1", 2025, 12, 23, 12, us=1)
    _create_archive_ts(archiver, "test-2", 2025, 12, 23, 10)
    output_nonfuzzy = cmd(archiver, "prune", "--list", "--dry-run", "--keep=1d").splitlines()
    assert re.search(r"Keeping archive \(rule: keep #1\):\s+test-1", output_nonfuzzy.pop(0))
    assert re.search(r"Would prune:\s+test-2", output_nonfuzzy.pop(0))
    output_fuzzy = cmd(archiver, "prune", "--list", "--dry-run", "--keep=1dz").splitlines()
    assert re.search(r"Keeping archive \(rule: keep #1\):\s+test-1", output_fuzzy.pop(0))


@freeze_time(datetime(2025, 12, 24, 12, 0, 0, tzinfo=None))  # A Wednesday
def test_prune_fuzzy_weeks(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    _create_archive_ts(archiver, "test-1", 2025, 12, 17, 12, us=1)  # The previous Wednesday
    _create_archive_ts(archiver, "test-2", 2025, 12, 15, 10)  # Monday, start of previous week
    output_nonfuzzy = cmd(archiver, "prune", "--list", "--dry-run", "--keep=1w").splitlines()
    assert re.search(r"Keeping archive \(rule: keep #1\):\s+test-1", output_nonfuzzy.pop(0))
    assert re.search(r"Would prune:\s+test-2", output_nonfuzzy.pop(0))
    output_fuzzy = cmd(archiver, "prune", "--list", "--dry-run", "--keep=1wz").splitlines()
    assert re.search(r"Keeping archive \(rule: keep #1\):\s+test-1", output_fuzzy.pop(0))
    assert re.search(r"Keeping archive \(rule: keep #2\):\s+test-2", output_fuzzy.pop(0))


@freeze_time(datetime(2025, 12, 29, 12, 0, 0, tzinfo=None))  # Wednesday, end of year
def test_prune_repository_timedelta_everything_exact_vs_fuzzy(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    # Archiving strategy: One archive is made at 12:00 every day and assumed to take 0 seconds. Pruning is done
    # immediately afterwards. It is now 2025-12-29 12:00, the last Monday of the year, the 12:00 archive has been
    # created and we are now running prune maintenance.

    # ---- daily: last 2 weeks ----
    # Assuming every archive is created at exactly 12:00:00 and we run prune also at exactly 12:00:00,
    # "--keep-daily=2w" will keep THIRTEEN archives (assuming one every day) as the one from exactly 2 weeks ago falls
    # one microsecond outside of range.
    _create_archive_ts(archiver, "2025-12-29", 2025, 12, 29, 12)  # daily 1
    _create_archive_ts(archiver, "2025-12-28", 2025, 12, 28, 12)  # daily 2
    _create_archive_ts(archiver, "2025-12-27", 2025, 12, 27, 12)  # daily 3
    _create_archive_ts(archiver, "2025-12-26", 2025, 12, 26, 12)  # daily 4
    _create_archive_ts(archiver, "2025-12-25", 2025, 12, 25, 12)  # daily 5
    _create_archive_ts(archiver, "2025-12-24", 2025, 12, 24, 12)  # daily 6
    _create_archive_ts(archiver, "2025-12-23", 2025, 12, 23, 12)  # daily 7
    _create_archive_ts(archiver, "2025-12-22", 2025, 12, 22, 12)  # daily 8
    # Archiver not run on 2025-12-21 (daily 10)
    _create_archive_ts(archiver, "2025-12-20", 2025, 12, 20, 12)  # daily 10
    _create_archive_ts(archiver, "2025-12-19", 2025, 12, 19, 12)  # daily 11
    _create_archive_ts(archiver, "2025-12-18", 2025, 12, 18, 12)  # daily 12
    # Fuzzy by week includes the Tuesday and Wednesday 12:00 archives, as well as the one from the preceding Monday
    _create_archive_ts(archiver, "2025-12-17", 2025, 12, 17, 12)  # daily fuzzy 1
    _create_archive_ts(archiver, "2025-12-16", 2025, 12, 16, 12)  # daily fuzzy 2
    _create_archive_ts(archiver, "2025-12-15", 2025, 12, 15, 12)  # daily fuzzy 3
    # Fuzzy cutoff on crossing Sunday-Monday boundary. These would not exist in the exact case as stated in the example.
    _create_archive_ts(archiver, "2025-12-14", 2025, 12, 14, 12)  # daily fuzzy 4
    _create_archive_ts(archiver, "2025-12-13", 2025, 12, 13, 12)  # daily fuzzy 5
    _create_archive_ts(archiver, "2025-12-12", 2025, 12, 12, 12)  # daily fuzzy 6
    _create_archive_ts(archiver, "2025-12-11", 2025, 12, 11, 12)  # daily fuzzy 7
    _create_archive_ts(archiver, "2025-12-10", 2025, 12, 10, 12)  # daily fuzzy 8
    _create_archive_ts(archiver, "2025-12-09", 2025, 12, 9, 12)  # daily fuzzy 9
    _create_archive_ts(archiver, "2025-12-08", 2025, 12, 8, 12)  # daily fuzzy 10

    # ---- weekly: last 6 months ---
    # _create_archive_ts(archiver, "2025-12-14", 2025, 12, 14, 12) # weekly 1 (Duplicate with daily fuzzy 1)
    _create_archive_ts(archiver, "2025-12-07", 2025, 12, 7, 12)  # weekly 2
    _create_archive_ts(archiver, "2025-11-30", 2025, 11, 30, 12)  # weekly 3
    _create_archive_ts(archiver, "2025-11-23", 2025, 11, 23, 12)  # weekly 4
    _create_archive_ts(archiver, "2025-11-16", 2025, 11, 16, 12)  # weekly 5
    _create_archive_ts(archiver, "2025-11-09", 2025, 11, 9, 12)  # weekly 6
    _create_archive_ts(archiver, "2025-11-02", 2025, 11, 2, 12)  # weekly 7
    _create_archive_ts(archiver, "2025-10-26", 2025, 10, 26, 12)  # weekly 8
    _create_archive_ts(archiver, "2025-10-19", 2025, 10, 19, 12)  # weekly 9
    _create_archive_ts(archiver, "2025-10-12", 2025, 10, 12, 12)  # weekly 10
    _create_archive_ts(archiver, "2025-10-05", 2025, 10, 5, 12)  # weekly 11
    _create_archive_ts(
        archiver, "2025-09-27", 2025, 9, 27, 12
    )  # weekly 12 (archiver not run on Sunday 09-28, so 09-27 is kept)
    _create_archive_ts(archiver, "2025-09-21", 2025, 9, 21, 12)  # weekly 13
    _create_archive_ts(archiver, "2025-09-14", 2025, 9, 14, 12)  # weekly 14
    _create_archive_ts(archiver, "2025-09-07", 2025, 9, 7, 12)  # weekly 15
    _create_archive_ts(archiver, "2025-08-31", 2025, 8, 31, 12)  # weekly 16
    _create_archive_ts(archiver, "2025-08-24", 2025, 8, 24, 12)  # weekly 17
    _create_archive_ts(archiver, "2025-08-17", 2025, 8, 17, 12)  # weekly 18
    _create_archive_ts(archiver, "2025-08-10", 2025, 8, 10, 12)  # weekly 19
    _create_archive_ts(archiver, "2025-08-03", 2025, 8, 3, 12)  # weekly 20
    _create_archive_ts(archiver, "2025-07-27", 2025, 7, 27, 12)  # weekly 21
    _create_archive_ts(archiver, "2025-07-20", 2025, 7, 20, 12)  # weekly 22
    _create_archive_ts(archiver, "2025-07-13", 2025, 7, 13, 12)  # weekly 23
    _create_archive_ts(archiver, "2025-07-06", 2025, 7, 6, 12)  # weekly 24
    # 12-31 minus 6 months is 06-30, meaning fuzzy month catches all backups in June
    _create_archive_ts(archiver, "2025-06-29", 2025, 6, 29, 12)  # weekly fuzzy 1
    _create_archive_ts(archiver, "2025-06-22", 2025, 6, 22, 12)  # weekly fuzzy 2
    _create_archive_ts(archiver, "2025-06-15", 2025, 6, 15, 12)  # weekly fuzzy 3
    _create_archive_ts(archiver, "2025-06-08", 2025, 6, 8, 12)  # weekly fuzzy 4
    _create_archive_ts(archiver, "2025-06-01", 2025, 6, 1, 12)  # weekly fuzzy 5

    # ---- monthly: last year ----
    # Last Sunday each month (lowest granularity kept when monthly retention kick in) for the rest of the year
    # _create_archive_ts(archiver, "2025-06-29", 2025,  6, 29, 12) # monthly 1 (Duplicate with weekly fuzzy 1)
    _create_archive_ts(archiver, "2025-05-25", 2025, 5, 25, 12)  # monhtly 2
    _create_archive_ts(archiver, "2025-04-27", 2025, 4, 27, 12)  # monhtly 3
    _create_archive_ts(archiver, "2025-03-30", 2025, 3, 30, 12)  # monhtly 4
    _create_archive_ts(archiver, "2025-02-23", 2025, 2, 23, 12)  # monhtly 5
    _create_archive_ts(archiver, "2025-01-26", 2025, 1, 26, 12)  # monhtly 6
    # Last Sunday each month through 2024 as per fuzzy year delta
    _create_archive_ts(archiver, "2024-12-29", 2024, 12, 29, 12)  # monthly fuzzy 1
    _create_archive_ts(archiver, "2024-11-24", 2024, 11, 24, 12)  # monthly fuzzy 2
    _create_archive_ts(archiver, "2024-10-27", 2024, 10, 27, 12)  # monthly fuzzy 3
    _create_archive_ts(archiver, "2024-09-29", 2024, 9, 29, 12)  # monthly fuzzy 4
    _create_archive_ts(archiver, "2024-08-25", 2024, 8, 25, 12)  # monthly fuzzy 5
    _create_archive_ts(archiver, "2024-07-28", 2024, 7, 28, 12)  # monthly fuzzy 6
    _create_archive_ts(archiver, "2024-06-30", 2024, 6, 30, 12)  # monthly fuzzy 7
    _create_archive_ts(archiver, "2024-05-26", 2024, 5, 26, 12)  # monthly fuzzy 8
    _create_archive_ts(archiver, "2024-04-28", 2024, 4, 28, 12)  # monthly fuzzy 9
    _create_archive_ts(archiver, "2024-03-31", 2024, 3, 31, 12)  # monthly fuzzy 10
    _create_archive_ts(archiver, "2024-02-25", 2024, 2, 25, 12)  # monthly fuzzy 11
    _create_archive_ts(archiver, "2024-01-28", 2024, 1, 28, 12)  # monthly fuzzy 12

    # ---- yearly: exactly 3 -----
    # _create_archive_ts(archiver, "2024-12-29", 2024, 12, 29, 12) # yearly 1 (Duplicate with monthly fuzzy 1)
    _create_archive_ts(archiver, "2023-12-31", 2023, 12, 31, 12)  # yearly 2
    _create_archive_ts(archiver, "2022-12-25", 2022, 12, 25, 12)  # yearly 3
    _create_archive_ts(archiver, "2021-12-26", 2021, 12, 26, 12)  # yearly 4

    # ---- Exact deltas ------------------------------------------------
    output_exact = cmd(
        archiver,
        "prune",
        "--list",
        "--dry-run",
        "--keep-daily=2w",
        "--keep-weekly=6m",
        "--keep-monthly=1y",
        "--keep-yearly=3",
    )
    print("Prune output (exact):")
    print(output_exact)
    output_exact = list(reversed(output_exact.splitlines()))

    # Daily within 2 weeks
    assert re.search(r"Keeping archive \(rule: daily #1\):\s+2025-12-29", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: daily #2\):\s+2025-12-28", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: daily #3\):\s+2025-12-27", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: daily #4\):\s+2025-12-26", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: daily #5\):\s+2025-12-25", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: daily #6\):\s+2025-12-24", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: daily #7\):\s+2025-12-23", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: daily #8\):\s+2025-12-22", output_exact.pop())
    # Nothing on 2025-12-21
    assert re.search(r"Keeping archive \(rule: daily #9\):\s+2025-12-20", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: daily #10\):\s+2025-12-19", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: daily #11\):\s+2025-12-18", output_exact.pop())
    # Would match with daily by fuzzy week
    assert re.search(r"Keeping archive \(rule: daily #12\):\s+2025-12-17", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: daily #13\):\s+2025-12-16", output_exact.pop())
    assert re.search(r"Would prune:\s+2025-12-15", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: weekly #1\):\s+2025-12-14", output_exact.pop())
    assert re.search(r"Would prune:\s+2025-12-13", output_exact.pop())
    assert re.search(r"Would prune:\s+2025-12-12", output_exact.pop())
    assert re.search(r"Would prune:\s+2025-12-11", output_exact.pop())
    assert re.search(r"Would prune:\s+2025-12-10", output_exact.pop())
    assert re.search(r"Would prune:\s+2025-12-09", output_exact.pop())
    assert re.search(r"Would prune:\s+2025-12-08", output_exact.pop())

    # Weekly within 6 months
    assert re.search(r"Keeping archive \(rule: weekly #2\):\s+2025-12-07", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: weekly #3\):\s+2025-11-30", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: weekly #4\):\s+2025-11-23", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: weekly #5\):\s+2025-11-16", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: weekly #6\):\s+2025-11-09", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: weekly #7\):\s+2025-11-02", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: weekly #8\):\s+2025-10-26", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: weekly #9\):\s+2025-10-19", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: weekly #10\):\s+2025-10-12", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: weekly #11\):\s+2025-10-05", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: weekly #12\):\s+2025-09-27", output_exact.pop())  # (Not 09-28)
    assert re.search(r"Keeping archive \(rule: weekly #13\):\s+2025-09-21", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: weekly #14\):\s+2025-09-14", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: weekly #15\):\s+2025-09-07", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: weekly #16\):\s+2025-08-31", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: weekly #17\):\s+2025-08-24", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: weekly #18\):\s+2025-08-17", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: weekly #19\):\s+2025-08-10", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: weekly #20\):\s+2025-08-03", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: weekly #21\):\s+2025-07-27", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: weekly #22\):\s+2025-07-20", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: weekly #23\):\s+2025-07-13", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: weekly #24\):\s+2025-07-06", output_exact.pop())
    # Would match with weekly by fuzzy month
    assert re.search(r"Keeping archive \(rule: monthly #1\):\s+2025-06-29", output_exact.pop())
    assert re.search(r"Would prune:\s+2025-06-22", output_exact.pop())
    assert re.search(r"Would prune:\s+2025-06-15", output_exact.pop())
    assert re.search(r"Would prune:\s+2025-06-08", output_exact.pop())
    assert re.search(r"Would prune:\s+2025-06-01", output_exact.pop())

    # Monthly within 1 year
    assert re.search(r"Keeping archive \(rule: monthly #2\):\s+2025-05-25", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: monthly #3\):\s+2025-04-27", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: monthly #4\):\s+2025-03-30", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: monthly #5\):\s+2025-02-23", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: monthly #6\):\s+2025-01-26", output_exact.pop())
    # Would match with monthly by fuzzy year
    assert re.search(r"Keeping archive \(rule: yearly #1\):\s+2024-12-29", output_exact.pop())
    assert re.search(r"Would prune:\s+2024-11-24", output_exact.pop())
    assert re.search(r"Would prune:\s+2024-10-27", output_exact.pop())
    assert re.search(r"Would prune:\s+2024-09-29", output_exact.pop())
    assert re.search(r"Would prune:\s+2024-08-25", output_exact.pop())
    assert re.search(r"Would prune:\s+2024-07-28", output_exact.pop())
    assert re.search(r"Would prune:\s+2024-06-30", output_exact.pop())
    assert re.search(r"Would prune:\s+2024-05-26", output_exact.pop())
    assert re.search(r"Would prune:\s+2024-04-28", output_exact.pop())
    assert re.search(r"Would prune:\s+2024-03-31", output_exact.pop())
    assert re.search(r"Would prune:\s+2024-02-25", output_exact.pop())
    assert re.search(r"Would prune:\s+2024-01-28", output_exact.pop())

    # Yearly x3
    assert re.search(r"Keeping archive \(rule: yearly #2\):\s+2023-12-31", output_exact.pop())
    assert re.search(r"Keeping archive \(rule: yearly #3\):\s+2022-12-25", output_exact.pop())
    # Would match if yearly #1 matched with fuzzy by month instead
    assert re.search(r"Would prune:\s+2021-12-26", output_exact.pop())
    assert len(output_exact) == 0

    # ---- Exact deltas ------------------------------------------------
    output_fuzzy = cmd(
        archiver,
        "prune",
        "--list",
        "--dry-run",
        "--keep-daily=2wz",
        "--keep-weekly=6mz",
        "--keep-monthly=1yz",
        "--keep-yearly=3",
    )
    print("Prune output (fuzzy):")
    print(output_fuzzy)
    output_fuzzy = list(reversed(output_fuzzy.splitlines()))

    # Daily within 2 weeks
    assert re.search(r"Keeping archive \(rule: daily #1\):\s+2025-12-29", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: daily #2\):\s+2025-12-28", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: daily #3\):\s+2025-12-27", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: daily #4\):\s+2025-12-26", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: daily #5\):\s+2025-12-25", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: daily #6\):\s+2025-12-24", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: daily #7\):\s+2025-12-23", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: daily #8\):\s+2025-12-22", output_fuzzy.pop())
    # Nothing on 2025-12-21
    assert re.search(r"Keeping archive \(rule: daily #9\):\s+2025-12-20", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: daily #10\):\s+2025-12-19", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: daily #11\):\s+2025-12-18", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: daily #12\):\s+2025-12-17", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: daily #13\):\s+2025-12-16", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: daily #14\):\s+2025-12-15", output_fuzzy.pop())

    # Weekly within 6 months
    assert re.search(r"Keeping archive \(rule: weekly #1\):\s+2025-12-14", output_fuzzy.pop())
    assert re.search(r"Would prune:\s+2025-12-13", output_fuzzy.pop())
    assert re.search(r"Would prune:\s+2025-12-12", output_fuzzy.pop())
    assert re.search(r"Would prune:\s+2025-12-11", output_fuzzy.pop())
    assert re.search(r"Would prune:\s+2025-12-10", output_fuzzy.pop())
    assert re.search(r"Would prune:\s+2025-12-09", output_fuzzy.pop())
    assert re.search(r"Would prune:\s+2025-12-08", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: weekly #2\):\s+2025-12-07", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: weekly #3\):\s+2025-11-30", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: weekly #4\):\s+2025-11-23", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: weekly #5\):\s+2025-11-16", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: weekly #6\):\s+2025-11-09", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: weekly #7\):\s+2025-11-02", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: weekly #8\):\s+2025-10-26", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: weekly #9\):\s+2025-10-19", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: weekly #10\):\s+2025-10-12", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: weekly #11\):\s+2025-10-05", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: weekly #12\):\s+2025-09-27", output_fuzzy.pop())  # (Not 09-28)
    assert re.search(r"Keeping archive \(rule: weekly #13\):\s+2025-09-21", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: weekly #14\):\s+2025-09-14", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: weekly #15\):\s+2025-09-07", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: weekly #16\):\s+2025-08-31", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: weekly #17\):\s+2025-08-24", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: weekly #18\):\s+2025-08-17", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: weekly #19\):\s+2025-08-10", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: weekly #20\):\s+2025-08-03", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: weekly #21\):\s+2025-07-27", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: weekly #22\):\s+2025-07-20", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: weekly #23\):\s+2025-07-13", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: weekly #24\):\s+2025-07-06", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: weekly #25\):\s+2025-06-29", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: weekly #26\):\s+2025-06-22", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: weekly #27\):\s+2025-06-15", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: weekly #28\):\s+2025-06-08", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: weekly #29\):\s+2025-06-01", output_fuzzy.pop())

    # Monthly within 1 year
    assert re.search(r"Keeping archive \(rule: monthly #1\):\s+2025-05-25", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: monthly #2\):\s+2025-04-27", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: monthly #3\):\s+2025-03-30", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: monthly #4\):\s+2025-02-23", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: monthly #5\):\s+2025-01-26", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: monthly #6\):\s+2024-12-29", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: monthly #7\):\s+2024-11-24", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: monthly #8\):\s+2024-10-27", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: monthly #9\):\s+2024-09-29", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: monthly #10\):\s+2024-08-25", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: monthly #11\):\s+2024-07-28", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: monthly #12\):\s+2024-06-30", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: monthly #13\):\s+2024-05-26", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: monthly #14\):\s+2024-04-28", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: monthly #15\):\s+2024-03-31", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: monthly #16\):\s+2024-02-25", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: monthly #17\):\s+2024-01-28", output_fuzzy.pop())

    # Yearly x3
    assert re.search(r"Keeping archive \(rule: yearly #1\):\s+2023-12-31", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: yearly #2\):\s+2022-12-25", output_fuzzy.pop())
    assert re.search(r"Keeping archive \(rule: yearly #3\):\s+2021-12-26", output_fuzzy.pop())
    assert len(output_fuzzy) == 0


def test_prune_no_args(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    with pytest.raises(CommandError) as error:
        cmd(archiver, "prune")
    output = str(error.value)
    assert re.search(r"At least one of the .* settings must be specified.", output)
    assert re.search(r"keep(?!-)", output)
    flags = [
        "last",
        "within",
        "secondly",
        "minutely",
        "hourly",
        "daily",
        "weekly",
        "monthly",
        "yearly",
        "13weekly",
        "3monthly",
    ]
    for flag in flags:
        assert f"keep-{flag}" in output

from itertools import product
import json
import pytest
import re
from operator import attrgetter
from datetime import datetime, timezone, timedelta
from freezegun import freeze_time

from ...constants import *  # NOQA
from ...archiver.prune_cmd import (
    PRUNING_RULES,
    prune,
    PRUNE_DAILY,
    PRUNE_HOURLY,
    PRUNE_MINUTELY,
    PRUNE_MONTHLY,
    PRUNE_SECONDLY,
    PRUNE_WEEKLY,
    PRUNE_WITHIN,
    PRUNE_YEARLY,
)
from ...helpers import CommandError, interval
from ...manifest import ArchiveInfo
from . import cmd, RK_ENCRYPTION, generate_archiver_tests

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def _create_archive_ts(archiver, backup_files, name, y, m, d, H=0, M=0, S=0, us=0, tzinfo=None):
    cmd(
        archiver,
        "create",
        "--timestamp",
        datetime(y, m, d, H, M, S, us, tzinfo=tzinfo).strftime(ISO_FORMAT_ZONE),
        name,
        backup_files,
    )


def test_prune_repository(archivers, request, backup_files):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test1", backup_files)
    cmd(archiver, "create", "test2", backup_files)
    output = cmd(archiver, "prune", "--list", "--dry-run", "--keep-daily=1")
    assert re.search(r"Would prune:\s+test1", output)
    # Must keep the latest archive:
    assert re.search(r"Keeping archive \(rule: daily #1\):\s+test2", output)
    output = cmd(archiver, "repo-list")
    assert "test1" in output
    assert "test2" in output
    output = cmd(archiver, "prune", "--list", "--keep-daily=1")
    assert re.search(r"Pruning archive \(1/1\):\s+test1", output)
    output = cmd(archiver, "repo-list")
    assert "test1" not in output
    # The latest archive must still be there:
    assert "test2" in output


# This test must match docs/misc/prune-example.txt
def test_prune_repository_example(archivers, request, backup_files):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    # Archives that will be kept, per the example
    # Oldest archive
    _create_archive_ts(archiver, backup_files, "test01", 2015, 1, 1)
    # 6 monthly archives
    _create_archive_ts(archiver, backup_files, "test02", 2015, 6, 30)
    _create_archive_ts(archiver, backup_files, "test03", 2015, 7, 31)
    _create_archive_ts(archiver, backup_files, "test04", 2015, 8, 31)
    _create_archive_ts(archiver, backup_files, "test05", 2015, 9, 30)
    _create_archive_ts(archiver, backup_files, "test06", 2015, 10, 31)
    _create_archive_ts(archiver, backup_files, "test07", 2015, 11, 30)
    # 14 daily archives
    _create_archive_ts(archiver, backup_files, "test08", 2015, 12, 17)
    _create_archive_ts(archiver, backup_files, "test09", 2015, 12, 18)
    _create_archive_ts(archiver, backup_files, "test10", 2015, 12, 20)
    _create_archive_ts(archiver, backup_files, "test11", 2015, 12, 21)
    _create_archive_ts(archiver, backup_files, "test12", 2015, 12, 22)
    _create_archive_ts(archiver, backup_files, "test13", 2015, 12, 23)
    _create_archive_ts(archiver, backup_files, "test14", 2015, 12, 24)
    _create_archive_ts(archiver, backup_files, "test15", 2015, 12, 25)
    _create_archive_ts(archiver, backup_files, "test16", 2015, 12, 26)
    _create_archive_ts(archiver, backup_files, "test17", 2015, 12, 27)
    _create_archive_ts(archiver, backup_files, "test18", 2015, 12, 28)
    _create_archive_ts(archiver, backup_files, "test19", 2015, 12, 29)
    _create_archive_ts(archiver, backup_files, "test20", 2015, 12, 30)
    _create_archive_ts(archiver, backup_files, "test21", 2015, 12, 31)
    # Additional archives that would be pruned
    # The second backup of the year
    _create_archive_ts(archiver, backup_files, "test22", 2015, 1, 2)
    # The next older monthly backup
    _create_archive_ts(archiver, backup_files, "test23", 2015, 5, 31)
    # The next older daily backup
    _create_archive_ts(archiver, backup_files, "test24", 2015, 12, 16)
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


def test_prune_quarterly(archivers, request, backup_files):
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
            _create_archive_ts(archiver, backup_files, a, y, m, d)

        to_prune = list(set(test_dates) - set(to_keep))

        # Use 99 instead of -1 to test that oldest backup is kept.
        output = cmd(archiver, "prune", "--list", "--dry-run", f"--keep-{strat}=99")
        print(output)
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
def test_prune_retain_and_expire_oldest(archivers, request, backup_files):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    # Initial backup
    _create_archive_ts(archiver, backup_files, "original_archive", 2020, 9, 1, 11, 15)
    # Archive and prune daily for 30 days
    for i in range(1, 31):
        _create_archive_ts(archiver, backup_files, "september%02d" % i, 2020, 9, i, 12)
        cmd(archiver, "prune", "--keep-daily=7", "--keep-monthly=1")
    # Archive and prune 6 days into the next month
    for i in range(1, 7):
        _create_archive_ts(archiver, backup_files, "october%02d" % i, 2020, 10, i, 12)
        cmd(archiver, "prune", "--keep-daily=7", "--keep-monthly=1")
    # Oldest backup is still retained
    output = cmd(archiver, "prune", "--list", "--dry-run", "--keep-daily=7", "--keep-monthly=1")
    assert re.search(r"Keeping archive \(rule: monthly\[oldest\] #1" + r"\):\s+original_archive", output)
    # Archive one more day and prune.
    _create_archive_ts(archiver, backup_files, "october07", 2020, 10, 7, 12)
    cmd(archiver, "prune", "--keep-daily=7", "--keep-monthly=1")
    # Last day of previous month is retained as monthly, and oldest is expired.
    output = cmd(archiver, "prune", "--list", "--dry-run", "--keep-daily=7", "--keep-monthly=1")
    assert re.search(r"Keeping archive \(rule: monthly #1\):\s+september30", output)
    assert "original_archive" not in output


def test_prune_repository_prefix(archivers, request, backup_files):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "foo-2015-08-12-10:00", backup_files)
    cmd(archiver, "create", "foo-2015-08-12-20:00", backup_files)
    cmd(archiver, "create", "bar-2015-08-12-10:00", backup_files)
    cmd(archiver, "create", "bar-2015-08-12-20:00", backup_files)
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


def test_prune_repository_glob(archivers, request, backup_files):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "2015-08-12-10:00-foo", backup_files)
    cmd(archiver, "create", "2015-08-12-20:00-foo", backup_files)
    cmd(archiver, "create", "2015-08-12-10:00-bar", backup_files)
    cmd(archiver, "create", "2015-08-12-20:00-bar", backup_files)
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


mock_id = 0


def mock_archive(ts, id=None):
    """Create an ArchiveInfo with mocked/default values."""
    global mock_id
    if id is None:
        id = mock_id
        mock_id += 1
    return ArchiveInfo(name="", id=id, ts=ts.replace(tzinfo=timezone.utc), tags=(), host="", user="")


def test_prune_within():
    test_deltas = [
        timedelta(minutes=1),
        timedelta(hours=1.5),
        timedelta(hours=2.5),
        timedelta(hours=3.5),
        timedelta(hours=25),
        timedelta(hours=49),
    ]
    now = datetime.now(timezone.utc)
    test_dates = [now - d for d in test_deltas]
    test_archives = [mock_archive(date) for date in test_dates]

    def dotest(within, indices):
        keep = prune(test_archives, PRUNE_WITHIN, interval(within), now, False)
        assert set(keep) == {test_archives[i] for i in indices}
        assert all(keep[a].rule.key == "within" for a in keep)

    dotest("15S", [])
    dotest("2M", [0])
    dotest("1H", [0])
    dotest("2H", [0, 1])
    dotest("3H", [0, 1, 2])
    dotest("24H", [0, 1, 2, 3])
    dotest("26H", [0, 1, 2, 3, 4])
    dotest("2d", [0, 1, 2, 3, 4])
    dotest("50H", [0, 1, 2, 3, 4, 5])
    dotest("3d", [0, 1, 2, 3, 4, 5])
    dotest("1w", [0, 1, 2, 3, 4, 5])
    dotest("1m", [0, 1, 2, 3, 4, 5])
    dotest("1y", [0, 1, 2, 3, 4, 5])


@pytest.mark.parametrize(
    "rule,num_to_keep,expected_indices",
    [
        (PRUNE_YEARLY, 3, (12, 1, 0)),
        (PRUNE_MONTHLY, 3, (12, 7, 3)),
        (PRUNE_WEEKLY, 2, (12, 7)),
        (PRUNE_DAILY, 3, (12, 7, 6)),
        (PRUNE_HOURLY, 3, (12, 9, 7)),
        (PRUNE_MINUTELY, 3, (12, 9, 8)),
        (PRUNE_SECONDLY, 4, (12, 11, 10, 9)),
        (PRUNE_DAILY, 0, []),
        (PRUNE_DAILY, -1, (12, 7, 6, 5, 4, 3, 2, 1, 0)),
    ],
)
def test_prune(rule, num_to_keep, expected_indices):
    archives = [
        # years apart
        mock_archive(datetime(2015, 1, 1, 10, 0, 0)),
        mock_archive(datetime(2016, 1, 1, 10, 0, 0)),
        mock_archive(datetime(2017, 1, 1, 10, 0, 0)),
        # months apart
        mock_archive(datetime(2017, 2, 1, 10, 0, 0)),
        mock_archive(datetime(2017, 3, 1, 10, 0, 0)),
        # days apart
        mock_archive(datetime(2017, 3, 2, 10, 0, 0)),
        mock_archive(datetime(2017, 3, 3, 10, 0, 0)),
        mock_archive(datetime(2017, 3, 4, 10, 0, 0)),
        # minutes apart
        mock_archive(datetime(2017, 10, 1, 9, 45, 0)),
        mock_archive(datetime(2017, 10, 1, 9, 55, 0)),
        # seconds apart
        mock_archive(datetime(2017, 10, 1, 10, 0, 1)),
        mock_archive(datetime(2017, 10, 1, 10, 0, 3)),
        mock_archive(datetime(2017, 10, 1, 10, 0, 5)),
    ]
    keep = prune(sorted(archives, key=attrgetter("ts"), reverse=True), rule, num_to_keep, None, False)

    assert set(keep) == {archives[i] for i in expected_indices}
    assert all(result.rule == rule for _, result in keep.items())


def test_prune_keep_oldest():
    archives = [
        # oldest backup, but not last in its year
        mock_archive(datetime(2018, 1, 1, 10, 0, 0)),
        # an interim backup
        mock_archive(datetime(2018, 12, 30, 10, 0, 0)),
        # year-end backups
        mock_archive(datetime(2018, 12, 31, 10, 0, 0)),
        mock_archive(datetime(2019, 12, 31, 10, 0, 0)),
    ]
    sorted_archives = sorted(archives, key=attrgetter("ts"), reverse=True)

    # Keep oldest when retention target can't otherwise be met
    keep = prune(sorted_archives, PRUNE_YEARLY, 3, None, True)

    assert keep[archives[0]].rule.key == "yearly" and keep[archives[0]].oldest is True
    assert keep[archives[2]].rule.key == "yearly" and keep[archives[2]].oldest is False
    assert keep[archives[3]].rule.key == "yearly" and keep[archives[3]].oldest is False
    assert len(keep) == 3

    # Otherwise, prune it
    keep = prune(sorted_archives, PRUNE_YEARLY, 2, None, True)

    assert keep[archives[2]].rule.key == "yearly" and keep[archives[2]].oldest is False
    assert keep[archives[3]].rule.key == "yearly" and keep[archives[3]].oldest is False
    assert len(keep) == 2


def test_prune_no_archives():
    archives = []

    keep = prune(archives, PRUNE_YEARLY, 3, None, False)

    assert keep == {}


def test_prune_list_with_metadata_format(archivers, request, backup_files):
    # Regression test for: prune --list with a format string that requires loading
    # archive metadata (e.g. {hostname}) must not fail when archives are deleted.
    # The bug was that format_item() was called after archive.delete(), causing
    # Archive.DoesNotExist when the formatter tried to lazy-load the archive.
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test1", backup_files)
    cmd(archiver, "create", "test2", backup_files)
    # {hostname} is a "call key" that triggers lazy loading of the archive from the repo.
    # With the buggy code this would raise Archive.DoesNotExist for the pruned archive.
    output = cmd(archiver, "prune", "--list", "--keep-daily=1", "--format={name} {hostname}{NL}")
    assert "test1" in output
    assert "test2" in output


def test_prune_json(archivers, request, backup_files):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test1", backup_files)
    cmd(archiver, "create", "test2", backup_files)
    prune_result = json.loads(cmd(archiver, "prune", "--json", "--dry-run", "--keep-daily=1"))
    assert "repository" in prune_result
    assert "encryption" in prune_result
    assert len(prune_result["repository"]["id"]) == 64
    archives = prune_result["archives"]
    assert len(archives) == 2
    kept = [a for a in archives if a["kept"]]
    pruned = [a for a in archives if not a["kept"]]
    assert len(kept) == 1
    assert len(pruned) == 1
    assert kept[0]["name"] == "test2"
    assert kept[0]["keep_rule"] == "daily"
    assert kept[0]["kept_archive_number"] == 1
    assert not kept[0]["kept_oldest"]
    assert "deleted_archive_number" not in kept[0]
    assert pruned[0]["name"] == "test1"
    assert pruned[0]["deleted_archive_number"] == 1
    assert "keep_rule" not in pruned[0]
    assert "kept_archive_number" not in pruned[0]
    for archive in archives:
        assert "name" in archive
        assert "id" in archive
        assert "time" in archive
        assert "kept" in archive


def test_prune_json_list_pruned(archivers, request, backup_files):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test1", backup_files)
    cmd(archiver, "create", "test2", backup_files)
    prune_result = json.loads(cmd(archiver, "prune", "--json", "--dry-run", "--list-pruned", "--keep-daily=1"))
    archives = prune_result["archives"]
    assert len(archives) == 1
    assert archives[0]["name"] == "test1"
    assert archives[0]["kept"] is False
    assert archives[0]["deleted_archive_number"] == 1


def test_prune_keep_last_same_second(archivers, request, backup_files):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test1", backup_files)
    cmd(archiver, "create", "test2", backup_files)
    output = cmd(archiver, "prune", "--list", "--dry-run", "--keep-last=2")
    # Both archives are kept even though they have the same timestamp to the second. Would previously have failed with
    # old behavior of --keep-last. Archives sorted on seconds, order is undefined.
    assert re.search(r"Keeping archive \(rule: last #\d\):\s+test1", output)
    assert re.search(r"Keeping archive \(rule: last #\d\):\s+test2", output)


@freeze_time(datetime(2023, 12, 31, 23, 59, 59, tzinfo=None))  # Non-leap year ending on a Sunday
def test_prune_keep_int_or_interval(archivers, request, backup_files):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    _create_archive_ts(archiver, backup_files, "test-1", 2023, 12, 31, 23, 59, 59)
    _create_archive_ts(archiver, backup_files, "test-2", 2023, 12, 31, 23, 59, 59)
    _create_archive_ts(archiver, backup_files, "test-3", 2023, 12, 31, 23, 59, 58)
    for keep_arg in ["--keep=2", "--keep=1S"]:
        output = cmd(archiver, "prune", "--list", "--dry-run", keep_arg)
        assert re.search(r"Keeping archive \(rule: keep #\d\):\s+test-1", output)
        assert re.search(r"Keeping archive \(rule: keep #\d\):\s+test-2", output)
        assert re.search(r"Would prune:\s+test-3", output)


@pytest.mark.parametrize("keep_arg", ["--keep-daily=-1", "--keep-daily=all"])
def test_prune_keep_all(archivers, request, backup_files, keep_arg):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    _create_archive_ts(archiver, backup_files, "test-1", 2023, 12, 30, 23, 59, 59, tzinfo=timezone.utc)
    _create_archive_ts(archiver, backup_files, "test-2", 2023, 12, 29, 23, 59, 59, tzinfo=timezone.utc)
    _create_archive_ts(archiver, backup_files, "test-3", 2023, 12, 28, 23, 59, 59, tzinfo=timezone.utc)
    output = cmd(archiver, "prune", "--list", "--dry-run", keep_arg)
    assert re.search(r"Keeping archive \(rule: daily #1\):\s+test-1", output)
    assert re.search(r"Keeping archive \(rule: daily #2\):\s+test-2", output)
    assert re.search(r"Keeping archive \(rule: daily #3\):\s+test-3", output)


@freeze_time(datetime(2023, 12, 31, 23, 59, 59, tzinfo=None))
def test_prune_keep_secondly_int_or_interval(archivers, request, backup_files, keep_arg):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    _create_archive_ts(archiver, backup_files, "test-1", 2023, 12, 31, 23, 59, 58)
    _create_archive_ts(archiver, backup_files, "test-2", 2023, 12, 31, 23, 59, 57, 1)
    _create_archive_ts(archiver, backup_files, "test-3", 2023, 12, 31, 23, 59, 57)
    _create_archive_ts(archiver, backup_files, "test-4", 2023, 12, 31, 23, 59, 56, 999999)
    for keep_arg in ["--keep-secondly=2", "--keep-secondly=2S"]:
        output = cmd(archiver, "prune", "--list", "--dry-run", keep_arg).splitlines()
        assert re.search(r"Keeping archive \(rule: secondly #1\):\s+test-1", output.pop(0))
        assert re.search(r"Keeping archive \(rule: secondly #2\):\s+test-2", output.pop(0))
        assert re.search(r"Would prune:\s+test-3", output.pop(0))
        assert re.search(r"Would prune:\s+test-4", output.pop(0))


@freeze_time(datetime(2023, 12, 31, 23, 59, 0, tzinfo=None))
def test_prune_keep_minutely_int_or_interval(archivers, request, backup_files):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    _create_archive_ts(archiver, backup_files, "test-1", 2023, 12, 31, 23, 58)
    _create_archive_ts(archiver, backup_files, "test-2", 2023, 12, 31, 23, 57, 1)
    _create_archive_ts(archiver, backup_files, "test-3", 2023, 12, 31, 23, 57)
    _create_archive_ts(archiver, backup_files, "test-4", 2023, 12, 31, 23, 56, 0, 1)  # Last possible microsecond
    _create_archive_ts(archiver, backup_files, "test-5", 2023, 12, 31, 23, 56)
    for keep_arg in ["--keep-minutely=3", "--keep-minutely=3M"]:
        output = cmd(archiver, "prune", "--list", "--dry-run", keep_arg).splitlines()
        assert re.search(r"Keeping archive \(rule: minutely #1\):\s+test-1", output.pop(0))
        assert re.search(r"Keeping archive \(rule: minutely #2\):\s+test-2", output.pop(0))
        assert re.search(r"Would prune:\s+test-3", output.pop(0))
        assert re.search(r"Keeping archive \(rule: minutely #3\):\s+test-4", output.pop(0))
        assert re.search(r"Would prune:\s+test-5", output.pop(0))


@freeze_time(datetime(2023, 12, 31, 23, 0, 0, tzinfo=None))
def test_prune_keep_hourly_int_or_interval(archivers, request, backup_files):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    _create_archive_ts(archiver, backup_files, "test-1", 2023, 12, 31, 22)
    _create_archive_ts(archiver, backup_files, "test-2", 2023, 12, 31, 21, us=1)
    _create_archive_ts(archiver, backup_files, "test-3", 2023, 12, 31, 21)
    _create_archive_ts(archiver, backup_files, "test-4", 2023, 12, 31, 20, us=1)  # Last possible microsecond
    _create_archive_ts(archiver, backup_files, "test-5", 2023, 12, 31, 20)
    for keep_arg in ["--keep-hourly=3", "--keep-hourly=3H"]:
        output = cmd(archiver, "prune", "--list", "--dry-run", keep_arg).splitlines()
        assert re.search(r"Keeping archive \(rule: hourly #1\):\s+test-1", output.pop(0))
        assert re.search(r"Keeping archive \(rule: hourly #2\):\s+test-2", output.pop(0))
        assert re.search(r"Would prune:\s+test-3", output.pop(0))
        assert re.search(r"Keeping archive \(rule: hourly #3\):\s+test-4", output.pop(0))
        assert re.search(r"Would prune:\s+test-5", output.pop(0))


@freeze_time(datetime(2023, 12, 31, 0, 0, 0, tzinfo=None))
def test_prune_keep_daily_int_or_interval(archivers, request, backup_files):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    _create_archive_ts(archiver, backup_files, "test-1", 2023, 12, 30)
    _create_archive_ts(archiver, backup_files, "test-2", 2023, 12, 29, S=1)
    _create_archive_ts(archiver, backup_files, "test-3", 2023, 12, 29)
    _create_archive_ts(archiver, backup_files, "test-4", 2023, 12, 28, us=1)  # Last possible microsecond
    _create_archive_ts(archiver, backup_files, "test-5", 2023, 12, 28)
    for keep_arg in ["--keep-daily=3", "--keep-daily=3d"]:
        output = cmd(archiver, "prune", "--list", "--dry-run", keep_arg).splitlines()
        assert re.search(r"Keeping archive \(rule: daily #1\):\s+test-1", output.pop(0))
        assert re.search(r"Keeping archive \(rule: daily #2\):\s+test-2", output.pop(0))
        assert re.search(r"Would prune:\s+test-3", output.pop(0))
        assert re.search(r"Keeping archive \(rule: daily #3\):\s+test-4", output.pop(0))
        assert re.search(r"Would prune:\s+test-5", output.pop(0))


@freeze_time(datetime(2023, 12, 31, 0, 0, 0, tzinfo=None))
def test_prune_keep_weekly_int_or_interval(archivers, request, backup_files):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    _create_archive_ts(archiver, backup_files, "test-1", 2023, 12, 24)
    _create_archive_ts(archiver, backup_files, "test-2", 2023, 12, 17, us=1)
    _create_archive_ts(archiver, backup_files, "test-3", 2023, 12, 17)
    _create_archive_ts(archiver, backup_files, "test-4", 2023, 12, 10, us=1)  # Last possible microsecond
    _create_archive_ts(archiver, backup_files, "test-5", 2023, 12, 10)
    for keep_arg in ["--keep-weekly=3", "--keep-weekly=3w"]:
        output = cmd(archiver, "prune", "--list", "--dry-run", keep_arg).splitlines()
        assert re.search(r"Keeping archive \(rule: weekly #1\):\s+test-1", output.pop(0))
        assert re.search(r"Keeping archive \(rule: weekly #2\):\s+test-2", output.pop(0))
        assert re.search(r"Would prune:\s+test-3", output.pop(0))
        assert re.search(r"Keeping archive \(rule: weekly #3\):\s+test-4", output.pop(0))
        assert re.search(r"Would prune:\s+test-5", output.pop(0))


@freeze_time(datetime(2023, 12, 31, 0, 0, 0, tzinfo=None))
def test_prune_keep_monthly_int_or_interval(archivers, request, backup_files):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    _create_archive_ts(archiver, backup_files, "test-1", 2023, 11, 30)
    _create_archive_ts(
        archiver, backup_files, "test-2", 2023, 10, 30, us=1
    )  # Month defined as 31 days, so not Oct 31st
    _create_archive_ts(archiver, backup_files, "test-3", 2023, 10, 30)
    _create_archive_ts(archiver, backup_files, "test-4", 2023, 9, 29, us=1)  # Last possible microsecond
    _create_archive_ts(archiver, backup_files, "test-5", 2023, 9, 29)
    for keep_arg in ["--keep-monthly=3", "--keep-monthly=3m"]:
        output = cmd(archiver, "prune", "--list", "--dry-run", keep_arg).splitlines()
        assert re.search(r"Keeping archive \(rule: monthly #1\):\s+test-1", output.pop(0))
        assert re.search(r"Keeping archive \(rule: monthly #2\):\s+test-2", output.pop(0))
        assert re.search(r"Would prune:\s+test-3", output.pop(0))
        assert re.search(r"Keeping archive \(rule: monthly #3\):\s+test-4", output.pop(0))
        assert re.search(r"Would prune:\s+test-5", output.pop(0))


# 2023-12-31 is Sunday, week 52. Makes these week calculations a little easier.
@freeze_time(datetime(2023, 12, 31, 0, 0, 0, tzinfo=None))
def test_prune_keep_13weekly_int_or_interval(archivers, request, backup_files):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    _create_archive_ts(archiver, backup_files, "test-1", 2023, 10, 1)
    _create_archive_ts(archiver, backup_files, "test-2", 2023, 7, 2, us=1)
    _create_archive_ts(archiver, backup_files, "test-3", 2023, 7, 2)
    _create_archive_ts(archiver, backup_files, "test-4", 2023, 4, 2, us=1)  # Last possible microsecond
    _create_archive_ts(archiver, backup_files, "test-5", 2023, 4, 2)
    for keep_arg in ["--keep-13weekly=3", "--keep-13weekly=39w"]:
        output = cmd(archiver, "prune", "--list", "--dry-run", keep_arg).splitlines()
        assert re.search(r"Keeping archive \(rule: quarterly_13weekly #1\):\s+test-1", output.pop(0))
        assert re.search(r"Keeping archive \(rule: quarterly_13weekly #2\):\s+test-2", output.pop(0))
        assert re.search(r"Would prune:\s+test-3", output.pop(0))
        assert re.search(r"Keeping archive \(rule: quarterly_13weekly #3\):\s+test-4", output.pop(0))
        assert re.search(r"Would prune:\s+test-5", output.pop(0))


@freeze_time(datetime(2023, 12, 31, 0, 0, 0, tzinfo=None))
def test_prune_keep_3monthly_int_or_interval(archivers, request, backup_files):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    _create_archive_ts(archiver, backup_files, "test-1", 2023, 9, 30)
    _create_archive_ts(archiver, backup_files, "test-2", 2023, 6, 30, us=1)
    _create_archive_ts(archiver, backup_files, "test-3", 2023, 6, 30)
    _create_archive_ts(archiver, backup_files, "test-4", 2023, 3, 31, us=1)  # Last possible microsecond
    _create_archive_ts(archiver, backup_files, "test-5", 2023, 3, 31)
    # 275d is the interval from now to 2023-03-31
    for keep_arg in ["--keep-3monthly=3", "--keep-3monthly=275d"]:
        output = cmd(archiver, "prune", "--list", "--short", "--dry-run", keep_arg).splitlines()
        assert re.search(r"Keeping archive \(rule: quarterly_3monthly #1\):\s+test-1", output.pop(0))
        assert re.search(r"Keeping archive \(rule: quarterly_3monthly #2\):\s+test-2", output.pop(0))
        assert re.search(r"Would prune:\s+test-3", output.pop(0))
        assert re.search(r"Keeping archive \(rule: quarterly_3monthly #3\):\s+test-4", output.pop(0))
        assert re.search(r"Would prune:\s+test-5", output.pop(0))


@freeze_time(datetime(2023, 12, 31, 0, 0, 0, tzinfo=None))
def test_prune_keep_yearly_int_or_interval(archivers, request, backup_files):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    _create_archive_ts(archiver, backup_files, "test-1", 2022, 12, 31)
    _create_archive_ts(archiver, backup_files, "test-2", 2021, 12, 31, us=1)
    _create_archive_ts(archiver, backup_files, "test-3", 2021, 12, 31)
    _create_archive_ts(archiver, backup_files, "test-4", 2020, 12, 31, us=1)  # Last possible microsecond
    _create_archive_ts(archiver, backup_files, "test-5", 2020, 12, 31)
    for keep_arg in ["--keep-yearly=3", "--keep-yearly=3y"]:
        output = cmd(archiver, "prune", "--list", "--dry-run", keep_arg).splitlines()
        assert re.search(r"Keeping archive \(rule: yearly #1\):\s+test-1", output.pop(0))
        assert re.search(r"Keeping archive \(rule: yearly #2\):\s+test-2", output.pop(0))
        assert re.search(r"Would prune:\s+test-3", output.pop(0))
        assert re.search(r"Keeping archive \(rule: yearly #3\):\s+test-4", output.pop(0))
        assert re.search(r"Would prune:\s+test-5", output.pop(0))


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


def test_prune_errors_on_keep_and_last(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    with pytest.raises(CommandError) as error:
        cmd(archiver, "prune", "--dry-run", "--keep-last=5", "--keep=3")
    assert 'Only one of the "keep" and "last" settings may be specified.' in str(error.value)


def test_prune_errors_on_keep_and_within(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    with pytest.raises(CommandError) as error:
        cmd(archiver, "prune", "--dry-run", "--keep-within=7d", "--keep=3")
    assert 'Only one of the "keep" and "within" settings may be specified.' in str(error.value)


@pytest.mark.parametrize("keep_arg,value", product([rule.key for rule in PRUNING_RULES], ["0", "0S"]))
def test_prune_all_zero_args_one(archivers, request, keep_arg, value):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    arg_with_prefix = "--keep" if keep_arg == "keep" else f"--keep-{keep_arg.replace('quarterly_', '')}"
    output = _cmd_prune_error(archiver, f"{arg_with_prefix}={value}")
    assert re.search(r"None of the .* settings have a positive value. At least one must be non-zero.", output)


def test_prune_all_zero_multiple_multiple(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    output = _cmd_prune_error(archiver, "--keep-secondly=0S", "--keep-daily=0")
    assert re.search(r"None of the .* settings have a positive value. At least one must be non-zero.", output)


@pytest.mark.parametrize(
    "lo_val,hi_val",
    [("14d", "7d"), ("-1", "7d"), ("-1", "1"), ("-1", "-1"), ("all", "7d"), ("all", "1"), ("all", "-1")],
)
def test_prune_warns_on_redundant_interval_flags(archivers, request, lo_val, hi_val):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    with pytest.raises(CommandError) as error:
        cmd(archiver, "prune", "--dry-run", f"--keep-hourly={lo_val}", f"--keep-daily={hi_val}")
    assert "hourly=" in str(error.value)
    assert "daily=" in str(error.value)
    assert "effectively useless" in str(error.value)


@pytest.mark.parametrize("lo_val,hi_val", [("7d", "14d"), ("7d", "-1"), ("1", "-1"), ("7d", "all"), ("1", "all")])
def test_prune_does_not_warn_on_normal_interval_flags(archivers, request, lo_val, hi_val):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    output = cmd(archiver, "prune", "--dry-run", f"--keep-hourly={lo_val}", f"--keep-daily={hi_val}")
    assert "effectively useless" not in output


def test_prune_int_rolling_schedule_oldest_retention():
    daily_n = 6
    monthly_n = 3
    start_date = datetime(2024, 1, 1, tzinfo=timezone.utc)

    previous_archives = []
    archives = []

    for day_offset in range(97):
        backup_ts = start_date + timedelta(days=day_offset)
        previous_archives = archives
        archives = [mock_archive(backup_ts, day_offset), *archives]

        keep = {}
        keep |= prune(archives, PRUNE_DAILY, daily_n, None, False, keep)
        keep |= prune(archives, PRUNE_MONTHLY, monthly_n, None, True, keep)

        archives = sorted(keep.keys(), key=lambda a: a.ts, reverse=True)

    # It is now 2024-04-06. The last run should have just pruned the jan-01
    # archive since the monthly retention count is now satisfied at jan-31. It
    # was kept until now to satisfy the oldest-rule.

    assert previous_archives[-1].ts.strftime("%m-%d") == "01-01"
    assert archives[-1].ts.strftime("%m-%d") == "01-31"


def test_prune_interval_rolling_schedule_oldest_retention():
    daily_interval = timedelta(days=6)
    monthly_interval = timedelta(days=31 * 3)  # Matching --keep-monthly=3m after argument parsing
    start_date = datetime(2024, 1, 1, tzinfo=timezone.utc)

    previous_archives = []
    archives = []

    for day_offset in range(94):
        backup_ts = start_date + timedelta(days=day_offset)
        previous_archives = archives
        archives = [mock_archive(backup_ts, day_offset), *archives]

        keep = {}
        keep |= prune(archives, PRUNE_DAILY, daily_interval, backup_ts, False, keep)
        keep |= prune(archives, PRUNE_MONTHLY, monthly_interval, backup_ts, True, keep)

        print(
            f"For backup+prune at {backup_ts.strftime('%m-%d')} ({day_offset})"
            f" the following {len(archives)} archives are kept:"
        )
        for a, result in keep.items():
            print(f"    {a.id}: {a.ts.strftime('%Y-%m-%d')} {result}")

        archives = sorted(keep.keys(), key=lambda a: a.ts, reverse=True)

    # It is now 2024-04-03. The last run should have just pruned the jan-01
    # archive since it now falls outside the retention range (_exactly_ 93 days
    # or 3 months ago, timestamp compared exclusively). It was kept until now
    # to satisfy the oldest-rule.

    assert previous_archives[-1].ts.strftime("%m-%d") == "01-01"
    assert archives[-1].ts.strftime("%m-%d") == "01-31"

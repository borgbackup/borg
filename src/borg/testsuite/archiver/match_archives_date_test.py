from datetime import datetime, timezone

from ...constants import *  # NOQA
from . import cmd, create_src_archive, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


# (archive_name, timestamp)
YEAR_ARCHIVES = [
    ("archive-year-start", "2025-01-01T00:00:00"),
    ("archive-year-same", "2025-12-31T23:59:59"),
    ("archive-year-diff", "2024-12-31T23:59:59"),
]

MONTH_ARCHIVES = [
    ("archive-mon-start", "2025-02-01T00:00:00"),
    ("archive-mon-same", "2025-02-28T23:59:59"),
    ("archive-mon-diff", "2025-01-31T23:59:59"),
]

HOUR_ARCHIVES = [
    ("archive-hour-start", "2025-01-01T14:00:00"),
    ("archive-hour-same", "2025-01-01T14:59:59"),
    ("archive-hour-diff", "2025-01-01T13:59:59"),
]

MINUTE_ARCHIVES = [
    ("archive-min-start", "2025-01-01T13:31:00"),
    ("archive-min-same", "2025-01-01T13:31:59"),
    ("archive-min-diff", "2025-01-01T13:30:59"),
]

SECOND_ARCHIVES = [
    ("archive-sec-target", "2025-01-01T13:30:45"),
    ("archive-sec-before", "2025-01-01T13:30:44"),
    ("archive-sec-after", "2025-01-01T13:30:46"),
]


def test_match_archives_year(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    for name, ts in YEAR_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    # older‐year should only hit the 2024 filter
    out_2024 = cmd(archiver, "repo-list", "-v", "--match-archives=date:2024", exit_code=0)
    assert "archive-year-diff" in out_2024
    assert "archive-year-start" not in out_2024
    assert "archive-year-same" not in out_2024

    # 2025 filter should hit both minimum and maximum possible days in 2025
    out_2025 = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025", exit_code=0)
    assert "archive-year-start" in out_2025
    assert "archive-year-same" in out_2025
    assert "archive-year-diff" not in out_2025


def test_match_archives_month(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    for name, ts in MONTH_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    # January only includes January
    out_jan = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-01", exit_code=0)
    assert "archive-mon-diff" in out_jan
    assert "archive-mon-start" not in out_jan
    assert "archive-mon-same" not in out_jan

    # February includes minimum and maximum possible days in February
    out_feb = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-02", exit_code=0)
    assert "archive-mon-start" in out_feb
    assert "archive-mon-same" in out_feb
    assert "archive-mon-diff" not in out_feb


def test_match_archives_hour(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    for name, ts in HOUR_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    # 13:00‐range only matches 13:00 hour
    out_13 = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-01-01T13", exit_code=0)
    assert "archive-hour-diff" in out_13
    assert "archive-hour-start" not in out_13
    assert "archive-hour-same" not in out_13

    # 14:00‐range matches both beginning and end of the hour
    out_14 = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-01-01T14", exit_code=0)
    assert "archive-hour-start" in out_14
    assert "archive-hour-same" in out_14
    assert "archive-hour-diff" not in out_14


def test_match_archives_minute(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    for name, ts in MINUTE_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    # 13:30 only matches 13:30 minute
    out_1330 = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-01-01T13:30", exit_code=0)
    assert "archive-min-diff" in out_1330
    assert "archive-min-start" not in out_1330
    assert "archive-min-same" not in out_1330

    # 13:31 matches both beginning and end of the minute
    out_1331 = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-01-01T13:31", exit_code=0)
    assert "archive-min-start" in out_1331
    assert "archive-min-same" in out_1331
    assert "archive-min-diff" not in out_1331


def test_match_archives_second(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    for name, ts in SECOND_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    # exact‐second match only
    out_exact = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-01-01T13:30:45", exit_code=0)
    assert "archive-sec-target" in out_exact
    assert "archive-sec-before" not in out_exact
    assert "archive-sec-after" not in out_exact


def test_unix_timestamps(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_src_archive(archiver, "archive-sec-before", ts="2025-01-01T13:30:44")
    create_src_archive(archiver, "archive-sec-target", ts="2025-01-01T13:30:45")
    create_src_archive(archiver, "archive-sec-after", ts="2025-01-01T13:30:46")
    # localize the datetime, since the archive creation time will be local
    dt_target = datetime.fromisoformat("2025-01-01T13:30:45").astimezone()

    utc_ts_target = int(dt_target.astimezone(timezone.utc).timestamp())

    output = cmd(archiver, "repo-list", "-v", f"--match-archives=date:@{utc_ts_target}", exit_code=0)

    assert "archive-sec-target" in output
    assert "archive-sec-before" not in output
    assert "archive-sec-after" not in output

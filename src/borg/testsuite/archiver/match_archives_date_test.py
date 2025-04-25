import pytest
from datetime import datetime, timezone

from ...constants import *  # NOQA
from . import cmd, create_src_archive, generate_archiver_tests, RK_ENCRYPTION
from ...helpers.errors import CommandError

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

DAY_ARCHIVES = [
    ("archive-day-start", "2025-01-02T00:00:00"),
    ("archive-day-same", "2025-01-02T23:59:59"),
    ("archive-day-diff", "2025-01-01T23:59:59"),
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


def test_match_archives_day(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    for name, ts in DAY_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    # 2025-01-01 only includes 2025-01-01
    out_01 = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-01-01", exit_code=0)
    assert "archive-day-diff" in out_01
    assert "archive-day-start" not in out_01
    assert "archive-day-same" not in out_01

    # 2025-01-02 includes minimum and maximum possible times in 2025-01-02
    out_02 = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-01-02", exit_code=0)
    assert "archive-day-start" in out_02
    assert "archive-day-same" in out_02
    assert "archive-day-diff" not in out_02


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


TIMEZONE_ARCHIVES = [("archive-la", "2025-01-01T12:01:00-08:00"), ("archive-utc", "2025-01-02T12:01:00+00:00")]


@pytest.mark.parametrize("timezone_variant", ["2025-01-01T12:01:00-08:00", "2025-01-01T12:01:00[America/Los_Angeles]"])
def test_match_la_equivalents(archivers, request, timezone_variant):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    for name, ts in TIMEZONE_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    output = cmd(archiver, "repo-list", "-v", f"--match-archives=date:{timezone_variant}", exit_code=0)
    assert "archive-la" in output
    assert "archive-utc" not in output


@pytest.mark.parametrize(
    "timezone_variant", ["2025-01-02T12:01:00+00:00", "2025-01-02T12:01:00Z", "2025-01-02T12:01:00[Etc/UTC]"]
)
def test_match_utc_equivalents(archivers, request, timezone_variant):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    for name, ts in TIMEZONE_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    output = cmd(archiver, "repo-list", "-v", f"--match-archives=date:{timezone_variant}", exit_code=0)
    assert "archive-utc" in output
    assert "archive-la" not in output


HOUR_TZ_ARCHIVES = [
    ("archive-hour-diff", "2025-01-01T09:59:00Z"),
    ("archive-hour-start", "2025-01-01T10:00:00Z"),
    ("archive-hour-same", "2025-01-01T10:59:59Z"),
]


def test_match_hour_from_different_tz(archivers, request):
    """
    Test that the date filter works for hours with archives created in a different timezone.
    """
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    for name, ts in HOUR_TZ_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    # We're filtering “local 11:00” in +01:00 zone, which is 10:00–10:59:59 UTC
    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-01-01T11+01:00", exit_code=0)
    assert "archive-hour-start" in out
    assert "archive-hour-same" in out
    assert "archive-hour-diff" not in out


def test_match_day_from_different_tz(archivers, request):
    """
    Test that the date filter works for days with archives created in a different timezone.
    """
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    # Local 2025‑03‑02T00:30:00+02:00 → UTC 2025‑03‑01T22:30:00Z
    create_src_archive(archiver, "archive-utc-bound", ts="2025-03-02T00:30:00+02:00")

    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-03-01[Etc/UTC]", exit_code=0)
    assert "archive-utc-bound" in out


@pytest.mark.parametrize(
    "invalid_expr",
    [
        "2025-01-01T00:00:00+14:01",  # beyond +14:00 (ISO 8601 boundary)
        "2025-01-01T00:00:00-12:01",  # beyond -12:00 (ISO 8601 boundary)
        "2025-01-01T00:00:00+09:99",  # invalid minutes
        "2025-01-01T00:00:00[garbage]",  # invalid region
        "2025-01-01T00:00:00[Not/AZone]",  # structured but nonexistent
    ],
)
def test_invalid_timezones_rejected(archivers, request, invalid_expr):
    """
    Test that invalid timezone expressions are rejected.
    """
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    with pytest.raises(CommandError) as excinfo:
        cmd(archiver, "repo-list", "-v", f"--match-archives=date:{invalid_expr}")

    msg = str(excinfo.value)
    assert "Invalid date pattern" in msg
    assert invalid_expr in msg


WILDCARD_DAY_ARCHIVES = [
    ("wd-jan12", "2025-01-12T00:00:00"),
    ("wd-feb12", "2025-02-12T23:59:59"),
    ("wd-jan13", "2025-01-13T00:00:00"),
]


# Day-only wildcard: *-*-12
def test_match_wildcard_specific_day(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    for name, ts in WILDCARD_DAY_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:*-*-12", exit_code=0)
    assert "wd-jan12" in out
    assert "wd-feb12" in out
    assert "wd-jan13" not in out


WILDCARD_MONTH_ARCHIVES = [
    ("wm-apr1", "2025-04-01T00:00:00"),
    ("wm-apr30", "2025-04-30T23:59:59"),
    ("wm-mar31", "2025-03-31T23:59:59"),
]


# Month-only wildcard: *-04
def test_match_wildcard_every_april(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    for name, ts in WILDCARD_MONTH_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:*-04", exit_code=0)
    assert "wm-apr1" in out
    assert "wm-apr30" in out
    assert "wm-mar31" not in out


WILDCARD_MINUTE_ARCHIVES = [
    ("w-min-a", "2025-01-01T12:10:00"),
    ("w-min-b", "2025-01-01T12:59:00"),
    ("w-min-c", "2025-01-01T12:10:01"),  # should not match
]


# Time-of-day wildcard (minute‐level): 2025-01-01T12:*:00
def test_match_wildcard_any_minute_at_second_zero(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    for name, ts in WILDCARD_MINUTE_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-01-01T12:*:00", exit_code=0)
    assert "w-min-a" in out
    assert "w-min-b" in out
    assert "w-min-c" not in out


# Wildcard plus timezone: day in America/Detroit
WILDCARD_TZ_ARCHIVES = [
    # UTC 2025-04-12T03:59:59Z -> local EDT = 2025-04-11T23:59:59 (before - should not match)
    ("w-tz-before", "2025-04-12T03:59:59Z"),
    # UTC 2025-04-12T04:00:00Z -> local EDT = 2025-04-12T00:00:00 (start - should match)
    ("w-tz-start", "2025-04-12T04:00:00Z"),
    # UTC 2025-04-12T16:30:00Z -> local EDT = 2025-04-12T12:30:00 (halfway - should match)
    ("w-tz-mid", "2025-04-12T16:30:00Z"),
    # UTC 2025-04-13T03:59:59Z -> local EDT = 2025-04-12T23:59:59 (inclusive end - should still match)
    ("w-tz-same", "2025-04-13T03:59:59Z"),
    # UTC 2025-04-13T04:00:00Z -> local EDT = 2025-04-13T00:00:00 (after)
    ("w-tz-after", "2025-04-13T04:00:00Z"),
]


def test_match_wildcard_day_with_tz(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    for name, ts in WILDCARD_TZ_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-04-12T*:*:*[America/Detroit]", exit_code=0)
    # only the three in the EDT-local-Apr-12 window with second=0 should match
    assert "w-tz-start" in out
    assert "w-tz-mid" in out
    assert "w-tz-same" in out
    assert "w-tz-before" not in out
    assert "w-tz-after" not in out


WILDCARD_MIXED_ARCHIVES = [
    ("wmix-hit1", "2025-01-01T12:00:00"),  # matches: 01-01 12:00
    ("wmix-hit2", "2025-01-01T12:59:59"),  # matches: 01-01 12:*
    ("wmix-miss1", "2025-01-01T13:00:00"),  # wrong hour
    ("wmix-miss2", "2025-01-02T12:00:00"),  # wrong day
]


def test_match_wildcard_mixed_day_and_hour(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    for name, ts in WILDCARD_MIXED_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:*-01-01T12:*", exit_code=0)
    assert "wmix-hit1" in out
    assert "wmix-hit2" in out
    assert "wmix-miss1" not in out
    assert "wmix-miss2" not in out


# Interval matching tests

INTERVAL_ARCHIVES = [
    ("int-before", "2025-03-31T23:59:59"),
    ("int-start", "2025-04-01T00:00:00"),
    ("int-mid", "2025-04-15T12:00:00"),
    ("int-end", "2025-05-01T00:00:00"),
    ("int-after", "2025-05-01T00:00:01"),
]


# Explicit interval match tests
def test_match_explicit_interval(archivers, request):
    """
    Test matching archives between two explicit, fully-specified timestamps.
    The interval is inclusive of the start and exclusive of the end.
    """
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    for name, ts in INTERVAL_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-04-01T00:00:00/2025-05-01T00:00:00", exit_code=0)
    assert "int-start" in out
    assert "int-mid" in out
    assert "int-before" not in out
    assert "int-end" not in out  # exclusive end
    assert "int-after" not in out


def test_match_explicit_interval_with_timezone(archivers, request):
    """
    Test matching archives between two explicit timestamps with timezone offsets.
    Interval is inclusive of the start and exclusive of the end.
    """
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    TZ_INTERVAL_ARCHIVES = [
        ("tz-start", "2025-06-01T00:00:00+02:00"),  # UTC 2025-05-31T22:00:00Z
        ("tz-mid", "2025-06-01T12:00:00+02:00"),  # UTC 2025-06-01T10:00:00Z
        ("tz-end", "2025-06-02T00:00:00+02:00"),  # UTC 2025-06-01T22:00:00Z
    ]
    for name, ts in TZ_INTERVAL_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    # Express the interval in UTC, matching the UTC equivalents.
    out = cmd(
        archiver, "repo-list", "-v", "--match-archives=date:2025-05-31T22:00:00Z/2025-06-01T22:00:00Z", exit_code=0
    )
    assert "tz-start" in out
    assert "tz-mid" in out
    assert "tz-end" not in out

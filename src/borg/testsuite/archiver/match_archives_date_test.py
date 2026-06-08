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


# Duration-based interval tests


# Test duration prefix (duration/timestamp): 1-day before midnight
def test_match_duration_prefix_day(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    DURATION_ARCHIVES = [
        ("dur-start", "2025-04-01T00:00:00"),
        ("dur-mid", "2025-04-01T12:00:00"),
        ("dur-end", "2025-04-02T00:00:00"),
        ("dur-after", "2025-04-02T00:00:01"),
    ]
    for name, ts in DURATION_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    # D1D/2025-04-02T00:00:00 should cover 2025-04-01 inclusive to 2025-04-02 exclusive
    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:D1D/2025-04-02T00:00:00", exit_code=0)
    assert "dur-start" in out
    assert "dur-mid" in out
    assert "dur-end" not in out
    assert "dur-after" not in out


# Test duration suffix (timestamp/duration): 1-day after midnight
def test_match_duration_suffix_day(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    DURATION_ARCHIVES = [
        ("dur2-before", "2025-03-31T23:59:59"),
        ("dur2-start", "2025-04-01T00:00:00"),
        ("dur2-mid", "2025-04-01T12:00:00"),
        ("dur2-end", "2025-04-02T00:00:00"),
    ]
    for name, ts in DURATION_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    # 2025-04-01T00:00:00/D1D should cover 2025-04-01 00:00 inclusive to 2025-04-02 exclusive
    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-04-01T00:00:00/D1D", exit_code=0)
    assert "dur2-before" not in out
    assert "dur2-start" in out
    assert "dur2-mid" in out
    assert "dur2-end" not in out


# Test duration prefix for 1-month
def test_match_duration_prefix_month(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    MONTH_DUR_ARCHIVES = [
        ("dpm-start", "2025-01-01T00:00:00"),
        ("dpm-mid", "2025-01-15T12:00:00"),
        ("dpm-end", "2025-02-01T00:00:00"),
        ("dpm-after", "2025-02-01T00:00:01"),
    ]
    for name, ts in MONTH_DUR_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    # D1M/2025-02-01T00:00:00 should cover entire January 2025
    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:D1M/2025-02-01T00:00:00", exit_code=0)
    assert "dpm-start" in out
    assert "dpm-mid" in out
    assert "dpm-end" not in out
    assert "dpm-after" not in out


# Test duration suffix for 1-week
def test_match_duration_suffix_week(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    WEEK_DUR_ARCHIVES = [
        ("dw-before", "2025-01-01T00:00:00"),
        ("dw-start", "2025-01-08T00:00:00"),
        ("dw-mid", "2025-01-10T12:00:00"),
        ("dw-end", "2025-01-15T00:00:00"),
    ]
    for name, ts in WEEK_DUR_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    # 2025-01-08T00:00:00/D1W should cover 2025-01-08 to 2025-01-15
    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-01-08T00:00:00/D1W", exit_code=0)
    assert "dw-before" not in out
    assert "dw-start" in out
    assert "dw-mid" in out
    assert "dw-end" not in out


# Test composite duration prefix (1 month + 1 day)
def test_match_duration_composite_prefix(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    COMP_ARCHIVES = [
        ("cp-start", "2025-01-01T00:00:00"),
        ("cp-mid", "2025-02-01T00:00:00"),
        ("cp-end", "2025-02-02T00:00:00"),
        ("cp-after", "2025-02-02T00:00:01"),
    ]
    for name, ts in COMP_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    # D1M1D/2025-02-02T00:00:00 should cover 2025-01-01 to 2025-02-02
    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:D1M1D/2025-02-02T00:00:00", exit_code=0)
    assert "cp-start" in out
    assert "cp-mid" in out
    assert "cp-end" not in out
    assert "cp-after" not in out


# Test duration suffix for hours (timestamp/D3h)
def test_match_duration_suffix_hours(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    HOUR_DUR_ARCHIVES = [
        ("dh-before", "2025-04-01T09:59:59"),
        ("dh-start", "2025-04-01T10:00:00"),
        ("dh-mid", "2025-04-01T11:30:00"),
        ("dh-end", "2025-04-01T12:59:59"),
        ("dh-after", "2025-04-01T13:00:00"),
    ]
    for name, ts in HOUR_DUR_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    # 2025-04-01T10:00:00/D3h should cover 10:00 to 13:00 exclusive
    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-04-01T10:00:00/D3h", exit_code=0)
    assert "dh-before" not in out
    assert "dh-start" in out
    assert "dh-mid" in out
    assert "dh-end" in out
    assert "dh-after" not in out


# Test duration prefix for minutes (D30m/timestamp)
def test_match_duration_prefix_minutes(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    MIN_DUR_ARCHIVES = [
        ("dm-before", "2025-04-01T00:29:59"),
        ("dm-start", "2025-04-01T00:30:00"),
        ("dm-end", "2025-04-01T00:59:59"),
        ("dm-after", "2025-04-01T01:00:00"),
    ]
    for name, ts in MIN_DUR_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    # D30m/2025-04-01T01:00:00 should cover 00:30 to 01:00 exclusive
    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:D30m/2025-04-01T01:00:00", exit_code=0)
    assert "dm-before" not in out
    assert "dm-start" in out
    assert "dm-end" in out
    assert "dm-after" not in out


# Test composite duration suffix (timestamp/D1h30m)
def test_match_duration_suffix_composite_h_m(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    COMP_HM_ARCHIVES = [
        ("chm-before", "2025-04-01T00:59:59"),
        ("chm-start", "2025-04-01T01:00:00"),
        ("chm-mid", "2025-04-01T02:15:00"),
        ("chm-end", "2025-04-01T02:29:59"),
        ("chm-after", "2025-04-01T02:30:00"),
    ]
    for name, ts in COMP_HM_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    # 2025-04-01T01:00:00/D1h30m should cover 01:00 to 02:30 exclusive
    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-04-01T01:00:00/D1h30m", exit_code=0)
    assert "chm-before" not in out
    assert "chm-start" in out
    assert "chm-mid" in out
    assert "chm-end" in out
    assert "chm-after" not in out


# Keyword-based interval tests (oldest/newest)


def test_match_keyword_oldest_to_timestamp(archivers, request):
    """
    Test 'oldest/TIMESTAMP' selects from the earliest archive up to the given timestamp (exclusive).
    """
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    KEYWORD_ARCHIVES = [
        ("arch1", "2025-01-01T00:00:00"),
        ("arch2", "2025-01-02T00:00:00"),
        ("arch3", "2025-01-03T00:00:00"),
    ]
    for name, ts in KEYWORD_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    # oldest is arch1; oldest/arch2 => interval [arch1, arch2)
    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:oldest/2025-01-02T00:00:00", exit_code=0)
    assert "arch1" in out
    assert "arch2" not in out
    assert "arch3" not in out


def test_match_keyword_timestamp_to_newest(archivers, request):
    """
    Test 'TIMESTAMP/newest' selects from the given timestamp up to the latest archive (inclusive).
    """
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    KEYWORD_ARCHIVES = [
        ("arch1", "2025-01-01T00:00:00"),
        ("arch2", "2025-01-02T00:00:00"),
        ("arch3", "2025-01-03T00:00:00"),
    ]
    for name, ts in KEYWORD_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    # newest is arch3; arch2/newest => interval [arch2, arch3)
    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-01-02T00:00:00/newest", exit_code=0)
    assert "arch1" not in out
    assert "arch2" in out
    assert "arch3" in out


def test_match_keyword_oldest_to_newest(archivers, request):
    """
    Test 'oldest/newest' selects from the earliest archive up to the latest (exclusive).
    """
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    KEYWORD_ARCHIVES = [
        ("arch1", "2025-01-01T00:00:00"),
        ("arch2", "2025-01-02T00:00:00"),
        ("arch3", "2025-01-03T00:00:00"),
    ]
    for name, ts in KEYWORD_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:oldest/newest", exit_code=0)
    assert "arch1" in out
    assert "arch2" in out
    assert "arch3" in out


# Keyword permutations tests: oldest/now and now/newest


def test_match_keyword_oldest_to_now(archivers, request):
    """
    Test 'oldest/now' selects all archives since the earliest up to now.
    """
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    KEYWORD_ARCHIVES = [("k1", "2025-01-01T00:00:00"), ("k2", "2025-02-01T00:00:00"), ("k3", "2025-03-01T00:00:00")]
    for name, ts in KEYWORD_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:oldest/now", exit_code=0)
    # all created archives are before 'now', so should all match
    assert "k1" in out
    assert "k2" in out
    assert "k3" in out


def test_match_keyword_now_to_newest_invalid(archivers, request):
    """
    Test 'now/newest' should error, since newest will always be before 'now'.
    """
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    KEYWORD_ARCHIVES = [("kA", "2025-01-01T00:00:00"), ("kB", "2025-02-01T00:00:00"), ("kC", "2025-03-01T00:00:00")]
    for name, ts in KEYWORD_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)
    with pytest.raises(CommandError) as excinfo:
        cmd(archiver, "repo-list", "-v", "--match-archives=date:now/newest")

    msg = str(excinfo.value)
    assert "Invalid date pattern" in msg


def test_match_keyword_exact(archivers, request):
    """
    Test date:oldest returns the oldest archive, and date:newest returns the newest archive.
    """
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    KEYWORD_ARCHIVES = [("k1", "2025-01-01T00:00:00"), ("k2", "2025-02-01T00:00:00"), ("k3", "2025-03-01T00:00:00")]
    for name, ts in KEYWORD_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:oldest", exit_code=0)
    assert "k1" in out
    assert "k2" not in out
    assert "k3" not in out

    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:newest", exit_code=0)
    assert "k3" in out
    assert "k2" not in out
    assert "k1" not in out


# ISO week-date and ordinal-date support tests


def test_match_iso_week(archivers, request):
    """
    Test matching archives by ISO week number (YYYY-Www).
    Week 10 of 2025 runs from 2025-03-03 to 2025-03-09 inclusive.
    """
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    WEEK10_ARCHIVES = [
        ("iso-week-before", "2025-03-02T23:59:59"),
        ("iso-week-start", "2025-03-03T00:00:00"),
        ("iso-week-mid", "2025-03-05T12:00:00"),
        ("iso-week-end", "2025-03-09T23:59:59"),
        ("iso-week-after", "2025-03-10T00:00:00"),
    ]
    for name, ts in WEEK10_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-W10", exit_code=0)
    assert "iso-week-before" not in out
    assert "iso-week-start" in out
    assert "iso-week-mid" in out
    assert "iso-week-end" in out
    assert "iso-week-after" not in out


def test_match_iso_weekday(archivers, request):
    """
    Test matching archives by ISO week and weekday (YYYY-Www-D).
    Week 10 Day 3 of 2025 is Wednesday 2025-03-05.
    """
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    WEEKDAY_ARCHIVES = [
        ("iso-wed", "2025-03-05T08:00:00"),
        ("iso-tue", "2025-03-04T12:00:00"),
        ("iso-thu", "2025-03-06T18:00:00"),
    ]
    for name, ts in WEEKDAY_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-W10-3", exit_code=0)
    assert "iso-wed" in out
    assert "iso-tue" not in out
    assert "iso-thu" not in out


def test_match_ordinal_date(archivers, request):
    """
    Test matching archives by ordinal day of year (YYYY-DDD).
    Day 032 of 2025 is 2025-02-01.
    """
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    ORDINAL_ARCHIVES = [
        ("ord-jan31", "2025-01-31T23:59:59"),  # day 031
        ("ord-feb1", "2025-02-01T00:00:00"),  # day 032
        ("ord-feb1-end", "2025-02-01T23:59:59"),
        ("ord-feb2", "2025-02-02T00:00:00"),  # day 033
    ]
    for name, ts in ORDINAL_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-032", exit_code=0)
    assert "ord-jan31" not in out
    assert "ord-feb1" in out
    assert "ord-feb1-end" in out
    assert "ord-feb2" not in out


def test_match_rfc3339(archivers, request):
    """
    Test matching archives by RFC 3339 date format (use ' ' as delimiter rather than 'T').
    """
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    RFC_ARCHIVES = [
        ("rfc-start", "2025-01-01T00:00:00Z"),
        ("rfc-mid", "2025-01-01T12:00:00Z"),
        ("rfc-max", "2025-01-01T23:59:59Z"),
        ("rfc-after", "2025-01-02T00:00:00Z"),
    ]
    for name, ts in RFC_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    out = cmd(
        archiver, "repo-list", "-v", "--match-archives=date:2025-01-01 00:00:00Z/2025-01-02 00:00:00Z", exit_code=0
    )
    assert "rfc-start" in out
    assert "rfc-mid" in out
    assert "rfc-max" in out
    assert "rfc-after" not in out

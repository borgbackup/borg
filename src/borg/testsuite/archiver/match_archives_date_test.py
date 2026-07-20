import calendar
import os
import time
from datetime import datetime, timezone

import pytest

from ...constants import *  # NOQA
from ...helpers.errors import CommandError
from ...platform import is_win32
from . import cmd, create_src_archive, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,binary")  # NOQA


@pytest.fixture
def set_timezone(request):
    """Set the process-local timezone for the duration of a test, restoring it afterwards."""

    def _set(tz):
        old_tz = os.environ.get("TZ")

        def restore():
            if old_tz is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = old_tz
            time.tzset()

        request.addfinalizer(restore)
        os.environ["TZ"] = tz
        time.tzset()

    return _set


# (archive_name, timestamp)
YEAR_ARCHIVES = [
    ("archive-year-start", "2025-01-01T00:00:00+00:00"),
    ("archive-year-same", "2025-12-31T23:59:59+00:00"),
    ("archive-year-diff", "2024-12-31T23:59:59+00:00"),
]

MONTH_ARCHIVES = [
    ("archive-mon-start", "2025-02-01T00:00:00+00:00"),
    ("archive-mon-same", "2025-02-28T23:59:59+00:00"),
    ("archive-mon-diff", "2025-01-31T23:59:59+00:00"),
]

DAY_ARCHIVES = [
    ("archive-day-start", "2025-01-02T00:00:00+00:00"),
    ("archive-day-same", "2025-01-02T23:59:59+00:00"),
    ("archive-day-diff", "2025-01-01T23:59:59+00:00"),
]

HOUR_ARCHIVES = [
    ("archive-hour-start", "2025-01-01T14:00:00+00:00"),
    ("archive-hour-same", "2025-01-01T14:59:59+00:00"),
    ("archive-hour-diff", "2025-01-01T13:59:59+00:00"),
]

MINUTE_ARCHIVES = [
    ("archive-min-start", "2025-01-01T13:31:00+00:00"),
    ("archive-min-same", "2025-01-01T13:31:59+00:00"),
    ("archive-min-diff", "2025-01-01T13:30:59+00:00"),
]

SECOND_ARCHIVES = [
    ("archive-sec-target", "2025-01-01T13:30:45+00:00"),
    ("archive-sec-before", "2025-01-01T13:30:44+00:00"),
    ("archive-sec-after", "2025-01-01T13:30:46+00:00"),
]


def test_match_archives_year(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    for name, ts in YEAR_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    # older-year should only hit the 2024 filter
    out_2024 = cmd(archiver, "repo-list", "-v", "--match-archives=date:2024Z", exit_code=0)
    assert "archive-year-diff" in out_2024
    assert "archive-year-start" not in out_2024
    assert "archive-year-same" not in out_2024

    # 2025 filter should hit both minimum and maximum possible days in 2025
    out_2025 = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025Z", exit_code=0)
    assert "archive-year-start" in out_2025
    assert "archive-year-same" in out_2025
    assert "archive-year-diff" not in out_2025


def test_match_archives_month(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    for name, ts in MONTH_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    # January only includes January
    out_jan = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-01Z", exit_code=0)
    assert "archive-mon-diff" in out_jan
    assert "archive-mon-start" not in out_jan
    assert "archive-mon-same" not in out_jan

    # February includes minimum and maximum possible days in February
    out_feb = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-02Z", exit_code=0)
    assert "archive-mon-start" in out_feb
    assert "archive-mon-same" in out_feb
    assert "archive-mon-diff" not in out_feb


def test_match_archives_day(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    for name, ts in DAY_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    # 2025-01-01 only includes 2025-01-01
    out_01 = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-01-01Z", exit_code=0)
    assert "archive-day-diff" in out_01
    assert "archive-day-start" not in out_01
    assert "archive-day-same" not in out_01

    # 2025-01-02 includes minimum and maximum possible times in 2025-01-02
    out_02 = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-01-02Z", exit_code=0)
    assert "archive-day-start" in out_02
    assert "archive-day-same" in out_02
    assert "archive-day-diff" not in out_02


def test_match_archives_hour(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    for name, ts in HOUR_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    # 13:00-range only matches 13:00 hour
    out_13 = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-01-01T13Z", exit_code=0)
    assert "archive-hour-diff" in out_13
    assert "archive-hour-start" not in out_13
    assert "archive-hour-same" not in out_13

    # 14:00-range matches both beginning and end of the hour
    out_14 = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-01-01T14Z", exit_code=0)
    assert "archive-hour-start" in out_14
    assert "archive-hour-same" in out_14
    assert "archive-hour-diff" not in out_14


def test_match_archives_minute(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    for name, ts in MINUTE_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    # 13:30 only matches 13:30 minute
    out_1330 = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-01-01T13:30Z", exit_code=0)
    assert "archive-min-diff" in out_1330
    assert "archive-min-start" not in out_1330
    assert "archive-min-same" not in out_1330

    # 13:31 matches both beginning and end of the minute
    out_1331 = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-01-01T13:31Z", exit_code=0)
    assert "archive-min-start" in out_1331
    assert "archive-min-same" in out_1331
    assert "archive-min-diff" not in out_1331


def test_match_archives_second(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    for name, ts in SECOND_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    # exact-second match only
    out_exact = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-01-01T13:30:45Z", exit_code=0)
    assert "archive-sec-target" in out_exact
    assert "archive-sec-before" not in out_exact
    assert "archive-sec-after" not in out_exact


def test_match_archives_fractional_second(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_src_archive(archiver, "archive-fraction-target", ts="2025-01-01T13:30:45.123456+00:00")
    create_src_archive(archiver, "archive-fraction-other", ts="2025-01-01T13:30:45.123457+00:00")

    output = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-01-01T13:30:45.123456Z", exit_code=0)

    assert "archive-fraction-target" in output
    assert "archive-fraction-other" not in output


def test_unix_timestamps(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_src_archive(archiver, "archive-sec-before", ts="2025-01-01T13:30:44+00:00")
    create_src_archive(archiver, "archive-sec-target", ts="2025-01-01T13:30:45+00:00")
    create_src_archive(archiver, "archive-sec-after", ts="2025-01-01T13:30:46+00:00")
    dt_target = datetime(2025, 1, 1, 13, 30, 45, tzinfo=timezone.utc)
    utc_ts_target = calendar.timegm(dt_target.utctimetuple())

    output = cmd(archiver, "repo-list", "-v", f"--match-archives=date:@{utc_ts_target}", exit_code=0)

    assert "archive-sec-target" in output
    assert "archive-sec-before" not in output
    assert "archive-sec-after" not in output


def test_fractional_unix_timestamps(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_src_archive(archiver, "archive-fraction-target", ts="2025-01-01T13:30:45.123456+00:00")
    create_src_archive(archiver, "archive-fraction-other", ts="2025-01-01T13:30:45.123457+00:00")
    dt_target = datetime(2025, 1, 1, 13, 30, 45, 123456, tzinfo=timezone.utc)
    utc_ts_target = calendar.timegm(dt_target.utctimetuple())

    output = cmd(
        archiver, "repo-list", "-v", f"--match-archives=date:@{utc_ts_target}.{dt_target.microsecond:06d}", exit_code=0
    )

    assert "archive-fraction-target" in output
    assert "archive-fraction-other" not in output


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

    # We're filtering "local 11:00" in +01:00 zone, which is 10:00-10:59:59 UTC
    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-01-01T11+01:00", exit_code=0)
    assert "archive-hour-start" in out
    assert "archive-hour-same" in out
    assert "archive-hour-diff" not in out


LOCAL_TZ_ARCHIVES = [
    ("archive-local-in", "2025-01-15T18:30:00Z"),  # 13:30 in America/New_York (EST, UTC-5)
    ("archive-local-out", "2025-01-15T17:30:00Z"),  # 12:30 in America/New_York
]


@pytest.mark.skipif(is_win32, reason="time.tzset() is not available on Windows")
def test_match_bare_pattern_uses_local_timezone(archivers, request, set_timezone):
    """A pattern without a timezone suffix is interpreted in the local timezone."""
    set_timezone("America/New_York")
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    for name, ts in LOCAL_TZ_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    # bare 13:30 is "local" EST (UTC-5) or 18:30 UTC, matching only archive-local-in
    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-01-15T13:30", exit_code=0)
    assert "archive-local-in" in out
    assert "archive-local-out" not in out


def test_match_space_date_time_separator(archivers, request):
    """A space is accepted in place of the T date-time separator."""
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    create_src_archive(archiver, "archive-in", ts="2025-01-01T14:30:30+00:00")
    create_src_archive(archiver, "archive-out", ts="2025-01-01T14:31:30+00:00")

    out = cmd(archiver, "repo-list", "-v", "--match-archives=date:2025-01-01 14:30Z", exit_code=0)
    assert "archive-in" in out
    assert "archive-out" not in out


# Europe/Berlin springs forward 2026-03-29: 02:00 CET (+01:00) -> 03:00 CEST (+02:00).
DST_ARCHIVES = [
    ("archive-cet", "2026-03-29T00:30:00Z"),  # local 01:30 CET (+01:00), before the transition
    ("archive-plus2", "2026-03-28T23:30:00Z"),  # 01:30 at a fixed +02:00 offset
    ("archive-cest", "2026-03-29T01:00:00Z"),  # local 03:00 CEST (+02:00), after the transition
]


def test_match_dst_transition(archivers, request):
    """Named zones track DST, so they can differ from a fixed offset around a transition."""
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    for name, ts in DST_ARCHIVES:
        create_src_archive(archiver, name, ts=ts)

    # Before the transition Europe/Berlin is +01:00, so 01:30 there differs from a literal +02:00.
    out_berlin = cmd(archiver, "repo-list", "-v", "--match-archives=date:2026-03-29T01:30[Europe/Berlin]", exit_code=0)
    assert "archive-cet" in out_berlin
    assert "archive-plus2" not in out_berlin
    assert "archive-cest" not in out_berlin

    out_plus2 = cmd(archiver, "repo-list", "-v", "--match-archives=date:2026-03-29T01:30+02:00", exit_code=0)
    assert "archive-plus2" in out_plus2
    assert "archive-cet" not in out_plus2

    # After the transition Europe/Berlin is +02:00, so 03:00 there equals the fixed +02:00.
    out_after = cmd(archiver, "repo-list", "-v", "--match-archives=date:2026-03-29T03:00[Europe/Berlin]", exit_code=0)
    assert "archive-cest" in out_after
    assert "archive-cet" not in out_after
    assert "archive-plus2" not in out_after


def rejected_date_pattern(archiver, invalid_expr):
    """Run a rejected ``date:`` pattern and return the resulting error message."""
    args = ("repo-list", "-v", f"--match-archives=date:{invalid_expr}")
    if archiver.FORK_DEFAULT:
        return cmd(archiver, *args, exit_code=CommandError().exit_code)
    with pytest.raises(CommandError) as excinfo:
        cmd(archiver, *args)
    return str(excinfo.value)


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

    msg = rejected_date_pattern(archiver, invalid_expr)
    assert "Invalid date pattern" in msg
    assert invalid_expr in msg


def test_unix_timestamp_rejects_timezone(archivers, request):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    msg = rejected_date_pattern(archiver, "@1735732800Z")
    assert "Invalid date pattern" in msg
    assert "@1735732800Z" in msg


@pytest.mark.parametrize(
    "invalid_expr",
    [
        "9999",  # year interval end overflows datetime.max
        "9999-12",  # month interval end overflows datetime.max
        "9999-12-31T23",  # hour interval end overflows datetime.max
        "@253402300799",  # ~year 9999 epoch, interval end overflows
        "@99999999999999999999",  # epoch too large for C int
    ],
)
def test_out_of_range_rejected(archivers, request, invalid_expr):
    """Out-of-range patterns produce a clean CommandError, not a traceback."""
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    msg = rejected_date_pattern(archiver, invalid_expr)
    assert "Invalid date pattern" in msg
    assert invalid_expr in msg


@pytest.mark.parametrize("invalid_expr", ["2025-01-01T00:00:00.1234567Z", "@1735732800.1234567"])
def test_fractional_precision_rejected(archivers, request, invalid_expr):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    msg = rejected_date_pattern(archiver, invalid_expr)
    assert "Invalid date pattern" in msg
    assert invalid_expr in msg


@pytest.mark.parametrize("invalid_expr", ["2025\n", " 2025", "2025 "])
def test_surrounding_whitespace_rejected(archivers, request, invalid_expr):
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)

    assert "Invalid date pattern" in rejected_date_pattern(archiver, invalid_expr)

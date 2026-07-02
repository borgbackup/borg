import pytest
from datetime import datetime, timezone

from ...helpers.time import safe_ns, safe_s, safe_timestamp, SUPPORT_32BIT_PLATFORMS, calculate_relative_offset
from ...helpers.time import format_time, format_time_ns, OutputTimestamp


def utcfromtimestamp(timestamp):
    """Return a naive datetime instance representing the timestamp in the UTC time zone."""
    return datetime.fromtimestamp(timestamp, timezone.utc).replace(tzinfo=None)


def test_safe_timestamps():
    if SUPPORT_32BIT_PLATFORMS:
        # Nanoseconds fitting into int64.
        assert safe_ns(2**64) <= 2**63 - 1
        assert safe_ns(-1) == 0
        # Seconds fitting into int32.
        assert safe_s(2**64) <= 2**31 - 1
        assert safe_s(-1) == 0
        # datetime will not stumble over its Y10K problem.
        beyond_y10k = 2**100
        with pytest.raises(OverflowError):
            utcfromtimestamp(beyond_y10k)
        assert utcfromtimestamp(safe_s(beyond_y10k)) > datetime(2038, 1, 1)
        assert utcfromtimestamp(safe_ns(beyond_y10k) / 1000000000) > datetime(2038, 1, 1)
    else:
        # Nanoseconds fitting into int64.
        assert safe_ns(2**64) <= 2**63 - 1
        assert safe_ns(-1) == 0
        # Seconds are limited so that their ns conversion fits into int64.
        assert safe_s(2**64) * 1000000000 <= 2**63 - 1
        assert safe_s(-1) == 0
        # datetime will not stumble over its Y10K problem.
        beyond_y10k = 2**100
        with pytest.raises(OverflowError):
            utcfromtimestamp(beyond_y10k)
        assert utcfromtimestamp(safe_s(beyond_y10k)) > datetime(2262, 1, 1)
        assert utcfromtimestamp(safe_ns(beyond_y10k) / 1000000000) > datetime(2262, 1, 1)


def test_calculate_relative_offset_year_from_leap_day():
    # regression test for #9967: year offset from Feb 29 must not crash on non-leap target year.
    leap_day = datetime(2024, 2, 29, tzinfo=timezone.utc)
    assert calculate_relative_offset("1y", leap_day, earlier=False) == datetime(2025, 2, 28, tzinfo=timezone.utc)
    assert calculate_relative_offset("1y", leap_day, earlier=True) == datetime(2023, 2, 28, tzinfo=timezone.utc)
    # target year is also a leap year -> keep Feb 29.
    assert calculate_relative_offset("4y", leap_day, earlier=False) == datetime(2028, 2, 29, tzinfo=timezone.utc)


def test_calculate_relative_offset_year_regular():
    ts = datetime(2024, 6, 15, 12, 30, 45, tzinfo=timezone.utc)
    assert calculate_relative_offset("2y", ts, earlier=False) == datetime(2026, 6, 15, 12, 30, 45, tzinfo=timezone.utc)
    assert calculate_relative_offset("2y", ts, earlier=True) == datetime(2022, 6, 15, 12, 30, 45, tzinfo=timezone.utc)


def test_format_time_ns():
    ns = 1000000000_000123_456
    ts = safe_timestamp(ns)
    result = format_time_ns(ts, ns)
    # full nanosecond precision fraction, otherwise identical to format_time's output
    assert result.replace(".000123456", "") == format_time(ts)


def test_output_timestamp_ns_isoformat():
    ns = 1000000000_000123_456
    ots = OutputTimestamp(safe_timestamp(ns), ns=ns)
    iso = ots.isoformat()
    # full nanosecond precision fraction, otherwise identical to the seconds-precision isoformat
    assert iso.replace(".000123456", "") == safe_timestamp(ns).astimezone().isoformat(timespec="seconds")
    assert ots.to_json() == iso


def test_output_timestamp_without_ns_isoformat():
    ns = 1000000000_000123_456
    ots = OutputTimestamp(safe_timestamp(ns))  # no ns given
    assert ots.isoformat() == safe_timestamp(ns).astimezone().isoformat(timespec="microseconds")

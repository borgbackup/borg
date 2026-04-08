import pytest
from datetime import datetime, timezone, timedelta

from ...helpers.time import safe_ns, safe_s, SUPPORT_32BIT_PLATFORMS, format_timestamp_pair


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


def test_format_timestamp_pair_different_seconds():
    """When timestamps differ at second level, use second-precision format."""
    ts1 = datetime(2025, 11, 5, 17, 45, 53, 123456, tzinfo=timezone.utc)
    ts2 = datetime(2025, 11, 5, 17, 45, 54, 123456, tzinfo=timezone.utc)
    s1, s2 = format_timestamp_pair(ts1, ts2)
    # Must NOT contain a dot (no microseconds shown)
    assert "." not in s1
    assert "." not in s2
    # Must differ
    assert s1 != s2


def test_format_timestamp_pair_same_second_different_microsecond():
    """When timestamps look equal at second resolution but differ in microseconds,
    use microsecond-precision format so the difference is visible."""
    ts1 = datetime(2025, 11, 5, 17, 45, 53, 123, tzinfo=timezone.utc)
    ts2 = datetime(2025, 11, 5, 17, 45, 53, 456, tzinfo=timezone.utc)
    s1, s2 = format_timestamp_pair(ts1, ts2)
    # Must contain a dot (microseconds shown)
    assert "." in s1
    assert "." in s2
    # Must differ
    assert s1 != s2


def test_format_timestamp_pair_identical():
    """When timestamps are completely identical, use second-precision format."""
    ts = datetime(2025, 11, 5, 17, 45, 53, 0, tzinfo=timezone.utc)
    s1, s2 = format_timestamp_pair(ts, ts)
    assert "." not in s1
    assert s1 == s2

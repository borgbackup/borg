import pytest
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from ...helpers.time import safe_ns, safe_s, SUPPORT_32BIT_PLATFORMS, FlexibleDelta


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


def test_flexible_delta():
    # Year delta across leap year
    delta_1year = FlexibleDelta.parse("1y")
    dt_2023 = datetime(year=2023, month=12, day=24)
    assert delta_1year.add_to(dt_2023) == datetime(year=2024, month=12, day=23)
    assert delta_1year.add_to(dt_2023, calendar=True) == datetime(year=2024, month=12, day=24)
    assert delta_1year.subtract_from(dt_2023) == datetime(year=2022, month=12, day=24)
    assert delta_1year.subtract_from(dt_2023, calendar=True) == datetime(year=2022, month=12, day=24)

    delta_1month = FlexibleDelta.parse("1m")

    # Month delta across leap day
    dt_leap_february = datetime(year=2024, month=2, day=20)
    assert delta_1month.add_to(dt_leap_february) == datetime(year=2024, month=3, day=22)
    assert delta_1month.add_to(dt_leap_february, calendar=True) == datetime(year=2024, month=3, day=20)
    assert delta_1month.subtract_from(dt_leap_february) == datetime(year=2024, month=1, day=20)
    assert delta_1month.subtract_from(dt_leap_february, calendar=True) == datetime(year=2024, month=1, day=20)

    # Month delta across non-leap day February
    dt_nonleap_february = datetime(year=2025, month=2, day=20)
    assert delta_1month.add_to(dt_nonleap_february) == datetime(year=2025, month=3, day=23)
    assert delta_1month.add_to(dt_nonleap_february, calendar=True) == datetime(year=2025, month=3, day=20)

    # Month delta across 31-day month boundary
    dt_july = datetime(year=2025, month=7, day=20)
    assert delta_1month.add_to(dt_july) == datetime(year=2025, month=8, day=20)
    assert delta_1month.add_to(dt_july, calendar=True) == datetime(year=2025, month=8, day=20)

    # Month delta across 30-day month boundary
    dt_july = datetime(year=2025, month=6, day=20)
    assert delta_1month.add_to(dt_july) == datetime(year=2025, month=7, day=21)
    assert delta_1month.add_to(dt_july, calendar=True) == datetime(year=2025, month=7, day=20)

    # Day delta across summe/winter time change
    delta_1day = FlexibleDelta.parse("1d")
    dt_oslo_wintertime = datetime(year=2026, month=3, day=28, hour=10, tzinfo=ZoneInfo("Europe/Oslo"))
    assert delta_1day.add_to(dt_oslo_wintertime) == datetime(
        year=2026, month=3, day=29, hour=10, tzinfo=ZoneInfo("Europe/Oslo")
    )
    assert delta_1day.add_to(dt_oslo_wintertime, calendar=True) == datetime(
        year=2026, month=3, day=29, hour=10, tzinfo=ZoneInfo("Europe/Oslo")
    )

    # Fuzzy day delta
    delta_fuzzy_1day = FlexibleDelta.parse("1dz", fuzzyable=True)
    dt = datetime(year=2026, month=1, day=1, hour=12)
    assert delta_fuzzy_1day.add_to(dt) == datetime(year=2026, month=1, day=3, hour=0)  # +1day -> end of day
    assert delta_fuzzy_1day.subtract_from(dt) == datetime(year=2025, month=12, day=31, hour=0)  # -1day -> start of day

    # Fuzzy month delta
    delta_fuzzy_1month = FlexibleDelta.parse("1mz", fuzzyable=True)
    dt = datetime(year=2026, month=1, day=30)
    assert delta_fuzzy_1month.add_to(dt) == datetime(
        year=2026, month=4, day=1
    )  # End of next month (31 days) (for inclusive check, ie. +1μs)
    assert delta_fuzzy_1month.add_to(dt, calendar=True) == datetime(
        year=2026, month=3, day=1
    )  # End of next month (for inclusive check, ie. +1μs)
    assert delta_fuzzy_1month.subtract_from(dt) == datetime(year=2025, month=12, day=1)  # Start of previous month

    # Fuzzy week delta
    delta_fuzzy_1week = FlexibleDelta.parse("1wz", fuzzyable=True)
    dt = datetime(year=2024, month=2, day=28)  # A Wednesday, leap year
    assert delta_fuzzy_1week.add_to(dt) == datetime(
        year=2024, month=3, day=11
    )  # End of next week (for inclusive check, ie. +1μs)
    assert delta_fuzzy_1week.add_to(dt, calendar=True) == datetime(
        year=2024, month=3, day=11
    )  # End of next week (for inclusive check, ie. +1μs)
    assert delta_fuzzy_1week.subtract_from(dt) == datetime(year=2024, month=2, day=19)  # Start of previous week

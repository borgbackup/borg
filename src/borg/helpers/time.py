import os
import re
from datetime import datetime, timezone, timedelta
from dateutil.relativedelta import relativedelta, MO


def parse_timestamp(timestamp, tzinfo=timezone.utc):
    """Parse an ISO 8601 timestamp string.

    For naive/unaware datetime objects, assume they are in the tzinfo timezone (default: UTC).
    """
    dt = datetime.fromisoformat(timestamp)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=tzinfo)
    return dt


def parse_local_timestamp(timestamp, tzinfo=None):
    """Parse an ISO 8601 timestamp string.

    For naive/unaware datetime objects, assume the local timezone.
    Convert to the tzinfo timezone (the default None means: local timezone).
    """
    dt = datetime.fromisoformat(timestamp)
    if dt.tzinfo is None:
        dt = dt.astimezone(tz=tzinfo)
    return dt


def timestamp(s):
    """Convert a --timestamp=s argument to a datetime object."""
    try:
        # is it pointing to a file / directory?
        ts = safe_s(os.stat(s).st_mtime)
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except OSError:
        # didn't work, try parsing as an ISO timestamp. if no TZ is given, we assume local timezone.
        return parse_local_timestamp(s)


# Not too rarely, we get crappy timestamps from the fs, that overflow some computations.
# As they are crap anyway (valid filesystem timestamps always refer to the past up to
# the present, but never to the future), nothing is lost if we just clamp them to the
# maximum value we can support.
# As long as people are using borg on 32bit platforms to access borg archives, we must
# keep this value True. But we can expect that we can stop supporting 32bit platforms
# well before coming close to the year 2038, so this will never be a practical problem.
SUPPORT_32BIT_PLATFORMS = True  # set this to False before y2038.

if SUPPORT_32BIT_PLATFORMS:
    # second timestamps will fit into a signed int32 (platform time_t limit).
    # nanosecond timestamps thus will naturally fit into a signed int64.
    # subtract last 48h to avoid any issues that could be caused by tz calculations.
    # this is in the year 2038, so it is also less than y9999 (which is a datetime internal limit).
    # msgpack can pack up to uint64.
    MAX_S = 2**31 - 1 - 48 * 3600
    MAX_NS = MAX_S * 1000000000
else:
    # nanosecond timestamps will fit into a signed int64.
    # subtract last 48h to avoid any issues that could be caused by tz calculations.
    # this is in the year 2262, so it is also less than y9999 (which is a datetime internal limit).
    # round down to 1e9 multiple, so MAX_NS corresponds precisely to a integer MAX_S.
    # msgpack can pack up to uint64.
    MAX_NS = (2**63 - 1 - 48 * 3600 * 1000000000) // 1000000000 * 1000000000
    MAX_S = MAX_NS // 1000000000


def safe_s(ts):
    if 0 <= ts <= MAX_S:
        return ts
    elif ts < 0:
        return 0
    else:
        return MAX_S


def safe_ns(ts):
    if 0 <= ts <= MAX_NS:
        return ts
    elif ts < 0:
        return 0
    else:
        return MAX_NS


def safe_timestamp(item_timestamp_ns):
    t_ns = safe_ns(item_timestamp_ns)
    return datetime.fromtimestamp(t_ns / 1e9, timezone.utc)  # return tz-aware utc datetime obj


def format_time(ts: datetime, format_spec=""):
    """
    Convert *ts* to a human-friendly format with textual weekday (in local timezone).
    """
    return ts.astimezone().strftime("%a, %Y-%m-%d %H:%M:%S %z" if format_spec == "" else format_spec)


def format_timedelta(td):
    """Format a timedelta in a human-friendly format."""
    ts = td.total_seconds()
    s = ts % 60
    m = int(ts / 60) % 60
    h = int(ts / 3600) % 24
    txt = "%.3f seconds" % s
    if m:
        txt = "%d minutes %s" % (m, txt)
    if h:
        txt = "%d hours %s" % (h, txt)
    if td.days:
        txt = "%d days %s" % (td.days, txt)
    return txt


class FlexibleDelta:
    """
    Represents an interval that _may_ respect the calendar with relation to week boundaries and exact month lengths.
    """

    _unit_relativedelta_map = {
        "y": lambda count: relativedelta(years=count),
        "m": lambda count: relativedelta(months=count),
        "w": lambda count: relativedelta(weeks=count),
        "d": lambda count: relativedelta(days=count),
        "H": lambda count: relativedelta(hours=count),
        "M": lambda count: relativedelta(minutes=count),
        "S": lambda count: relativedelta(seconds=count),
    }

    _unit_timedelta_map = {
        "y": lambda count: timedelta(days=count * 365),
        "m": lambda count: timedelta(days=count * 31),
        "w": lambda count: timedelta(weeks=count),
        "d": lambda count: timedelta(days=count),
        "H": lambda count: timedelta(hours=count),
        "M": lambda count: timedelta(minutes=count),
        "S": lambda count: timedelta(seconds=count),
    }

    _unit_fuzzy_round_func_map = {
        "y": lambda earlier: relativedelta(
            years=0 if earlier else 1, month=1, day=1, hour=0, minute=0, second=0, microsecond=0
        ),
        "m": lambda earlier: relativedelta(
            months=0 if earlier else 1, day=1, hour=0, minute=0, second=0, microsecond=0
        ),
        "w": lambda earlier: relativedelta(
            weekday=MO(-1), weeks=(0 if earlier else 1), hour=0, minute=0, second=0, microsecond=0
        ),
        "d": lambda earlier: relativedelta(days=0 if earlier else 1, hour=0, minute=0, second=0, microsecond=0),
        "H": lambda earlier: relativedelta(hours=0 if earlier else 1, minute=0, second=0, microsecond=0),
        "M": lambda earlier: relativedelta(minutes=0 if earlier else 1, second=0, microsecond=0),
        "S": lambda earlier: relativedelta(seconds=0 if earlier else 1, microsecond=0),
    }

    def __init__(self, count, unit, fuzzy):
        self.relativedelta = self._unit_relativedelta_map[unit](count)
        self.timedelta = self._unit_timedelta_map[unit](count)
        self.fuzzy_round_func = self._unit_fuzzy_round_func_map[unit]
        self.fuzzy = fuzzy

        # For repr
        self.count = count
        self.unit = unit

    def __repr__(self):
        return f'{self.__class__.__name__}(count={self.count}, unit="{self.unit}", fuzzy={self.fuzzy})'

    _interval_regex = re.compile(r"^(?P<count>\d+)(?P<unit>[ymwdHMS])(?P<fuzzy>z)?$")

    @classmethod
    def parse(cls, interval_string, fuzzyable=False):
        """
        Parse interval string into
        """
        match = cls._interval_regex.search(interval_string)

        if not match:
            raise ValueError(f"Invalid interval format: {interval_string}")

        count = int(match.group("count"))
        unit = match.group("unit")
        fuzzy = fuzzyable and match.group("fuzzy") is not None

        return cls(count, unit, fuzzy)

    @classmethod
    def parse_fuzzy(cls, interval_string):
        """
        Convenience fuzzy parser for easy use with argparse
        """
        return cls.parse(interval_string, fuzzyable=True)

    def apply(self, base_ts, earlier=False, calendar=False):
        scale = -1 if earlier else 1
        delta = self.relativedelta if calendar else self.timedelta

        offset_ts = base_ts + delta * scale

        if self.fuzzy:
            # Offset further so that timestamp represents the start/end of its unit. e.g. "1yz" rounds result either up
            # or down to nearest full year after applying initial offset (2025-07-31 - "1yz" = 2024-01-01).
            offset_ts += self.fuzzy_round_func(earlier)

        return offset_ts

    def add_to(self, base_ts, calendar=False):
        return self.apply(base_ts, earlier=False, calendar=calendar)

    def subtract_from(self, base_ts, calendar=False):
        return self.apply(base_ts, earlier=True, calendar=calendar)


def calculate_relative_offset(format_string, from_ts, earlier=False):
    """
    Calculate an offset based on a relative marker (e.g., 7d for 7 days, 8m for 8 months).

    earlier indicates whether the offset should be applied towards an earlier time.
    """
    if from_ts is None:
        from_ts = archive_ts_now()

    return FlexibleDelta.parse(format_string).apply(from_ts, earlier=earlier, calendar=True)


def offset_n_months(from_ts, n_months):
    def get_month_and_year_from_total(total_completed_months):
        month = (total_completed_months % 12) + 1
        year = total_completed_months // 12
        return month, year

    # Calculate target month and year by getting completed total_months until target_month
    total_months = (from_ts.year * 12) + from_ts.month + n_months - 1
    target_month, target_year = get_month_and_year_from_total(total_months)

    # calculate the max days of the target month by subtracting a day from the next month
    following_month, year_of_following_month = get_month_and_year_from_total(total_months + 1)
    max_days_in_month = (datetime(year_of_following_month, following_month, 1) - timedelta(1)).day

    return datetime(day=min(from_ts.day, max_days_in_month), month=target_month, year=target_year).replace(
        tzinfo=from_ts.tzinfo
    )


class OutputTimestamp:
    def __init__(self, ts: datetime):
        self.ts = ts

    def __format__(self, format_spec):
        # we want to output a timestamp in the user's local timezone
        return format_time(self.ts.astimezone(), format_spec=format_spec)

    def __str__(self):
        return self.isoformat()

    def isoformat(self):
        # we want to output a timestamp in the user's local timezone
        return self.ts.astimezone().isoformat(timespec="microseconds")

    to_json = isoformat


def archive_ts_now():
    """return tz-aware datetime obj for current time for usage as archive timestamp"""
    return datetime.now(timezone.utc)  # utc time / utc timezone

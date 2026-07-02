import os
import re
from datetime import UTC, datetime, timedelta, timezone
from zoneinfo import ZoneInfo


def parse_timestamp(timestamp, tzinfo=UTC):
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


_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def utcfromtimestampns(ts_ns: int) -> datetime:
    # similar to datetime.fromtimestamp, but works with ns and avoids floating point.
    # also, it would avoid an overflow on 32bit platforms with old glibc.
    return _EPOCH + timedelta(microseconds=ts_ns // 1000)


def timestamp(s):
    """Convert a --timestamp=s argument to a datetime object."""
    if isinstance(s, datetime):
        return s
    try:
        # is it pointing to a file / directory?
        ts_ns = safe_ns(os.stat(s).st_mtime_ns)
        return utcfromtimestampns(ts_ns)
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
SUPPORT_32BIT_PLATFORMS = False  # set this to False before y2038.

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
    return utcfromtimestampns(t_ns)  # return tz-aware utc datetime obj


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


def calculate_relative_offset(format_string, from_ts, earlier=False):
    """
    Calculate an offset based on a relative marker (e.g., 7d for 7 days, 8m for 8 months).

    earlier indicates whether the offset should be applied towards an earlier time.
    """
    if from_ts is None:
        from_ts = archive_ts_now()

    if format_string is not None:
        offset_regex = re.compile(r"(?P<offset>\d+)(?P<unit>[ymwdHMS])")
        match = offset_regex.search(format_string)

        if match:
            unit = match.group("unit")
            offset = int(match.group("offset"))
            offset *= -1 if earlier else 1

            match unit:
                case "y":
                    return from_ts.replace(year=from_ts.year + offset)
                case "m":
                    return offset_n_months(from_ts, offset)
                case "w":
                    return from_ts + timedelta(days=offset * 7)
                case "d":
                    return from_ts + timedelta(days=offset)
                case "H":
                    return from_ts + timedelta(seconds=offset * 60 * 60)
                case "M":
                    return from_ts + timedelta(seconds=offset * 60)
                case "S":
                    return from_ts + timedelta(seconds=offset)

    raise ValueError(f"Invalid relative ts offset format: {format_string}")


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
    return datetime.now(UTC)  # utc time / utc timezone


class DatePatternError(ValueError):
    """Raised when a date: archive pattern cannot be parsed."""


def date_match_exact(dt: datetime):
    """Return predicate matching archives whose timestamp equals dt."""
    dt_utc = dt.astimezone(UTC)
    return lambda ts: ts.astimezone(UTC) == dt_utc


def date_match_interval(start: datetime, end: datetime):
    """Return predicate matching archives in the start-inclusive, end-exclusive interval."""
    start_utc = start.astimezone(UTC)
    end_utc = end.astimezone(UTC)
    return lambda ts: start_utc <= ts.astimezone(UTC) < end_utc


def parse_date_pattern_tz(tzstr: str):
    """Parse a date: pattern timezone suffix."""
    if not tzstr:
        return None
    if tzstr == "Z":
        return UTC
    if tzstr[0] in "+-":
        sign = 1 if tzstr[0] == "+" else -1
        try:
            hh, mm = map(int, tzstr[1:].split(":"))
            if not (0 <= hh <= 23 and 0 <= mm < 60):
                raise ValueError
        except ValueError:
            raise DatePatternError("invalid UTC offset format")
        total_minutes = sign * (hh * 60 + mm)
        if not (-12 * 60 <= total_minutes <= 14 * 60):
            raise DatePatternError("UTC offset outside ISO-8601 bounds")
        return timezone(timedelta(minutes=total_minutes))
    if tzstr.startswith("[") and tzstr.endswith("]"):
        try:
            return ZoneInfo(tzstr[1:-1])
        except Exception:
            raise DatePatternError("invalid timezone format")
    raise DatePatternError("invalid timezone format")


DATE_PATTERN_RE = r"""
  ^
  (?:
     @(?P<epoch>\d+)(?:\.(?P<epoch_fraction>\d{1,6}))?
   |
     (?P<year>\d{4})
     (?:
         -(?P<month>\d{2})
         (?:
             -(?P<day>\d{2})
             (?:
                 T(?P<hour>\d{2})
                 (?:
                     :(?P<minute>\d{2})
                     (?:
                         :(?P<second>\d{2})(?:\.(?P<fraction>\d{1,6}))?
                     )?
                 )?
             )?
         )?
     )?
  )
  (?P<tz>Z|[+\-]\d\d:\d\d|\[[^]]+\])?
  $
"""


def build_date_pattern_datetime(groups: dict, tz) -> datetime:
    """Build the earliest datetime represented by a date: pattern."""
    second = 0
    microsecond = 0
    if groups.get("second"):
        second = int(groups["second"])
    if groups.get("fraction"):
        microsecond = int((groups["fraction"] + "000000")[:6])
    try:
        return datetime(
            year=int(groups["year"]),
            month=int(groups.get("month") or 1),
            day=int(groups.get("day") or 1),
            hour=int(groups.get("hour") or 0),
            minute=int(groups.get("minute") or 0),
            second=second,
            microsecond=microsecond,
            tzinfo=tz,
        )
    except ValueError as exc:
        raise DatePatternError(str(exc))


def parse_date_pattern_interval(expr: str) -> tuple[datetime, datetime]:
    """Parse a static date: pattern into the interval it represents."""
    match = re.match(DATE_PATTERN_RE, expr, re.VERBOSE)
    if not match:
        raise DatePatternError(f"unrecognised date: {expr!r}")

    groups = match.groupdict()
    tz = parse_date_pattern_tz(groups["tz"])

    if groups["epoch"] and groups["tz"]:
        raise DatePatternError("Unix timestamps must not have timezone suffixes")

    try:
        if groups["epoch"]:
            if groups["epoch_fraction"]:
                start = _EPOCH + timedelta(
                    seconds=int(groups["epoch"]), microseconds=int((groups["epoch_fraction"] + "000000")[:6])
                )
                return start, start
            start = _EPOCH + timedelta(seconds=int(groups["epoch"]))
            return start, start + timedelta(seconds=1)

        start = build_date_pattern_datetime(groups, tz)
        if groups["second"]:
            if groups["fraction"]:
                return start, start
            return start, start + timedelta(seconds=1)
        if groups["minute"]:
            return start, start + timedelta(minutes=1)
        if groups["hour"]:
            return start, start + timedelta(hours=1)
        if groups["day"]:
            return start, start + timedelta(days=1)
        if groups["month"]:
            return start, offset_n_months(start, 1)
        return start, offset_n_months(start, 12)
    except (ValueError, OverflowError) as exc:
        raise DatePatternError(str(exc))


def compile_date_pattern(expr: str):
    """
    Compile a date: archive match expression into a timestamp predicate.

    Supported expressions are static calendar timestamps from year to fractional-second precision,
    optional timezone suffixes (Z, +/-HH:MM, or [Region/City]), and Unix epoch timestamps prefixed with @.
    """
    expr = expr.strip()
    start, end = parse_date_pattern_interval(expr)
    if start == end:
        return date_match_exact(start)
    return date_match_interval(start, end)

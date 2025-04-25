import os
import re
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo


def parse_timestamp(timestamp, tzinfo=timezone.utc):
    """Parse a ISO 8601 timestamp string.

    For naive/unaware dt, assume it is in tzinfo timezone (default: UTC).
    """
    dt = datetime.fromisoformat(timestamp)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=tzinfo)
    return dt


def parse_local_timestamp(timestamp, tzinfo=None):
    """Parse a ISO 8601 timestamp string.

    For naive/unaware dt, assume it is in local timezone.
    Convert to tzinfo timezone (the default None means: local timezone).
    """
    dt = datetime.fromisoformat(timestamp)
    if dt.tzinfo is None:
        dt = dt.astimezone(tz=tzinfo)
    return dt


def timestamp(s):
    """Convert a --timestamp=s argument to a datetime object"""
    try:
        # is it pointing to a file / directory?
        ts = safe_s(os.stat(s).st_mtime)
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except OSError:
        # didn't work, try parsing as a ISO timestamp. if no TZ is given, we assume local timezone.
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
    Convert *ts* to a human-friendly format with textual weekday.
    """
    return ts.strftime("%a, %Y-%m-%d %H:%M:%S %z" if format_spec == "" else format_spec)


def format_timedelta(td):
    """Format timedelta in a human friendly format"""
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
    Calculates offset based on a relative marker. 7d (7 days), 8m (8 months)
    earlier: whether offset should be calculated to an earlier time.
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

            if unit == "y":
                return from_ts.replace(year=from_ts.year + offset)
            elif unit == "m":
                return offset_n_months(from_ts, offset)
            elif unit == "w":
                return from_ts + timedelta(days=offset * 7)
            elif unit == "d":
                return from_ts + timedelta(days=offset)
            elif unit == "H":
                return from_ts + timedelta(seconds=offset * 60 * 60)
            elif unit == "M":
                return from_ts + timedelta(seconds=offset * 60)
            elif unit == "S":
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
        return f"{self}"

    def isoformat(self):
        # we want to output a timestamp in the user's local timezone
        return self.ts.astimezone().isoformat(timespec="microseconds")

    to_json = isoformat


def archive_ts_now():
    """return tz-aware datetime obj for current time for usage as archive timestamp"""
    return datetime.now(timezone.utc)  # utc time / utc timezone


class DatePatternError(ValueError):
    """Raised when a date: archive pattern cannot be parsed."""


def exact_predicate(dt: datetime):
    """Return predicate matching archives whose ts equals dt (UTC)."""
    dt_utc = dt.astimezone(timezone.utc)
    return lambda ts: ts.astimezone(timezone.utc) == dt_utc


def interval_predicate(start: datetime, end: datetime):
    start_utc = start.astimezone(timezone.utc)
    end_utc = end.astimezone(timezone.utc)
    return lambda ts: start_utc <= ts.astimezone(timezone.utc) < end_utc


def parse_tz(tzstr: str):
    """
    Parses a UTC offset like +08:00 or [Region/Name] into a timezone object.
    """
    if not tzstr:
        return None
    if tzstr == "Z":
        return timezone.utc
    if tzstr[0] in "+-":
        sign = 1 if tzstr[0] == "+" else -1
        try:
            hh, mm = map(int, tzstr[1:].split(":"))
            if not (0 <= mm < 60):
                raise ValueError
        except Exception:
            raise DatePatternError("invalid UTC offset format")
        # we do it this way so that, for example, -8:30 is
        # -8 hours and -30 minutes, not -8 hours and +30 minutes
        total_minutes = sign * (hh * 60 + mm)
        # enforce ISO-8601 bounds (-12:00 to +14:00)
        if not (-12 * 60 <= total_minutes <= 14 * 60):
            raise DatePatternError("UTC offset outside ISO-8601 bounds")
        return timezone(timedelta(minutes=total_minutes))
    # [Region/Name]
    try:
        return ZoneInfo(tzstr.strip("[]"))
    except Exception:
        raise DatePatternError("invalid timezone format")


def _build_datetime_from_groups(gd: dict, tz: timezone) -> datetime:
    """
    Construct a datetime from partial ISO groups, filling missing fields with
    the earliest valid value, and attaching tzinfo.
    """
    year = int(gd["year"])
    month = int(gd.get("month") or 1)
    day = int(gd.get("day") or 1)
    hour = int(gd.get("hour") or 0)
    minute = int(gd.get("minute") or 0)
    # handle fractional seconds
    microsecond = 0
    second = 0
    sec_str = gd.get("second")
    if sec_str:
        if "." in sec_str:
            whole, frac = sec_str.split(".", 1)
            second = int(whole)
            # pad or trim frac to microseconds
            microsecond = int(float(f"0.{frac}") * 1_000_000)
        else:
            second = int(sec_str)
    return datetime(year, month, day, hour, minute, second, microsecond, tzinfo=tz)


pattern = r"""
  ^
  (?:
     @(?P<epoch>\d+)                      # unix epoch
   | (?P<year>   \d{4}|\*)                # year (YYYY or *)
     (?:-(?P<month>  \d{2}|\*)            # month (MM or *)
        (?:-(?P<day>    \d{2}|\*)         # day (DD or *)
           (?:[T ](?P<hour>   \d{2}|\*)   # hour (HH or *)
             (?::(?P<minute>\d{2}|\*)     # minute (MM or *)
               (?::(?P<second>\d{2}(?:\.\d+)?|\*))?  # second (SS or SS.fff or *)
             )?
           )?
        )?
     )?
  )
  (?P<tz>Z|[+\-]\d\d:\d\d|\[[^\]]+\])?    # optional timezone suffix
  $
"""


def _parse_to_interval(expr: str) -> tuple[datetime, datetime]:
    """
    Parse a possibly incomplete ISO-8601 timestamp (with optional timezone) into
    a start and end datetime representing the full interval.
    """
    # note: we match the same pattern that supports wildcards, but at the point this function is called,
    #       we know that the pattern contains no wildcards. This is to allow us to reuse the same regex.
    m = re.match(pattern, expr, re.VERBOSE)
    if not m:
        raise DatePatternError(f"unrecognised date: {expr!r}")
    gd = m.groupdict()
    # handle unix-epoch forms directly
    if gd["epoch"]:
        epoch = int(gd["epoch"])
        start = datetime.fromtimestamp(epoch, tz=timezone.utc)
        end = start + timedelta(seconds=1)
        return start, end

    tz = parse_tz(gd["tz"])
    # build the start moment
    start = _build_datetime_from_groups(gd, tz)
    # determine the end moment based on the highest precision present
    if gd["second"]:
        # fractional or whole second precision
        end = start + timedelta(seconds=1)
    elif gd["minute"]:
        end = start + timedelta(minutes=1)
    elif gd["hour"]:
        end = start + timedelta(hours=1)
    elif gd["day"]:
        end = start + timedelta(days=1)
    elif gd["month"]:
        end = offset_n_months(start, 1)
    elif gd["year"]:
        end = offset_n_months(start, 12)
    else:
        # fallback to one-second window (shouldn't occur)
        end = start + timedelta(seconds=1)
    return start, end


def compile_date_pattern(expr: str):
    """
    Accepts any of:
      YYYY
      YYYY-MM
      YYYY-MM-DD
      YYYY-MM-DDTHH
      YYYY-MM-DDTHH:MM
      YYYY-MM-DDTHH:MM:SS
      Unix epoch (@123456789)
    …with an optional trailing timezone (Z or ±HH:MM or [Region/City]).
    Additionally supports wildcards (`*`) in year, month, or day (or any combination), e.g.:
      "*-04-22"       # April 22 of any year
      "2025-*-01"     # 1st day of any month in 2025
      "*-*-15"        # 15th of every month, any year
    Returns a predicate that is True for timestamps in that interval.
    """
    expr = expr.strip()

    # 1) detect explicit user-defined intervals (split slash outside brackets to allow for [Region/Name])
    parts = re.split(r"/(?![^\[]*\])", expr, maxsplit=1)
    if len(parts) == 2:
        left, right = parts
        start_left, _ = _parse_to_interval(left)
        # use the start here to make it an exclusive upper bound, for behavior consistent with
        # the rest of the date pattern matching
        start_right, _ = _parse_to_interval(right)
        return interval_predicate(start_left, start_right)
    m = re.match(pattern, expr, re.VERBOSE)
    if not m:
        raise DatePatternError(f"unrecognised date: {expr!r}")

    gd = m.groupdict()
    tz = parse_tz(gd["tz"])

    # 2) detect explicit wildcards (*) in any named group
    wildcard_fields = ("year", "month", "day", "hour", "minute", "second")
    if any(gd[f] == "*" for f in wildcard_fields if f in gd):
        # build a discrete‐match predicate
        yi = None if gd["year"] == "*" else int(gd["year"])
        mi = None if gd["month"] == "*" else int(gd["month"]) if gd["month"] else None
        di = None if gd["day"] == "*" else int(gd["day"]) if gd["day"] else None
        hi = None if gd["hour"] == "*" else int(gd["hour"]) if gd["hour"] else None
        ni = None if gd["minute"] == "*" else int(gd["minute"]) if gd["minute"] else None
        si = None
        if gd["second"]:
            if gd["second"] != "*":
                si = float(gd["second"])

        def wildcard_pred(ts):
            dt = ts.astimezone(tz)
            return (
                (yi is None or dt.year == yi)
                and (mi is None or dt.month == mi)
                and (di is None or dt.day == di)
                and (hi is None or dt.hour == hi)
                and (ni is None or dt.minute == ni)
                and (si is None or (si <= dt.second + dt.microsecond / 1e6 < si + 1))
            )

        return wildcard_pred

    # 3) fraction‐precision exact match
    if gd["second"] and "." in gd["second"]:
        dt = _build_datetime_from_groups(gd, tz)
        return exact_predicate(dt)

    # 4) remaining precisions: use _parse_to_interval to get start/end
    start, end = _parse_to_interval(expr)
    return interval_predicate(start, end)

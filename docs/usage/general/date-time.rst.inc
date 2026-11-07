Date and Time
~~~~~~~~~~~~~

We format date and time in accordance with ISO 8601, that is: YYYY-MM-DD and
HH:MM:SS (24-hour clock).

For more information, see: https://xkcd.com/1179/

Unless otherwise noted, we display local date and time.
Internally, we store and process date and time as UTC.


.. rubric:: TIMESPAN / INTERVAL

Some options accept a TIMESPAN or an INTERVAL parameter, which can be given as
a number of years (e.g. ``2y``), months (e.g. ``12m``), weeks (e.g. ``2w``),
days (e.g. ``7d``), hours (e.g. ``8H``), minutes (e.g. ``30M``), or seconds
(e.g. ``150S``).

Weeks, days, hours, minutes, and seconds have fixed lengths. For example,
``1w`` is 7 days and ``1d`` is ``86400S``. Months and years are interpreted
relative to a reference timestamp. ``1m`` can be shorter than, equal to,
or longer than ``30d``. ``1y`` spans 365 or 366 days and always matches
12 months.

Months and years follow the calendar. For example, ``12m`` before
2026-07-22 is 2025-07-22. ``3y`` before 2026-07-22 is 2023-07-22.
The time of day is preserved. If the target month has fewer days, the date
is clamped to its last day. One month before 2024-03-31 is 2024-02-29.
One year before 2024-02-29 is 2023-02-28.

The ``borg prune`` ``--keep-*`` retention options accept either a plain count
(e.g. ``--keep-daily 7``, keeping up to 7 daily archives) or a time interval
(e.g. ``--keep-daily 7d``, keeping one daily archive per day within a 7-day window).
When using interval-based retention, ``--from`` may be specified to set the
reference timestamp for the interval (defaults to the current time).

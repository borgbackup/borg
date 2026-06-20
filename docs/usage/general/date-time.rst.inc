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

The ``borg prune`` ``--keep-*`` retention options accept either a plain count
(e.g. ``--keep-daily 7``, keeping up to 7 daily archives) or a time interval
(e.g. ``--keep-daily 7d``, keeping one daily archive per day within a 7-day window).
When using interval-based retention, ``--from`` may be specified to set the
reference timestamp for the interval (defaults to the current time).

Please note that Borg treats months (e.g. ``12m``) as fixed 31-day periods
rather than calendar months. As a result, ``12m`` corresponds to
12 × 31 = 372 days. Similarly, years (e.g. ``2y``) are treated as fixed
365-day periods and do not take leap years into account.

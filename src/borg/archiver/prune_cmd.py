from typing import Callable, NamedTuple
from datetime import datetime, timedelta
import logging
import math
from functools import wraps
import os
from itertools import count, combinations
from ._common import with_repository, Highlander
from ..constants import *  # NOQA
from ..helpers import ArchiveFormatter, ProgressIndicatorPercent, CommandError, Error
from ..helpers import archivename_validator, int_or_interval, sig_int, timestamp
from ..helpers import json_print, basic_json_data
from ..helpers.argparsing import ArgumentParser
from ..manifest import ArchiveInfo, Manifest

from ..logger import create_logger

logger = create_logger()


class PruningRule(NamedTuple):
    key: str
    period_func: Callable[[ArchiveInfo | datetime], str]

    def __str__(self):
        return self.key


class KeepResult(NamedTuple):
    rule: PruningRule
    idx: int
    oldest: bool = False

    def __str__(self):
        return f"Keep(rule={self.rule}, idx={self.idx}{', oldest=True' if self.oldest else ''})"


def archive_datetime_dispatch(func: Callable[[datetime], str]) -> Callable[[ArchiveInfo | datetime], str]:
    """
    Wraps a datetime-taking function with a dispatcher that can call that
    function by extracting the timestamp from an archive.
    """

    @wraps(func)
    def wrapper(arg):
        if isinstance(arg, datetime):
            return func(arg)
        if isinstance(arg, ArchiveInfo):
            return func(arg.ts)
        raise TypeError(f"{func.__name__}(): expected datetime or Archive, " f"got {type(arg).__name__}")

    return wrapper


# The *_period_func group of functions create period grouping keys to group
# together archives falling within a certain period. Among archives in each of
# these groups, only the latest (by creation timestamp) is kept. The values
# returned by these functions MUST be ordered the same as the input timestamp.


def unique_period_func():
    counter = count()
    max_digits = math.ceil(math.log10(MAX_ARCHIVES))

    @archive_datetime_dispatch
    def unique_values(_dt):
        """Group archives by an incrementing counter, practically making each archive a group of 1"""
        return str(next(counter)).zfill(max_digits)

    return unique_values


def pattern_period_func(pattern):
    @archive_datetime_dispatch
    def inner(dt):
        """Group archives by extracting given strftime-pattern from their creation timestamp"""
        # compute in local timezone
        return dt.astimezone().strftime(pattern)

    return inner


@archive_datetime_dispatch
def quarterly_13weekly_period_func(dt):
    """Group archives by extracting the ISO-8601 13-week quarter from their creation timestamp"""
    (year, week) = dt.astimezone().isocalendar()[:2]  # local time
    return f"{year}-{min(max((week - 1) // 13, 0), 3):02}"


@archive_datetime_dispatch
def quarterly_3monthly_period_func(dt):
    """Group archives by extracting the 3-month quarter from their creation timestamp"""
    (year, month) = dt.astimezone().timetuple()[:2]  # local time
    return f"{year}-{(month - 1) // 3:02}"


# Each archive is considered for keeping
PRUNE_KEEP = PruningRule("keep", unique_period_func())
# Last archive (by creation timestamp) within period group is considered for keeping
PRUNE_SECONDLY = PruningRule("secondly", pattern_period_func("%Y-%m-%d %H:%M:%S"))
PRUNE_MINUTELY = PruningRule("minutely", pattern_period_func("%Y-%m-%d %H:%M"))
PRUNE_HOURLY = PruningRule("hourly", pattern_period_func("%Y-%m-%d %H"))
PRUNE_DAILY = PruningRule("daily", pattern_period_func("%Y-%m-%d"))
PRUNE_WEEKLY = PruningRule("weekly", pattern_period_func("%G-%V"))
PRUNE_MONTHLY = PruningRule("monthly", pattern_period_func("%Y-%m"))
PRUNE_QUARTERLY_13WEEKLY = PruningRule("quarterly_13weekly", quarterly_13weekly_period_func)
PRUNE_QUARTERLY_3MONTHLY = PruningRule("quarterly_3monthly", quarterly_3monthly_period_func)
PRUNE_YEARLY = PruningRule("yearly", pattern_period_func("%Y"))

# Fake rule used to indicate archives skipped by --since
PRUNE_SINCE = PruningRule("skip", unique_period_func())

PRUNING_RULES = [
    PRUNE_KEEP,
    PRUNE_SECONDLY,
    PRUNE_MINUTELY,
    PRUNE_HOURLY,
    PRUNE_DAILY,
    PRUNE_WEEKLY,
    PRUNE_MONTHLY,
    PRUNE_QUARTERLY_13WEEKLY,
    PRUNE_QUARTERLY_3MONTHLY,
    PRUNE_YEARLY,
]


def prune(
    archives: list[ArchiveInfo],
    rule: PruningRule,
    n_or_interval: int | timedelta,
    since_timestamp: datetime | None,
    keep_oldest: bool,
    previously_kept: frozenset[ArchiveInfo] = frozenset(),
) -> dict[ArchiveInfo, KeepResult]:
    if len(archives) == 0 or n_or_interval in (0, timedelta(0)):
        return {}

    if isinstance(n_or_interval, int):
        n, earliest_timestamp = n_or_interval, None
    else:
        if since_timestamp is None:
            raise ValueError("since_timestamp is required when using interval-based pruning")
        n, earliest_timestamp = None, since_timestamp - n_or_interval

    keep: dict[ArchiveInfo, KeepResult] = {}

    def can_retain(a):
        if n is not None:
            return n == -1 or len(keep) < n
        else:
            return a.ts > earliest_timestamp

    prev_period = None
    for archive in archives:
        if not can_retain(archive):
            break
        period = rule.period_func(archive)
        if period != prev_period:
            prev_period = period
            if archive not in keep and archive not in previously_kept:
                keep[archive] = KeepResult(rule=rule, idx=len(keep))

    if keep_oldest:
        # Keep oldest archive if we didn't reach the target retention.
        oldest_archive = archives[-1]
        if oldest_archive not in keep and oldest_archive not in previously_kept and can_retain(oldest_archive):
            keep[oldest_archive] = KeepResult(rule=rule, idx=len(keep), oldest=True)

    return keep


class PruneMixIn:
    @with_repository(compatibility=(Manifest.Operation.DELETE,))
    def do_prune(self, args, repository, manifest):
        """Prune archives according to specified rules."""
        self._validate_prune_args(args)

        match = [args.name] if args.name else args.match_archives
        archives = manifest.archives.list(match=match, sort_by=["ts"], reverse=True)
        archives = [ai for ai in archives if "@PROT" not in ai.tags]

        # Archives to keep along with the rule that ensured them being kept
        keep = {}

        since = getattr(args, PRUNE_SINCE.key)
        candidate_archives = archives

        if since is not None:
            # Prefilter: Archives from _after_ the `prune_since` time are skipped entirely.
            for archive in archives:
                if archive.ts <= since:
                    break
                keep[archive] = KeepResult(rule=PRUNE_SINCE, idx=len(keep))
            candidate_archives = archives[len(keep) :]

        # Apply each retention rule to all candidate archives. The
        # `previously_kept` parameter prevents later (coarser-grained) rules
        # from double-counting archives already retained by earlier rules.
        active_rules = [
            (rule, getattr(args, rule.key)) for rule in PRUNING_RULES if getattr(args, rule.key) is not None
        ]
        for rule, n_or_interval in active_rules:
            keep |= prune(
                archives=candidate_archives,
                rule=rule,
                n_or_interval=n_or_interval,
                since_timestamp=(since if since is not None else datetime.now().astimezone()),
                keep_oldest=(
                    rule == active_rules[-1][0]
                ),  # Activate keep_oldest rule only for the largest active interval
                previously_kept=frozenset(keep),
            )

        archives_to_prune = set(archives) - set(keep)

        if args.format is not None:
            format = args.format
        elif args.short:
            format = "{archive}"
        else:
            format = os.environ.get("BORG_PRUNE_FORMAT", "{archive:<36} {time} [{id}]")
        formatter = ArchiveFormatter(format, repository, manifest, manifest.key, iec=args.iec)

        if args.json:
            output_data = []
        else:
            logger.info("Repository contains %d archives.", manifest.archives.count())
            logger.info("Applying rules to the matching %d archives...", len(archives))
            logger.info("Keeping %d archives, pruning %d archives.", len(keep), len(archives_to_prune))

        list_logger = logging.getLogger("borg.output.list")
        # set up counters for the progress display
        num_archives_deleted = 0
        pi = ProgressIndicatorPercent(total=len(archives_to_prune), msg="Pruning archives %3.0f%%", msgid="prune")
        for archive_info in archives:
            if sig_int and sig_int.action_done():
                break
            # get_item_data/format_item may internally load the archive from the repository,
            # so we must call it before deleting the archive.
            if args.json:
                archive_data = formatter.get_item_data(archive_info, jsonline=True)
            else:
                archive_formatted = formatter.format_item(archive_info, jsonline=False)
            if archive_info in archives_to_prune:
                if not args.json:
                    pi.show()
                num_archives_deleted += 1
                if args.dry_run:
                    log_message = "Would prune:"
                else:
                    log_message = f"Pruning archive ({num_archives_deleted}/{len(archives_to_prune)}):"
                    manifest.archives.delete_by_id(archive_info.id)
                if args.json:
                    archive_data["kept"] = False
                    archive_data["deleted_archive_number"] = num_archives_deleted
            else:
                result = keep[archive_info]
                result_message = f"{result.rule.key}{'[oldest]' if result.oldest else ''} #{result.idx + 1}"
                log_message = f"Keeping archive (rule: {result_message}):"
                if args.json:
                    archive_data["kept"] = True
                    archive_data["keep_rule"] = result.rule.key
                    archive_data["kept_oldest"] = result.oldest
                    archive_data["kept_archive_number"] = result.idx + 1
            if args.json:
                if (
                    args.output_list
                    or not (args.list_pruned or args.list_kept)
                    or (args.list_pruned and archive_info in archives_to_prune)
                    or (args.list_kept and archive_info not in archives_to_prune)
                ):
                    output_data.append(archive_data)
            elif (
                args.output_list
                or (args.list_pruned and archive_info in archives_to_prune)
                or (args.list_kept and archive_info not in archives_to_prune)
            ):
                list_logger.info(f"{log_message:<44} {archive_formatted}")
        if not args.json:
            pi.finish()
        if args.json:
            json_print(basic_json_data(manifest, extra={"archives": output_data}))
        if num_archives_deleted > 0 and not args.dry_run:
            manifest.write()
            self.print_warning('Done. Run "borg compact" to free space.', wc=None)
        if sig_int:
            raise Error("Got Ctrl-C / SIGINT.")

    def _validate_prune_args(self, args):
        keep_args = {rule.key: getattr(args, rule.key) for rule in PRUNING_RULES if getattr(args, rule.key) is not None}

        if len(keep_args) == 0:
            raise CommandError(
                'At least one of the "keep" "keep-secondly", "keep-minutely", "keep-hourly", "keep-daily", '
                '"keep-weekly", "keep-monthly", "keep-13weekly", "keep-3monthly", or "keep-yearly" settings must be '
                "specified."
            )

        def lo_hi_mismatch_errmsg(lo_arg, lo_val, hi_arg, hi_val):
            return (
                f"The combination of \"{lo_arg}='{lo_val}'\" and \"{hi_arg}='{hi_val}'\" is invalid. It is effectively "
                f"useless since every archive matched by {hi_arg} would have already been matched by {lo_arg} and may "
                "have led to undefined behavior were it allowed."
            )

        prune_keys = {rule.key for rule in PRUNING_RULES}
        interval_args = [
            (arg, val)
            for arg, val in keep_args.items()
            if arg in prune_keys and (isinstance(val, timedelta) or val == -1)
        ]
        for (lo_arg, lo_val), (hi_arg, hi_val) in combinations(interval_args, 2):
            if lo_val == -1 or lo_val >= hi_val:
                raise CommandError(lo_hi_mismatch_errmsg(lo_arg, lo_val, hi_arg, hi_val))

        int_args = [
            (arg, val)
            for arg, val in keep_args.items()
            if any((arg == r.key for r in PRUNING_RULES)) and isinstance(val, int)
        ]
        for (lo_arg, lo_val), (hi_arg, hi_val) in combinations(int_args, 2):
            if lo_val == -1:
                raise CommandError(lo_hi_mismatch_errmsg(lo_arg, lo_val, hi_arg, hi_val))

    def build_parser_prune(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog
        from ._common import define_archive_filters_group

        prune_epilog = process_epilog(
            """
        The prune command prunes a repository by soft-deleting all archives not
        matching any of the specified retention options.

        Important:

        - The prune command will only mark archives for deletion ("soft-deletion"),
          repository disk space is **not** freed until you run ``borg compact``.
        - You can use ``borg undelete`` to undelete archives, but only until
          you run ``borg compact``.

        This command is normally used by automated backup scripts wanting to keep a
        certain number of historic backups. This retention policy is commonly referred to as
        `GFS <https://en.wikipedia.org/wiki/Backup_rotation_scheme#Grandfather-father-son>`_
        (Grandfather-father-son) backup rotation scheme.

        The recommended way to use prune is to give the archive series name to it via the
        NAME argument (assuming you have the same name for all archives in a series).
        Alternatively, you can also use --match-archives (-a), then only archives that
        match the pattern are considered for deletion and only those archives count
        towards the totals specified by the rules.
        Otherwise, *all* archives in the repository are candidates for deletion!
        There is no automatic distinction between archives representing different
        contents. These need to be distinguished by specifying matching globs.

        If you have multiple series of archives with different data sets (e.g.
        from different machines) in one shared repository, use one prune call per
        series.

        The ``--keep`` option is the simplest way to specify a basic retention
        policy. It accepts a count or a time interval for retention (e.g.
        ``10`` or ``7d``, ``4w``). With a count it keeps at most that many
        recent archives; with an interval it keeps all archives created within
        that time window. When ``--since`` is given together with an interval
        retention, the interval is measured backwards from that timestamp
        instead of from the current time. See ``Date and Time`` docs for exact
        INTERVAL format.

        The ``--keep-secondly``, ``--keep-minutely``, ``--keep-hourly``,
        ``--keep-daily``, ``--keep-weekly``, ``--keep-monthly``,
        ``--keep-13weekly``, ``--keep-3monthly``, and ``--keep-yearly`` options
        specify time period retention policies. They accept either a count N for
        retention or a time interval INTERVAL for retention, same as for ``--keep``.
        With a retention count, they keep at most that many archives (one per
        period, e.g. one per day or one per month until the retention count is
        met). With a retention interval, they keep one archive per period
        within that time span (e.g. at most one per day in a span of seven
        days, even if some days had none) -- measured from ``--since`` if given,
        otherwise from the current time. Specifying a count of ``-1`` (or the
        word ``all``) means no limit. A zero count or zero-length interval
        keeps nothing.

        The ``--since`` option restricts pruning to archives older than the given
        TIMESTAMP. Archives newer than this timestamp are kept unconditionally
        as a pre-filter. When ``--since`` is used together with interval-based
        ``--keep-*`` options (e.g. ``--keep-daily 7d``), the interval is
        measured backwards from the given timestamp rather than from the
        current time. Count-based retention is unaffected.

        The ``--keep-13weekly`` and ``--keep-3monthly`` rules are two different
        strategies for keeping archives every quarter year.

        The oldest archive is always kept. This is useful for rolling tiered backup
        schemes, where the earliest backup in a retention window should survive until
        the next tier's interval naturally replaces it.

        When using interval-based pruning with multiple ``--keep-*`` options,
        the intervals must be specified in increasing order of coarseness.
        For example, ``--keep-daily 7d --keep-weekly 4w`` is valid, but
        ``--keep-daily 30d --keep-weekly 7d`` is not, because the weekly
        interval is already covered by the daily one.


        A practical approach for recurring backups is to use rules
        with increasing coarseness so that most of recent history is kept and
        older history gradually thins out with time. For example,
        ``--keep-daily 7d --keep-weekly 4w --keep-monthly 6`` keeps an
        archive per day for the past week, per week for the past month, and
        one per month for six months after that. Combine this with ``--since``
        to align time windows to calendar boundaries rather than the exact
        moment you run prune for more predictable behavior of coarser rules:
        ``--keep-daily 7d --keep-weekly 4w --since $(date +%F)``.

        Count-based retention keeps archives less bound to time. For instance,
        ``--keep-yearly 3`` retains 3 yearly archives however far back they
        span and ``--keep-daily 20`` keeps 20 archives no matter if you missed
        a week in between. This can be useful for less regular archive
        creation, or if your use case does not map well to specific time
        intervals, or if you simply prefer to think of archive retention in
        numbers rather than intervals.

        For count-based retention, backups selected by more granular rules do
        not count towards those of coarser rules. ``--keep 3 --keep-monthly 2``
        will first keep the 3 latest archives and then keep 2 monthly archives,
        skipping ones that were already kept by ``--keep 3``.

        The time that each archive creation started is used to match archives
        to pruning periods. Dates and times are interpreted in the local
        timezone of your system. Weeks go from Monday to Sunday.


        You can influence how the ``--list`` output is formatted by using the ``--short``
        option (less wide output) or by giving a custom format using ``--format`` (see
        the ``borg repo-list`` description for more details about the format string).
        """
        )
        subparser = ArgumentParser(parents=[common_parser], description=self.do_prune.__doc__, epilog=prune_epilog)
        subparsers.add_subcommand("prune", subparser, help="prune archives")
        subparser.add_argument(
            "-n", "--dry-run", dest="dry_run", action="store_true", help="do not change the repository"
        )
        subparser.add_argument(
            "--list", dest="output_list", action="store_true", help="output a verbose list of archives it keeps/prunes"
        )
        subparser.add_argument("--short", dest="short", action="store_true", help="use a less wide archive part format")
        subparser.add_argument(
            "--list-pruned", dest="list_pruned", action="store_true", help="output verbose list of archives it prunes"
        )
        subparser.add_argument(
            "--list-kept", dest="list_kept", action="store_true", help="output verbose list of archives it keeps"
        )
        subparser.add_argument(
            "--format",
            metavar="FORMAT",
            dest="format",
            action=Highlander,
            help="specify format for the archive part " '(default: "{archive:<36} {time} [{id}]")',
        )
        subparser.add_argument(
            "--json",
            action="store_true",
            help="Format output as JSON. "
            "The form of ``--format`` is ignored, "
            "but keys used in it are added to the JSON output. "
            "Some keys are always present. Note: JSON can only represent text.",
        )
        subparser.add_argument(
            "--since",
            metavar="TIMESTAMP",
            dest=PRUNE_SINCE.key,
            type=timestamp,
            action=Highlander,
            help="only consider archives older than this for pruning",
        )
        subparser.add_argument(
            "--keep",
            dest=PRUNE_KEEP.key,
            type=int_or_interval,
            action=Highlander,
            help="number or time interval of archives to keep",
        )
        subparser.add_argument(
            "--keep-secondly",
            dest=PRUNE_SECONDLY.key,
            type=int_or_interval,
            action=Highlander,
            help="number or time interval of secondly archives to keep",
        )
        subparser.add_argument(
            "--keep-minutely",
            dest=PRUNE_MINUTELY.key,
            type=int_or_interval,
            action=Highlander,
            help="number or time interval of minutely archives to keep",
        )
        subparser.add_argument(
            "-H",
            "--keep-hourly",
            dest=PRUNE_HOURLY.key,
            type=int_or_interval,
            action=Highlander,
            help="number or time interval of hourly archives to keep",
        )
        subparser.add_argument(
            "-d",
            "--keep-daily",
            dest=PRUNE_DAILY.key,
            type=int_or_interval,
            action=Highlander,
            help="number or time interval of daily archives to keep",
        )
        subparser.add_argument(
            "-w",
            "--keep-weekly",
            dest=PRUNE_WEEKLY.key,
            type=int_or_interval,
            action=Highlander,
            help="number or time interval of weekly archives to keep",
        )
        subparser.add_argument(
            "-m",
            "--keep-monthly",
            dest=PRUNE_MONTHLY.key,
            type=int_or_interval,
            action=Highlander,
            help="number or time interval of monthly archives to keep",
        )
        quarterly_group = subparser.add_mutually_exclusive_group()
        quarterly_group.add_argument(
            "--keep-13weekly",
            dest=PRUNE_QUARTERLY_13WEEKLY.key,
            type=int_or_interval,
            help="number or time interval of quarterly archives to keep (13 week strategy)",
        )
        quarterly_group.add_argument(
            "--keep-3monthly",
            dest=PRUNE_QUARTERLY_3MONTHLY.key,
            type=int_or_interval,
            help="number or time interval of quarterly archives to keep (3 month strategy)",
        )
        subparser.add_argument(
            "-y",
            "--keep-yearly",
            dest=PRUNE_YEARLY.key,
            type=int_or_interval,
            action=Highlander,
            help="number or time interval of yearly archives to keep",
        )
        define_archive_filters_group(subparser, sort_by=False, first_last=False)
        subparser.add_argument(
            "name", metavar="NAME", nargs="?", type=archivename_validator, help="specify the archive name"
        )

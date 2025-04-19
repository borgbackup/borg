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
from ..helpers import archivename_validator, interval, int_or_interval, sig_int
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
# these groups, only the latest (by creation timestamp) is kept.


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
PRUNE_WITHIN = PruningRule("within", unique_period_func())
PRUNE_LAST = PruningRule("last", unique_period_func())
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

PRUNING_RULES = [
    PRUNE_WITHIN,
    PRUNE_LAST,
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
    base_timestamp: datetime | None,
    keep_oldest: bool,
    previously_kept: frozenset[ArchiveInfo] = frozenset(),
) -> dict[ArchiveInfo, KeepResult]:
    if len(archives) == 0 or n_or_interval in (0, timedelta(0)):
        return {}

    if isinstance(n_or_interval, int):
        n, earliest_timestamp = n_or_interval, None
    else:
        if base_timestamp is None:
            raise ValueError("base_timestamp is required when using interval-based pruning")
        n, earliest_timestamp = None, base_timestamp - n_or_interval

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


        if args.format is not None:
            format = args.format
        elif args.short:
            format = "{archive}"
        else:
            format = os.environ.get("BORG_PRUNE_FORMAT", "{archive:<36} {time} [{id}]")
        formatter = ArchiveFormatter(format, repository, manifest, manifest.key, iec=args.iec)

        match = [args.name] if args.name else args.match_archives
        archives = manifest.archives.list(match=match, sort_by=["ts"], reverse=True)
        archives = [ai for ai in archives if "@PROT" not in ai.tags]

        # Archives to keep along with the rule that ensured them being kept
        keep = {}

        base_timestamp = datetime.now().astimezone()
        active_rules = {rule: getattr(args, rule.key) for rule in PRUNING_RULES if getattr(args, rule.key) is not None}
        for i, (rule, n_or_interval) in enumerate(active_rules.items(), 1):
            keep |= prune(
                archives=archives,
                rule=rule,
                n_or_interval=n_or_interval,
                base_timestamp=base_timestamp,
                keep_oldest=i == len(active_rules),  # Activate keep_oldest rule only for the largest active interval
                previously_kept=frozenset(keep),
            )

        to_delete = set(archives) - set(keep)
        if not args.json:
            logger.info("Repository contains %d archives.", manifest.archives.count())
            logger.info("Applying rules to the matching %d archives...", len(archives))
            logger.info("Keeping %d archives, pruning %d archives.", len(keep), len(to_delete))
        if args.json:
            output_data = []
        list_logger = logging.getLogger("borg.output.list")
        # set up counters for the progress display
        to_delete_len = len(to_delete)
        archives_deleted = 0
        pi = ProgressIndicatorPercent(total=len(to_delete), msg="Pruning archives %3.0f%%", msgid="prune")
        for archive_info in archives:
            if sig_int and sig_int.action_done():
                break
            # get_item_data/format_item may internally load the archive from the repository,
            # so we must call it before deleting the archive.
            if args.json:
                archive_data = formatter.get_item_data(archive_info, jsonline=True)
            else:
                archive_formatted = formatter.format_item(archive_info, jsonline=False)
            if archive_info in to_delete:
                if not args.json:
                    pi.show()
                archives_deleted += 1
                if args.dry_run:
                    log_message = "Would prune:"
                else:
                    log_message = "Pruning archive (%d/%d):" % (archives_deleted, to_delete_len)
                    manifest.archives.delete_by_id(archive_info.id)
                if args.json:
                    archive_data["kept"] = False
                    archive_data["deleted_archive_number"] = archives_deleted
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
                    or (args.list_pruned and archive_info in to_delete)
                    or (args.list_kept and archive_info not in to_delete)
                ):
                    output_data.append(archive_data)
            elif (
                args.output_list
                or (args.list_pruned and archive_info in to_delete)
                or (args.list_kept and archive_info not in to_delete)
            ):
                list_logger.info(f"{log_message:<44} {archive_formatted}")
        if not args.json:
            pi.finish()
        if args.json:
            json_print(basic_json_data(manifest, extra={"archives": output_data}))
        if archives_deleted > 0 and not args.dry_run:
            manifest.write()
            self.print_warning('Done. Run "borg compact" to free space.', wc=None)
        if sig_int:
            raise Error("Got Ctrl-C / SIGINT.")

    def _validate_prune_args(self, args):
        keep_args = {rule.key: getattr(args, rule.key) for rule in PRUNING_RULES if getattr(args, rule.key) is not None}

        if len(keep_args) == 0:
            raise CommandError(
                'At least one of the "keep", "keep-within", "keep-last", '
                '"keep-secondly", "keep-minutely", "keep-hourly", "keep-daily", '
                '"keep-weekly", "keep-monthly", "keep-13weekly", "keep-3monthly", '
                'or "keep-yearly" settings must be specified.'
            )

        if PRUNE_KEEP.key in keep_args and PRUNE_LAST.key in keep_args:
            raise CommandError('Only one of the "keep" and "last" settings may be specified.')

        if PRUNE_KEEP.key in keep_args and PRUNE_WITHIN.key in keep_args:
            raise CommandError('Only one of the "keep" and "within" settings may be specified.')

        if all(not bool(val) for val in keep_args.values()):
            raise CommandError(
                'None of the "keep", "keep-secondly", "keep-minutely", "keep-hourly", "keep-daily", "keep-weekly", '
                '"keep-monthly", "keep-13weekly", "keep-3monthly", or "keep-yearly" settings have a positive value. '
                "At least one must be non-zero."
            )

        def lo_hi_mismatch_errmsg(lo_arg, lo_val, hi_arg, hi_val):
            return (
                f"The combination of \"{lo_arg}='{lo_val}'\" and \"{hi_arg}='{hi_val}'\" is invalid. It is effectively "
                f"useless since every archive matched by {hi_arg} would have already been matched by {lo_arg}."
            )

        prune_keys = {rule.key for rule in PRUNING_RULES if rule != PRUNE_LAST}
        interval_args = [
            (arg, val)
            for arg, val in keep_args.items()
            if arg in prune_keys and (isinstance(val, timedelta) or val == -1)
        ]
        for (lo_arg, lo_val), (hi_arg, hi_val) in combinations(interval_args, 2):
            if hi_val == -1:
                # 'Infinity' is always bigger
                continue

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

        The ``--keep-within`` option takes an argument of the form "<int><char>",
        where char is "y", "m", "w", "d", "H", "M", or "S".  For example,
        ``--keep-within 2d`` means to keep all archives that were created within
        the past 2 days.  "1m" is taken to mean "31d". The archives kept with
        this option do not count towards the totals specified by any other options.

        A good procedure is to thin out more and more the older your backups get.
        As an example, ``--keep-daily 7`` means to keep the latest backup on each day,
        up to 7 most recent days with backups (days without backups do not count).
        The rules are applied from secondly to yearly, and backups selected by previous
        rules do not count towards those of later rules. The time that each backup
        starts is used for pruning purposes. Dates and times are interpreted in the local
        timezone of the system where borg prune runs, and weeks go from Monday to Sunday.
        Specifying a negative number of archives to keep means that there is no limit.

        Borg will retain the oldest archive if any of the secondly, minutely, hourly,
        daily, weekly, monthly, quarterly, or yearly rules was not otherwise able to
        meet its retention target. This enables the first chronological archive to
        continue aging until it is replaced by a newer archive that meets the retention
        criteria.

        The ``--keep-13weekly`` and ``--keep-3monthly`` rules are two different
        strategies for keeping archives every quarter year.

        The ``--keep-last N`` option is doing the same as ``--keep-secondly N`` (and it will
        keep the last N archives under the assumption that you do not create more than one
        backup archive in the same second).

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
            "--keep-within",
            metavar="INTERVAL",
            dest=PRUNE_WITHIN.key,
            type=interval,
            action=Highlander,
            help="keep all archives within this time interval",
        )
        subparser.add_argument(
            "--keep-last", dest=PRUNE_LAST.key, type=int, action=Highlander, help="number of archives to keep"
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

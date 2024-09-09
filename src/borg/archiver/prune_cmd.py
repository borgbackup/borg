import argparse
from collections import OrderedDict
from datetime import datetime, timezone, timedelta
import logging
from operator import attrgetter
import os

from ._common import with_repository, Highlander
from ..archive import Archive
from ..cache import Cache
from ..constants import *  # NOQA
from ..helpers import ArchiveFormatter, interval, sig_int, ProgressIndicatorPercent, CommandError, Error
from ..manifest import Manifest

from ..logger import create_logger

logger = create_logger()


def prune_within(archives, hours, kept_because):
    target = datetime.now(timezone.utc) - timedelta(seconds=hours * 3600)
    kept_counter = 0
    result = []
    for a in archives:
        if a.ts > target:
            kept_counter += 1
            kept_because[a.id] = ("within", kept_counter)
            result.append(a)
    return result


PRUNING_PATTERNS = OrderedDict(
    [
        ("secondly", "%Y-%m-%d %H:%M:%S"),
        ("minutely", "%Y-%m-%d %H:%M"),
        ("hourly", "%Y-%m-%d %H"),
        ("daily", "%Y-%m-%d"),
        ("weekly", "%G-%V"),
        ("monthly", "%Y-%m"),
        ("yearly", "%Y"),
    ]
)


def prune_split(archives, rule, n, kept_because=None):
    last = None
    keep = []
    pattern = PRUNING_PATTERNS[rule]
    if kept_because is None:
        kept_because = {}
    if n == 0:
        return keep

    a = None
    for a in sorted(archives, key=attrgetter("ts"), reverse=True):
        # we compute the pruning in local time zone
        period = a.ts.astimezone().strftime(pattern)
        if period != last:
            last = period
            if a.id not in kept_because:
                keep.append(a)
                kept_because[a.id] = (rule, len(keep))
                if len(keep) == n:
                    break
    # Keep oldest archive if we didn't reach the target retention count
    if a is not None and len(keep) < n and a.id not in kept_because:
        keep.append(a)
        kept_because[a.id] = (rule + "[oldest]", len(keep))
    return keep


class PruneMixIn:
    @with_repository(compatibility=(Manifest.Operation.DELETE,))
    def do_prune(self, args, repository, manifest):
        """Prune repository archives according to specified rules"""
        if not any(
            (args.secondly, args.minutely, args.hourly, args.daily, args.weekly, args.monthly, args.yearly, args.within)
        ):
            raise CommandError(
                'At least one of the "keep-within", "keep-last", '
                '"keep-secondly", "keep-minutely", "keep-hourly", "keep-daily", '
                '"keep-weekly", "keep-monthly" or "keep-yearly" settings must be specified.'
            )

        if args.format is not None:
            format = args.format
        elif args.short:
            format = "{archive}"
        else:
            format = os.environ.get("BORG_PRUNE_FORMAT", "{archive:<36} {time} [{id}]")
        formatter = ArchiveFormatter(format, repository, manifest, manifest.key, iec=args.iec)

        archives = manifest.archives.list(match=args.match_archives, sort_by=["ts"], reverse=True)
        keep = []
        # collect the rule responsible for the keeping of each archive in this dict
        # keys are archive ids, values are a tuple
        #   (<rulename>, <how many archives were kept by this rule so far >)
        kept_because = {}

        # find archives which need to be kept because of the keep-within rule
        if args.within:
            keep += prune_within(archives, args.within, kept_because)

        # find archives which need to be kept because of the various time period rules
        for rule in PRUNING_PATTERNS.keys():
            num = getattr(args, rule, None)
            if num is not None:
                keep += prune_split(archives, rule, num, kept_because)

        to_delete = set(archives) - set(keep)
        with Cache(repository, manifest, lock_wait=self.lock_wait, iec=args.iec) as cache:
            list_logger = logging.getLogger("borg.output.list")
            # set up counters for the progress display
            to_delete_len = len(to_delete)
            archives_deleted = 0
            uncommitted_deletes = 0
            pi = ProgressIndicatorPercent(total=len(to_delete), msg="Pruning archives %3.0f%%", msgid="prune")
            for archive in archives:
                if sig_int and sig_int.action_done():
                    break
                if archive in to_delete:
                    pi.show()
                    if args.dry_run:
                        log_message = "Would prune:"
                    else:
                        archives_deleted += 1
                        log_message = "Pruning archive (%d/%d):" % (archives_deleted, to_delete_len)
                        archive = Archive(manifest, archive.name, cache)
                        archive.delete()
                        uncommitted_deletes += 1
                else:
                    log_message = "Keeping archive (rule: {rule} #{num}):".format(
                        rule=kept_because[archive.id][0], num=kept_because[archive.id][1]
                    )
                if (
                    args.output_list
                    or (args.list_pruned and archive in to_delete)
                    or (args.list_kept and archive not in to_delete)
                ):
                    list_logger.info(f"{log_message:<44} {formatter.format_item(archive, jsonline=False)}")
            pi.finish()
            if sig_int:
                raise Error("Got Ctrl-C / SIGINT.")
            elif uncommitted_deletes > 0:
                manifest.write()

    def build_parser_prune(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog
        from ._common import define_archive_filters_group

        prune_epilog = process_epilog(
            """
        The prune command prunes a repository by deleting all archives not matching
        any of the specified retention options.

        Important: Repository disk space is **not** freed until you run ``borg compact``.

        This command is normally used by automated backup scripts wanting to keep a
        certain number of historic backups. This retention policy is commonly referred to as
        `GFS <https://en.wikipedia.org/wiki/Backup_rotation_scheme#Grandfather-father-son>`_
        (Grandfather-father-son) backup rotation scheme.

        If you use --match-archives (-a), then only archives that match the pattern are
        considered for deletion and only those archives count towards the totals
        specified by the rules.
        Otherwise, *all* archives in the repository are candidates for deletion!
        There is no automatic distinction between archives representing different
        contents. These need to be distinguished by specifying matching globs.

        If you have multiple sequences of archives with different data sets (e.g.
        from different machines) in one shared repository, use one prune call per
        data set that matches only the respective archives using the --match-archives
        (-a) option.

        The ``--keep-within`` option takes an argument of the form "<int><char>",
        where char is "H", "d", "w", "m", "y". For example, ``--keep-within 2d`` means
        to keep all archives that were created within the past 48 hours.
        "1m" is taken to mean "31d". The archives kept with this option do not
        count towards the totals specified by any other options.

        A good procedure is to thin out more and more the older your backups get.
        As an example, ``--keep-daily 7`` means to keep the latest backup on each day,
        up to 7 most recent days with backups (days without backups do not count).
        The rules are applied from secondly to yearly, and backups selected by previous
        rules do not count towards those of later rules. The time that each backup
        starts is used for pruning purposes. Dates and times are interpreted in the local
        timezone of the system where borg prune runs, and weeks go from Monday to Sunday.
        Specifying a negative number of archives to keep means that there is no limit.
        As of borg 1.2.0, borg will retain the oldest archive if any of the secondly,
        minutely, hourly, daily, weekly, monthly, or yearly rules was not otherwise able to
        meet its retention target. This enables the first chronological archive to continue
        aging until it is replaced by a newer archive that meets the retention criteria.

        The ``--keep-last N`` option is doing the same as ``--keep-secondly N`` (and it will
        keep the last N archives under the assumption that you do not create more than one
        backup archive in the same second).

        You can influence how the ``--list`` output is formatted by using the ``--short``
        option (less wide output) or by giving a custom format using ``--format`` (see
        the ``borg repo-list`` description for more details about the format string).
        """
        )
        subparser = subparsers.add_parser(
            "prune",
            parents=[common_parser],
            add_help=False,
            description=self.do_prune.__doc__,
            epilog=prune_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="prune archives",
        )
        subparser.set_defaults(func=self.do_prune)
        subparser.add_argument("-n", "--dry-run", dest="dry_run", action="store_true", help="do not change repository")
        subparser.add_argument(
            "--list", dest="output_list", action="store_true", help="output verbose list of archives it keeps/prunes"
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
            "--keep-within",
            metavar="INTERVAL",
            dest="within",
            type=interval,
            action=Highlander,
            help="keep all archives within this time interval",
        )
        subparser.add_argument(
            "--keep-last",
            "--keep-secondly",
            dest="secondly",
            type=int,
            default=0,
            action=Highlander,
            help="number of secondly archives to keep",
        )
        subparser.add_argument(
            "--keep-minutely",
            dest="minutely",
            type=int,
            default=0,
            action=Highlander,
            help="number of minutely archives to keep",
        )
        subparser.add_argument(
            "-H",
            "--keep-hourly",
            dest="hourly",
            type=int,
            default=0,
            action=Highlander,
            help="number of hourly archives to keep",
        )
        subparser.add_argument(
            "-d",
            "--keep-daily",
            dest="daily",
            type=int,
            default=0,
            action=Highlander,
            help="number of daily archives to keep",
        )
        subparser.add_argument(
            "-w",
            "--keep-weekly",
            dest="weekly",
            type=int,
            default=0,
            action=Highlander,
            help="number of weekly archives to keep",
        )
        subparser.add_argument(
            "-m",
            "--keep-monthly",
            dest="monthly",
            type=int,
            default=0,
            action=Highlander,
            help="number of monthly archives to keep",
        )
        subparser.add_argument(
            "-y",
            "--keep-yearly",
            dest="yearly",
            type=int,
            default=0,
            action=Highlander,
            help="number of yearly archives to keep",
        )
        define_archive_filters_group(subparser, sort_by=False, first_last=False)

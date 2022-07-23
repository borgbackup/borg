import argparse
import logging
import re

from .common import with_repository
from ..archive import Archive, Statistics
from ..cache import Cache
from ..constants import *  # NOQA
from ..helpers import format_archive
from ..helpers import interval, prune_within, prune_split, PRUNING_PATTERNS
from ..helpers import Manifest, sig_int
from ..helpers import log_multi
from ..helpers import ProgressIndicatorPercent

from ..logger import create_logger

logger = create_logger()


class PruneMixIn:
    @with_repository(exclusive=True, compatibility=(Manifest.Operation.DELETE,))
    def do_prune(self, args, repository, manifest, key):
        """Prune repository archives according to specified rules"""
        if not any(
            (args.secondly, args.minutely, args.hourly, args.daily, args.weekly, args.monthly, args.yearly, args.within)
        ):
            self.print_error(
                'At least one of the "keep-within", "keep-last", '
                '"keep-secondly", "keep-minutely", "keep-hourly", "keep-daily", '
                '"keep-weekly", "keep-monthly" or "keep-yearly" settings must be specified.'
            )
            return self.exit_code
        checkpoint_re = r"\.checkpoint(\.\d+)?"
        archives_checkpoints = manifest.archives.list(
            glob=args.glob_archives,
            consider_checkpoints=True,
            match_end=r"(%s)?\Z" % checkpoint_re,
            sort_by=["ts"],
            reverse=True,
        )
        is_checkpoint = re.compile(r"(%s)\Z" % checkpoint_re).search
        checkpoints = [arch for arch in archives_checkpoints if is_checkpoint(arch.name)]
        # keep the latest checkpoint, if there is no later non-checkpoint archive
        if archives_checkpoints and checkpoints and archives_checkpoints[0] is checkpoints[0]:
            keep_checkpoints = checkpoints[:1]
        else:
            keep_checkpoints = []
        checkpoints = set(checkpoints)
        # ignore all checkpoint archives to avoid keeping one (which is an incomplete backup)
        # that is newer than a successfully completed backup - and killing the successful backup.
        archives = [arch for arch in archives_checkpoints if arch not in checkpoints]
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

        to_delete = (set(archives) | checkpoints) - (set(keep) | set(keep_checkpoints))
        stats = Statistics(iec=args.iec)
        with Cache(repository, key, manifest, lock_wait=self.lock_wait, iec=args.iec) as cache:

            def checkpoint_func():
                manifest.write()
                repository.commit(compact=False, save_space=args.save_space)
                cache.commit()

            list_logger = logging.getLogger("borg.output.list")
            # set up counters for the progress display
            to_delete_len = len(to_delete)
            archives_deleted = 0
            uncommitted_deletes = 0
            pi = ProgressIndicatorPercent(total=len(to_delete), msg="Pruning archives %3.0f%%", msgid="prune")
            for archive in archives_checkpoints:
                if sig_int and sig_int.action_done():
                    break
                if archive in to_delete:
                    pi.show()
                    if args.dry_run:
                        log_message = "Would prune:"
                    else:
                        archives_deleted += 1
                        log_message = "Pruning archive (%d/%d):" % (archives_deleted, to_delete_len)
                        archive = Archive(
                            repository, key, manifest, archive.name, cache, consider_part_files=args.consider_part_files
                        )
                        archive.delete(stats, forced=args.forced)
                        checkpointed = self.maybe_checkpoint(
                            checkpoint_func=checkpoint_func, checkpoint_interval=args.checkpoint_interval
                        )
                        uncommitted_deletes = 0 if checkpointed else (uncommitted_deletes + 1)
                else:
                    if is_checkpoint(archive.name):
                        log_message = "Keeping checkpoint archive:"
                    else:
                        log_message = "Keeping archive (rule: {rule} #{num}):".format(
                            rule=kept_because[archive.id][0], num=kept_because[archive.id][1]
                        )
                if args.output_list:
                    list_logger.info(
                        "{message:<40} {archive}".format(message=log_message, archive=format_archive(archive))
                    )
            pi.finish()
            if sig_int:
                # Ctrl-C / SIGINT: do not checkpoint (commit) again, we already have a checkpoint in this case.
                self.print_error("Got Ctrl-C / SIGINT.")
            elif uncommitted_deletes > 0:
                checkpoint_func()
            if args.stats:
                log_multi(str(stats), logger=logging.getLogger("borg.output.stats"))
        return self.exit_code

    def build_parser_prune(self, subparsers, common_parser, mid_common_parser):

        from .common import process_epilog
        from .common import define_archive_filters_group

        prune_epilog = process_epilog(
            """
        The prune command prunes a repository by deleting all archives not matching
        any of the specified retention options.

        Important: Repository disk space is **not** freed until you run ``borg compact``.

        This command is normally used by automated backup scripts wanting to keep a
        certain number of historic backups. This retention policy is commonly referred to as
        `GFS <https://en.wikipedia.org/wiki/Backup_rotation_scheme#Grandfather-father-son>`_
        (Grandfather-father-son) backup rotation scheme.

        Also, prune automatically removes checkpoint archives (incomplete archives left
        behind by interrupted backup runs) except if the checkpoint is the latest
        archive (and thus still needed). Checkpoint archives are not considered when
        comparing archive counts against the retention limits (``--keep-X``).

        If a prefix is set with -P, then only archives that start with the prefix are
        considered for deletion and only those archives count towards the totals
        specified by the rules.
        Otherwise, *all* archives in the repository are candidates for deletion!
        There is no automatic distinction between archives representing different
        contents. These need to be distinguished by specifying matching prefixes.

        If you have multiple sequences of archives with different data sets (e.g.
        from different machines) in one shared repository, use one prune call per
        data set that matches only the respective archives using the -P option.

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
        starts is used for pruning purposes. Dates and times are interpreted in
        the local timezone, and weeks go from Monday to Sunday. Specifying a
        negative number of archives to keep means that there is no limit. As of borg
        1.2.0, borg will retain the oldest archive if any of the secondly, minutely,
        hourly, daily, weekly, monthly, or yearly rules was not otherwise able to meet
        its retention target. This enables the first chronological archive to continue
        aging until it is replaced by a newer archive that meets the retention criteria.

        The ``--keep-last N`` option is doing the same as ``--keep-secondly N`` (and it will
        keep the last N archives under the assumption that you do not create more than one
        backup archive in the same second).

        When using ``--stats``, you will get some statistics about how much data was
        deleted - the "Deleted data" deduplicated size there is most interesting as
        that is how much your repository will shrink.
        Please note that the "All archives" stats refer to the state after pruning.
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
            "--force",
            dest="forced",
            action="store_true",
            help="force pruning of corrupted archives, " "use ``--force --force`` in case ``--force`` does not work.",
        )
        subparser.add_argument(
            "-s", "--stats", dest="stats", action="store_true", help="print statistics for the deleted archive"
        )
        subparser.add_argument(
            "--list", dest="output_list", action="store_true", help="output verbose list of archives it keeps/prunes"
        )
        subparser.add_argument(
            "--keep-within",
            metavar="INTERVAL",
            dest="within",
            type=interval,
            help="keep all archives within this time interval",
        )
        subparser.add_argument(
            "--keep-last",
            "--keep-secondly",
            dest="secondly",
            type=int,
            default=0,
            help="number of secondly archives to keep",
        )
        subparser.add_argument(
            "--keep-minutely", dest="minutely", type=int, default=0, help="number of minutely archives to keep"
        )
        subparser.add_argument(
            "-H", "--keep-hourly", dest="hourly", type=int, default=0, help="number of hourly archives to keep"
        )
        subparser.add_argument(
            "-d", "--keep-daily", dest="daily", type=int, default=0, help="number of daily archives to keep"
        )
        subparser.add_argument(
            "-w", "--keep-weekly", dest="weekly", type=int, default=0, help="number of weekly archives to keep"
        )
        subparser.add_argument(
            "-m", "--keep-monthly", dest="monthly", type=int, default=0, help="number of monthly archives to keep"
        )
        subparser.add_argument(
            "-y", "--keep-yearly", dest="yearly", type=int, default=0, help="number of yearly archives to keep"
        )
        define_archive_filters_group(subparser, sort_by=False, first_last=False)
        subparser.add_argument(
            "--save-space", dest="save_space", action="store_true", help="work slower, but using less space"
        )
        subparser.add_argument(
            "-c",
            "--checkpoint-interval",
            metavar="SECONDS",
            dest="checkpoint_interval",
            type=int,
            default=1800,
            help="write checkpoint every SECONDS seconds (Default: 1800)",
        )

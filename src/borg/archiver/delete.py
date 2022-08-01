import argparse
import logging

from .common import with_repository
from ..archive import Archive, Statistics
from ..cache import Cache
from ..constants import *  # NOQA
from ..helpers import Manifest, sig_int
from ..helpers import log_multi, format_archive

from ..logger import create_logger

logger = create_logger()


class DeleteMixIn:
    @with_repository(exclusive=True, manifest=False)
    def do_delete(self, args, repository):
        """Delete archives"""
        self.output_list = args.output_list
        dry_run = args.dry_run
        manifest, key = Manifest.load(repository, (Manifest.Operation.DELETE,))
        archive_names = tuple(x.name for x in manifest.archives.list_considering(args))
        if not archive_names:
            return self.exit_code
        if args.glob_archives is None and args.first == 0 and args.last == 0:
            self.print_error(
                "Aborting: if you really want to delete all archives, please use -a '*' "
                "or just delete the whole repository (might be much faster)."
            )
            return EXIT_ERROR

        if args.forced == 2:
            deleted = False
            logger_list = logging.getLogger("borg.output.list")
            for i, archive_name in enumerate(archive_names, 1):
                try:
                    current_archive = manifest.archives.pop(archive_name)
                except KeyError:
                    self.exit_code = EXIT_WARNING
                    logger.warning(f"Archive {archive_name} not found ({i}/{len(archive_names)}).")
                else:
                    deleted = True
                    if self.output_list:
                        msg = "Would delete: {} ({}/{})" if dry_run else "Deleted archive: {} ({}/{})"
                        logger_list.info(msg.format(format_archive(current_archive), i, len(archive_names)))
            if dry_run:
                logger.info("Finished dry-run.")
            elif deleted:
                manifest.write()
                # note: might crash in compact() after committing the repo
                repository.commit(compact=False)
                logger.warning('Done. Run "borg check --repair" to clean up the mess.')
            else:
                logger.warning("Aborted.")
            return self.exit_code

        stats = Statistics(iec=args.iec)
        with Cache(repository, key, manifest, progress=args.progress, lock_wait=self.lock_wait, iec=args.iec) as cache:

            def checkpoint_func():
                manifest.write()
                repository.commit(compact=False, save_space=args.save_space)
                cache.commit()

            msg_delete = "Would delete archive: {} ({}/{})" if dry_run else "Deleting archive: {} ({}/{})"
            msg_not_found = "Archive {} not found ({}/{})."
            logger_list = logging.getLogger("borg.output.list")
            uncommitted_deletes = 0
            for i, archive_name in enumerate(archive_names, 1):
                if sig_int and sig_int.action_done():
                    break
                try:
                    archive_info = manifest.archives[archive_name]
                except KeyError:
                    logger.warning(msg_not_found.format(archive_name, i, len(archive_names)))
                else:
                    if self.output_list:
                        logger_list.info(msg_delete.format(format_archive(archive_info), i, len(archive_names)))

                    if not dry_run:
                        archive = Archive(
                            repository,
                            key,
                            manifest,
                            archive_name,
                            cache=cache,
                            consider_part_files=args.consider_part_files,
                        )
                        archive.delete(stats, progress=args.progress, forced=args.forced)
                        checkpointed = self.maybe_checkpoint(
                            checkpoint_func=checkpoint_func, checkpoint_interval=args.checkpoint_interval
                        )
                        uncommitted_deletes = 0 if checkpointed else (uncommitted_deletes + 1)
            if sig_int:
                # Ctrl-C / SIGINT: do not checkpoint (commit) again, we already have a checkpoint in this case.
                self.print_error("Got Ctrl-C / SIGINT.")
            elif uncommitted_deletes > 0:
                checkpoint_func()
            if args.stats:
                log_multi(str(stats), logger=logging.getLogger("borg.output.stats"))

        return self.exit_code

    def build_parser_delete(self, subparsers, common_parser, mid_common_parser):
        from .common import process_epilog, define_archive_filters_group

        delete_epilog = process_epilog(
            """
        This command deletes archives from the repository.

        Important: When deleting archives, repository disk space is **not** freed until
        you run ``borg compact``.

        When in doubt, use ``--dry-run --list`` to see what would be deleted.

        When using ``--stats``, you will get some statistics about how much data was
        deleted - the "Deleted data" deduplicated size there is most interesting as
        that is how much your repository will shrink.
        Please note that the "All archives" stats refer to the state after deletion.

        You can delete multiple archives by specifying a matching shell pattern,
        using the ``--glob-archives GLOB`` option (for more info on these patterns,
        see :ref:`borg_patterns`).

        Always first use ``--dry-run --list`` to see what would be deleted.
        """
        )
        subparser = subparsers.add_parser(
            "delete",
            parents=[common_parser],
            add_help=False,
            description=self.do_delete.__doc__,
            epilog=delete_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="delete archive",
        )
        subparser.set_defaults(func=self.do_delete)
        subparser.add_argument("-n", "--dry-run", dest="dry_run", action="store_true", help="do not change repository")
        subparser.add_argument(
            "--list", dest="output_list", action="store_true", help="output verbose list of archives"
        )
        subparser.add_argument(
            "--consider-checkpoints",
            action="store_true",
            dest="consider_checkpoints",
            help="consider checkpoint archives for deletion (default: not considered).",
        )
        subparser.add_argument(
            "-s", "--stats", dest="stats", action="store_true", help="print statistics for the deleted archive"
        )
        subparser.add_argument(
            "--cache-only",
            dest="cache_only",
            action="store_true",
            help="delete only the local cache for the given repository",
        )
        subparser.add_argument(
            "--force",
            dest="forced",
            action="count",
            default=0,
            help="force deletion of corrupted archives, " "use ``--force --force`` in case ``--force`` does not work.",
        )
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
        define_archive_filters_group(subparser)

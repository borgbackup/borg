import argparse
import logging

from ._common import with_repository
from ..constants import *  # NOQA
from ..helpers import format_archive, CommandError
from ..manifest import Manifest

from ..logger import create_logger

logger = create_logger()


class DeleteMixIn:
    @with_repository(exclusive=True, manifest=False)
    def do_delete(self, args, repository):
        """Delete archives"""
        self.output_list = args.output_list
        dry_run = args.dry_run
        manifest = Manifest.load(repository, (Manifest.Operation.DELETE,))
        archive_names = tuple(x.name for x in manifest.archives.list_considering(args))
        if not archive_names:
            return
        if args.match_archives is None and args.first == 0 and args.last == 0:
            raise CommandError(
                "Aborting: if you really want to delete all archives, please use -a 'sh:*' "
                "or just delete the whole repository (might be much faster)."
            )

        deleted = False
        logger_list = logging.getLogger("borg.output.list")
        for i, archive_name in enumerate(archive_names, 1):
            try:
                # this does NOT use Archive.delete, so this code hopefully even works in cases a corrupt archive
                # would make the code in class Archive crash, so the user can at least get rid of such archives.
                current_archive = manifest.archives.pop(archive_name)
            except KeyError:
                self.print_warning(f"Archive {archive_name} not found ({i}/{len(archive_names)}).")
            else:
                deleted = True
                if self.output_list:
                    msg = "Would delete: {} ({}/{})" if dry_run else "Deleted archive: {} ({}/{})"
                    logger_list.info(msg.format(format_archive(current_archive), i, len(archive_names)))
        if dry_run:
            logger.info("Finished dry-run.")
        elif deleted:
            manifest.write()
            repository.commit(compact=False)
            self.print_warning('Done. Run "borg compact" to free space.', wc=None)
        else:
            self.print_warning("Aborted.", wc=None)
        return


    def build_parser_delete(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog, define_archive_filters_group

        delete_epilog = process_epilog(
            """
        This command deletes archives from the repository.

        Important: When deleting archives, repository disk space is **not** freed until
        you run ``borg compact``.

        When in doubt, use ``--dry-run --list`` to see what would be deleted.

        You can delete multiple archives by specifying a matching pattern,
        using the ``--match-archives PATTERN`` option (for more info on these patterns,
        see :ref:`borg_patterns`).
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
        define_archive_filters_group(subparser)

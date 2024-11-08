import argparse
import logging

from ._common import with_repository
from ..constants import *  # NOQA
from ..helpers import format_archive, CommandError, bin_to_hex, archivename_validator
from ..manifest import Manifest

from ..logger import create_logger

logger = create_logger()


class UnDeleteMixIn:
    @with_repository(manifest=False)
    def do_undelete(self, args, repository):
        """Undelete archives"""
        self.output_list = args.output_list
        dry_run = args.dry_run
        manifest = Manifest.load(repository, (Manifest.Operation.DELETE,))
        if args.name:
            archive_infos = [manifest.archives.get_one([args.name], deleted=True)]
        else:
            args.deleted = True
            archive_infos = manifest.archives.list_considering(args)
        count = len(archive_infos)
        if count == 0:
            return
        if not args.name and not args.match_archives and args.first == 0 and args.last == 0:
            raise CommandError("Aborting: if you really want to undelete all archives, please use -a 'sh:*'.")

        undeleted = False
        logger_list = logging.getLogger("borg.output.list")
        for i, archive_info in enumerate(archive_infos, 1):
            name, id, hex_id = archive_info.name, archive_info.id, bin_to_hex(archive_info.id)
            try:
                if not dry_run:
                    manifest.archives.undelete_by_id(id)
            except KeyError:
                self.print_warning(f"Archive {name} {hex_id} not found ({i}/{count}).")
            else:
                undeleted = True
                if self.output_list:
                    msg = "Would undelete: {} ({}/{})" if dry_run else "Undeleted archive: {} ({}/{})"
                    logger_list.info(msg.format(format_archive(archive_info), i, count))
        if dry_run:
            logger.info("Finished dry-run.")
        elif undeleted:
            manifest.write()
            self.print_warning("Done.", wc=None)
        else:
            self.print_warning("Aborted.", wc=None)
        return

    def build_parser_undelete(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog, define_archive_filters_group

        undelete_epilog = process_epilog(
            """
        This command undeletes archives in the repository.

        Important: Undeleting archives is only possible before compacting.
        Once ``borg compact`` has run, all disk space occupied only by the
        soft-deleted archives will be freed and undelete is not possible
        anymore.

        When in doubt, use ``--dry-run --list`` to see what would be undeleted.

        You can undelete multiple archives by specifying a matching pattern,
        using the ``--match-archives PATTERN`` option (for more info on these patterns,
        see :ref:`borg_patterns`).
        """
        )
        subparser = subparsers.add_parser(
            "undelete",
            parents=[common_parser],
            add_help=False,
            description=self.do_undelete.__doc__,
            epilog=undelete_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="undelete archive",
        )
        subparser.set_defaults(func=self.do_undelete)
        subparser.add_argument("-n", "--dry-run", dest="dry_run", action="store_true", help="do not change repository")
        subparser.add_argument(
            "--list", dest="output_list", action="store_true", help="output verbose list of archives"
        )
        define_archive_filters_group(subparser)
        subparser.add_argument(
            "name", metavar="NAME", nargs="?", type=archivename_validator, help="specify the archive name"
        )

import argparse
import logging

from ._common import with_repository
from ..constants import *  # NOQA
from ..helpers import format_archive, CommandError, bin_to_hex, archivename_validator
from ..manifest import Manifest

from ..logger import create_logger

logger = create_logger()


class DeleteMixIn:
    @with_repository(manifest=False)
    def do_delete(self, args, repository):
        """Delete archives"""
        self.output_list = args.output_list
        dry_run = args.dry_run
        manifest = Manifest.load(repository, (Manifest.Operation.DELETE,))
        if args.name:
            archive_infos = [manifest.archives.get_one([args.name])]
        else:
            archive_infos = manifest.archives.list_considering(args)
        archive_infos = [ai for ai in archive_infos if "@PROT" not in ai.tags]
        count = len(archive_infos)
        if count == 0:
            return
        if not args.name and not args.match_archives and args.first == 0 and args.last == 0:
            raise CommandError(
                "Aborting: if you really want to delete all archives, please use -a 'sh:*' "
                "or just delete the whole repository (might be much faster)."
            )

        deleted = False
        logger_list = logging.getLogger("borg.output.list")
        for i, archive_info in enumerate(archive_infos, 1):
            name, id, hex_id = archive_info.name, archive_info.id, bin_to_hex(archive_info.id)
            try:
                # this does NOT use Archive.delete, so this code hopefully even works in cases a corrupt archive
                # would make the code in class Archive crash, so the user can at least get rid of such archives.
                if not dry_run:
                    manifest.archives.delete_by_id(id)
            except KeyError:
                self.print_warning(f"Archive {name} {hex_id} not found ({i}/{count}).")
            else:
                deleted = True
                if self.output_list:
                    msg = "Would delete: {} ({}/{})" if dry_run else "Deleted archive: {} ({}/{})"
                    logger_list.info(msg.format(format_archive(archive_info), i, count))
        if dry_run:
            logger.info("Finished dry-run.")
        elif deleted:
            manifest.write()
            self.print_warning('Done. Run "borg compact" to free space.', wc=None)
        else:
            self.print_warning("Aborted.", wc=None)
        return

    def build_parser_delete(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog, define_archive_filters_group

        delete_epilog = process_epilog(
            """
        This command soft-deletes archives from the repository.

        Important:

        - The delete command will only mark archives for deletion ("soft-deletion"),
          repository disk space is **not** freed until you run ``borg compact``.
        - You can use ``borg undelete`` to undelete archives, but only until
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
        define_archive_filters_group(subparser)
        subparser.add_argument(
            "name", metavar="NAME", nargs="?", type=archivename_validator, help="specify the archive name"
        )

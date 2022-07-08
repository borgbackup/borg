import argparse

from .common import with_repository, with_archive
from ..constants import *  # NOQA
from ..helpers import archivename_validator
from ..helpers import Manifest

from ..logger import create_logger

logger = create_logger()


class RenameMixIn:
    @with_repository(exclusive=True, cache=True, compatibility=(Manifest.Operation.CHECK,))
    @with_archive
    def do_rename(self, args, repository, manifest, key, cache, archive):
        """Rename an existing archive"""
        archive.rename(args.newname)
        manifest.write()
        repository.commit(compact=False)
        cache.commit()
        return self.exit_code

    def build_parser_rename(self, subparsers, common_parser, mid_common_parser):
        from .common import process_epilog

        rename_epilog = process_epilog(
            """
        This command renames an archive in the repository.

        This results in a different archive ID.
        """
        )
        subparser = subparsers.add_parser(
            "rename",
            parents=[common_parser],
            add_help=False,
            description=self.do_rename.__doc__,
            epilog=rename_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="rename archive",
        )
        subparser.set_defaults(func=self.do_rename)
        subparser.add_argument("name", metavar="OLDNAME", type=archivename_validator(), help="specify the archive name")
        subparser.add_argument(
            "newname", metavar="NEWNAME", type=archivename_validator(), help="specify the new archive name"
        )

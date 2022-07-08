import argparse
import textwrap
import sys

from .common import with_repository
from ..constants import *  # NOQA
from ..helpers import Manifest
from ..helpers import BaseFormatter, ArchiveFormatter, json_print, basic_json_data

from ..logger import create_logger

logger = create_logger()


class RListMixIn:
    @with_repository(compatibility=(Manifest.Operation.READ,))
    def do_rlist(self, args, repository, manifest, key):
        """List the archives contained in a repository"""
        if args.format is not None:
            format = args.format
        elif args.short:
            format = "{archive}{NL}"
        else:
            format = "{archive:<36} {time} [{id}]{NL}"
        formatter = ArchiveFormatter(format, repository, manifest, key, json=args.json, iec=args.iec)

        output_data = []

        for archive_info in manifest.archives.list_considering(args):
            if args.json:
                output_data.append(formatter.get_item_data(archive_info))
            else:
                sys.stdout.write(formatter.format_item(archive_info))

        if args.json:
            json_print(basic_json_data(manifest, extra={"archives": output_data}))

        return self.exit_code

    def build_parser_rlist(self, subparsers, common_parser, mid_common_parser):
        from .common import process_epilog, define_archive_filters_group

        rlist_epilog = (
            process_epilog(
                """
        This command lists the archives contained in a repository.

        .. man NOTES

        The FORMAT specifier syntax
        +++++++++++++++++++++++++++

        The ``--format`` option uses python's `format string syntax
        <https://docs.python.org/3.9/library/string.html#formatstrings>`_.

        Examples:
        ::

            $ borg rlist --format '{archive}{NL}'
            ArchiveFoo
            ArchiveBar
            ...

            # {VAR:NUMBER} - pad to NUMBER columns.
            # Strings are left-aligned, numbers are right-aligned.
            # Note: time columns except ``isomtime``, ``isoctime`` and ``isoatime`` cannot be padded.
            $ borg rlist --format '{archive:36} {time} [{id}]{NL}' /path/to/repo
            ArchiveFoo                           Thu, 2021-12-09 10:22:28 [0b8e9a312bef3f2f6e2d0fc110c196827786c15eba0188738e81697a7fa3b274]
            ...

        The following keys are always available:


        """
            )
            + BaseFormatter.keys_help()
            + textwrap.dedent(
                """

        Keys available only when listing archives in a repository:

        """
            )
            + ArchiveFormatter.keys_help()
        )
        subparser = subparsers.add_parser(
            "rlist",
            parents=[common_parser],
            add_help=False,
            description=self.do_rlist.__doc__,
            epilog=rlist_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="list repository contents",
        )
        subparser.set_defaults(func=self.do_rlist)
        subparser.add_argument(
            "--consider-checkpoints",
            action="store_true",
            dest="consider_checkpoints",
            help="Show checkpoint archives in the repository contents list (default: hidden).",
        )
        subparser.add_argument(
            "--short", dest="short", action="store_true", help="only print the archive names, nothing else"
        )
        subparser.add_argument(
            "--format",
            metavar="FORMAT",
            dest="format",
            help="specify format for archive listing " '(default: "{archive:<36} {time} [{id}]{NL}")',
        )
        subparser.add_argument(
            "--json",
            action="store_true",
            help="Format output as JSON. "
            "The form of ``--format`` is ignored, "
            "but keys used in it are added to the JSON output. "
            "Some keys are always present. Note: JSON can only represent text. "
            'A "barchive" key is therefore not available.',
        )
        define_archive_filters_group(subparser)

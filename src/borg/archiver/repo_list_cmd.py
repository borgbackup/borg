import argparse
import os
import textwrap
import sys

from ._common import with_repository, Highlander
from ..constants import *  # NOQA
from ..helpers import BaseFormatter, ArchiveFormatter, json_print, basic_json_data
from ..manifest import Manifest

from ..logger import create_logger

logger = create_logger()


class RepoListMixIn:
    @with_repository(compatibility=(Manifest.Operation.READ,))
    def do_repo_list(self, args, repository, manifest):
        """List the archives contained in a repository"""
        if args.format is not None:
            format = args.format
        elif args.short:
            format = "{id}{NL}"
        else:
            format = os.environ.get(
                "BORG_RLIST_FORMAT",
                "{id:.8}  {time}  {archive:<15}  {tags:<10}  {username:<10}  {hostname:<10}  {comment:.40}{NL}",
            )
        formatter = ArchiveFormatter(format, repository, manifest, manifest.key, iec=args.iec, deleted=args.deleted)

        output_data = []

        for archive_info in manifest.archives.list_considering(args):
            if args.json:
                output_data.append(formatter.get_item_data(archive_info, args.json))
            else:
                sys.stdout.write(formatter.format_item(archive_info, args.json))

        if args.json:
            json_print(basic_json_data(manifest, extra={"archives": output_data}))

    def build_parser_repo_list(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog, define_archive_filters_group

        repo_list_epilog = (
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

            $ borg repo-list --format '{archive}{NL}'
            ArchiveFoo
            ArchiveBar
            ...

            # {VAR:NUMBER} - pad to NUMBER columns.
            # Strings are left-aligned, numbers are right-aligned.
            # Note: time columns except ``isomtime``, ``isoctime`` and ``isoatime`` cannot be padded.
            $ borg repo-list --format '{archive:36} {time} [{id}]{NL}' /path/to/repo
            ArchiveFoo                           Thu, 2021-12-09 10:22:28 [0b8e9...3b274]
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
            "repo-list",
            parents=[common_parser],
            add_help=False,
            description=self.do_repo_list.__doc__,
            epilog=repo_list_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="list repository contents",
        )
        subparser.set_defaults(func=self.do_repo_list)
        subparser.add_argument(
            "--short", dest="short", action="store_true", help="only print the archive IDs, nothing else"
        )
        subparser.add_argument(
            "--format",
            metavar="FORMAT",
            dest="format",
            action=Highlander,
            help="specify format for archive listing " '(default: "{archive:<36} {time} [{id}]{NL}")',
        )
        subparser.add_argument(
            "--json",
            action="store_true",
            help="Format output as JSON. "
            "The form of ``--format`` is ignored, "
            "but keys used in it are added to the JSON output. "
            "Some keys are always present. Note: JSON can only represent text.",
        )
        define_archive_filters_group(subparser, deleted=True)

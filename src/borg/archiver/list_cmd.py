import argparse
import os
import textwrap
import sys

from ._common import with_repository, build_matcher, Highlander
from ..archive import Archive
from ..cache import Cache
from ..constants import *  # NOQA
from ..helpers import ItemFormatter, BaseFormatter, archivename_validator, PathSpec
from ..manifest import Manifest

from ..logger import create_logger

logger = create_logger()


class ListMixIn:
    @with_repository(compatibility=(Manifest.Operation.READ,))
    def do_list(self, args, repository, manifest):
        """List archive contents."""
        matcher = build_matcher(args.patterns, args.paths)
        if args.format is not None:
            format = args.format
        elif args.short:
            format = "{path}{NL}"
        else:
            format = os.environ.get("BORG_LIST_FORMAT", "{mode} {user:6} {group:6} {size:8} {mtime} {path}{extra}{NL}")

        archive_info = manifest.archives.get_one([args.name])

        def _list_inner(cache):
            archive = Archive(manifest, archive_info.id, cache=cache)
            formatter = ItemFormatter(archive, format)

            def item_filter(item):
                # Check if the item matches the patterns/paths.
                if not matcher.match(item.path):
                    return False
                # If depth is specified, also check the depth of the path.
                if args.depth is not None:
                    # Count path separators to determine depth.
                    # For paths like "dir/subdir/file.txt", the depth is 2.
                    path_depth = item.path.count("/")
                    if path_depth > args.depth:
                        return False
                return True

            for item in archive.iter_items(item_filter):
                sys.stdout.write(formatter.format_item(item, args.json_lines, sort=True))

        # Only load the cache if it will be used
        if ItemFormatter.format_needs_cache(format):
            with Cache(repository, manifest) as cache:
                _list_inner(cache)
        else:
            _list_inner(cache=None)

    def build_parser_list(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog, define_exclusion_group

        list_epilog = (
            process_epilog(
                """
        This command lists the contents of an archive.

        For more help on include/exclude patterns, see the output of :ref:`borg_patterns`.

        .. man NOTES

        The FORMAT specifier syntax
        +++++++++++++++++++++++++++

        The ``--format`` option uses Python's `format string syntax
        <https://docs.python.org/3.9/library/string.html#formatstrings>`_.

        Examples:
        ::

            $ borg list --format '{mode} {user:6} {group:6} {size:8} {mtime} {path}{extra}{NL}' ArchiveFoo
            -rw-rw-r-- user   user       1024 Thu, 2021-12-09 10:22:17 file-foo
            ...

            # {VAR:<NUMBER} - pad to NUMBER columns left-aligned.
            # {VAR:>NUMBER} - pad to NUMBER columns right-aligned.
            $ borg list --format '{mode} {user:>6} {group:>6} {size:<8} {mtime} {path}{extra}{NL}' ArchiveFoo
            -rw-rw-r--   user   user 1024     Thu, 2021-12-09 10:22:17 file-foo
            ...

        The following keys are always available:


        """
            )
            + BaseFormatter.keys_help()
            + textwrap.dedent(
                """

        Keys available only when listing files in an archive:

        """
            )
            + ItemFormatter.keys_help()
        )
        subparser = subparsers.add_parser(
            "list",
            parents=[common_parser],
            add_help=False,
            description=self.do_list.__doc__,
            epilog=list_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="list archive contents",
        )
        subparser.set_defaults(func=self.do_list)
        subparser.add_argument(
            "--short", dest="short", action="store_true", help="only print file/directory names, nothing else"
        )
        subparser.add_argument(
            "--format",
            metavar="FORMAT",
            dest="format",
            action=Highlander,
            help="specify format for file listing "
            '(default: "{mode} {user:6} {group:6} {size:8} {mtime} {path}{extra}{NL}")',
        )
        subparser.add_argument(
            "--json-lines",
            action="store_true",
            help="Format output as JSON Lines. "
            "The form of ``--format`` is ignored, "
            "but keys used in it are added to the JSON output. "
            "Some keys are always present. Note: JSON can only represent text.",
        )
        subparser.add_argument(
            "--depth", metavar="N", dest="depth", type=int, help="only list files up to the specified directory depth"
        )
        subparser.add_argument("name", metavar="NAME", type=archivename_validator, help="specify the archive name")
        subparser.add_argument(
            "paths", metavar="PATH", nargs="*", type=PathSpec, help="paths to list; patterns are supported"
        )
        define_exclusion_group(subparser)

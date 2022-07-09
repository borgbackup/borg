import argparse
import textwrap
import sys

from .common import with_repository, build_matcher
from ..archive import Archive
from ..cache import Cache
from ..constants import *  # NOQA
from ..helpers import Manifest
from ..helpers import ItemFormatter, BaseFormatter, NameSpec

from ..logger import create_logger

logger = create_logger()


class ListMixIn:
    @with_repository(compatibility=(Manifest.Operation.READ,))
    def do_list(self, args, repository, manifest, key):
        """List archive contents"""
        matcher = build_matcher(args.patterns, args.paths)
        if args.format is not None:
            format = args.format
        elif args.short:
            format = "{path}{NL}"
        else:
            format = "{mode} {user:6} {group:6} {size:8} {mtime} {path}{extra}{NL}"

        def _list_inner(cache):
            archive = Archive(
                repository, key, manifest, args.name, cache=cache, consider_part_files=args.consider_part_files
            )

            formatter = ItemFormatter(archive, format, json_lines=args.json_lines)
            for item in archive.iter_items(lambda item: matcher.match(item.path)):
                sys.stdout.write(formatter.format_item(item))

        # Only load the cache if it will be used
        if ItemFormatter.format_needs_cache(format):
            with Cache(repository, key, manifest, lock_wait=self.lock_wait) as cache:
                _list_inner(cache)
        else:
            _list_inner(cache=None)

        return self.exit_code

    def build_parser_list(self, subparsers, common_parser, mid_common_parser):
        from .common import process_epilog, define_exclusion_group

        list_epilog = (
            process_epilog(
                """
        This command lists the contents of an archive.

        For more help on include/exclude patterns, see the :ref:`borg_patterns` command output.

        .. man NOTES

        The FORMAT specifier syntax
        +++++++++++++++++++++++++++

        The ``--format`` option uses python's `format string syntax
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
            help="specify format for file listing "
            '(default: "{mode} {user:6} {group:6} {size:8} {mtime} {path}{extra}{NL}")',
        )
        subparser.add_argument(
            "--json-lines",
            action="store_true",
            help="Format output as JSON Lines. "
            "The form of ``--format`` is ignored, "
            "but keys used in it are added to the JSON output. "
            "Some keys are always present. Note: JSON can only represent text. "
            'A "bpath" key is therefore not available.',
        )
        subparser.add_argument("name", metavar="NAME", type=NameSpec, help="specify the archive name")
        subparser.add_argument(
            "paths", metavar="PATH", nargs="*", type=str, help="paths to list; patterns are supported"
        )
        define_exclusion_group(subparser)

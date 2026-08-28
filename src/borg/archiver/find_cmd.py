import os
import textwrap
import sys

from ._common import with_repository, build_matcher, define_archive_filters_group, Highlander
from ..archive import Archive
from ..cache import Cache
from ..constants import *  # NOQA
from ..helpers import ItemFormatter, BaseFormatter, PathSpec
from ..helpers.argparsing import ArgumentParser
from ..manifest import Manifest

from ..logger import create_logger

logger = create_logger()


class FindMixIn:
    @with_repository(compatibility=(Manifest.Operation.READ,))
    def do_find(self, args, repository, manifest):
        """Find files across archives."""
        matcher = build_matcher(args.patterns, args.paths)
        if args.format is not None:
            format = args.format
        else:
            format = os.environ.get(
                "BORG_FIND_FORMAT",
                "{archiveid:.8} {archivename} {mode} {user:6} {group:6} {size:8} {mtime} {path}{extra}{NL}",
            )
        # check the format before doing any work with it (also: the ItemFormatter is only built later)
        ItemFormatter.validate_format(format)

        archive_infos = manifest.archives.list_considering(args, reverse=True)
        num_archives = len(archive_infos)

        def _find_inner(cache):
            for i, info in enumerate(archive_infos):
                logger.info(f"Searching archive {info.name} {info.ts.astimezone()} ({i + 1}/{num_archives})")
                archive = Archive(manifest, info.id, cache=cache)
                formatter = ItemFormatter(archive, format)
                for item in archive.iter_items(lambda item: matcher.match(item.path)):
                    sys.stdout.write(formatter.format_item(item, args.json_lines, sort=True))

        # Only load the cache if it will be used
        if ItemFormatter.format_needs_cache(format):
            with Cache(repository, manifest) as cache:
                _find_inner(cache)
        else:
            _find_inner(cache=None)

    def build_parser_find(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog, define_exclusion_group

        find_epilog = process_epilog(
            textwrap.dedent(
                """
        This command finds files matching the given paths or patterns in the archives
        selected by the usual archive filter options (all archives, if no filters are
        given). It iterates over the matching archives from newest to oldest, over all
        items of each archive, and outputs one line per match, like ``borg list``, but
        prefixed with a short archive ID and the archive name. As the archives of a
        series all share the same name, only the archive ID uniquely identifies the
        archive.

        This makes it easy to answer questions like "which archives contain this file?"
        or "where did that file end up?"::

            $ borg find home/user/file.txt          # in which archives is this file?
            $ borg find 'sh:**/*.jpg' --last 3      # all jpg files in the last 3 archives

        The given PATHs match like in ``borg list`` or ``borg extract``: a plain path
        matches the item with that path as well as everything below it, and the pattern
        styles (``fm:``, ``sh:``, ``re:``, ``pp:``, ``pf:``) are supported as well.
        For more help on include/exclude patterns, see the output of :ref:`borg_patterns`.

        Note: there is no extra index for the file paths, so this command reads the
        metadata of all selected archives, which may take a while for many/big archives.

        .. man NOTES

        The FORMAT specifier syntax
        +++++++++++++++++++++++++++

        The ``--format`` option uses Python's `format string syntax
        <https://docs.python.org/3.11/library/string.html#formatstrings>`_.

        Examples:
        ::

            # only print the archive and the path, nothing else
            $ borg find --format '{archiveid:.8} {archivename} {path}{NL}' 'sh:**/*.jpg'
            20e70e3a photos photos/paris/eiffel.jpg
            ...

        {archiveid:.8} prints a short archive ID (use {archiveid} for the full ID),
        {archivename} the archive name (the archives of a series all share the name).

        The following keys are always available:

        """
            )
            + BaseFormatter.keys_help()
            + textwrap.dedent(
                """

        Keys available only when finding files in an archive:

        """
            )
            + ItemFormatter.keys_help()
        )
        subparser = ArgumentParser(parents=[common_parser], description=self.do_find.__doc__, epilog=find_epilog)
        subparsers.add_subcommand("find", subparser, help="find files across archives")
        subparser.add_argument(
            "--format",
            metavar="FORMAT",
            dest="format",
            action=Highlander,
            help="specify format for file listing (default: "
            '"{archiveid:.8} {archivename} {mode} {user:6} {group:6} {size:8} {mtime} {path}{extra}{NL}")',
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
            "paths", metavar="PATH", nargs="*", type=PathSpec, help="paths to find; patterns are supported"
        )
        define_archive_filters_group(subparser)
        define_exclusion_group(subparser)

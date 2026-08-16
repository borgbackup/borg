import os
import stat
import textwrap
import sys

from ._common import with_repository, build_matcher, Highlander
from ..archive import Archive
from ..cache import Cache
from ..constants import *  # NOQA
from ..helpers import ItemFormatter, BaseFormatter, archivename_validator, PathSpec
from ..helpers.argparsing import ArgumentParser
from ..helpers.sorting import sort_spec_validator, sorted_by_spec
from ..manifest import Manifest

from ..logger import create_logger

logger = create_logger()

# item fields "borg list --sort-by" can sort by
ITEM_SORT_KEYS = ("path", "type", "mode", "user", "uid", "group", "gid", "size", "mtime", "ctime", "atime")
item_sort_spec = sort_spec_validator(ITEM_SORT_KEYS, name="item_sort_spec")


def item_sort_key(field, item):
    """Compute the sort key of item for field, mirroring what ItemFormatter displays."""
    if field == "path":
        return item.path
    if field in ("type", "mode"):
        mode = stat.filemode(item.get("mode", 0))
        return mode[0] if field == "type" else mode
    if field == "size":
        return item.get_size()
    if field in ("uid", "gid"):
        value = item.get(field)
        return -1 if value is None else value
    if field in ("user", "group"):
        value = item.get(field)
        # if the name is not known, ItemFormatter displays the numeric id, so sort by that.
        return str(item.get("uid" if field == "user" else "gid")) if value is None else value
    if field in ("mtime", "ctime", "atime"):
        # raw ns timestamps. ItemFormatter falls back to mtime for a missing atime/ctime, mirror that.
        return item.get(field) or item.get("mtime") or 0
    raise ValueError(f"Invalid sort field name: {field}")


class ListMixIn:
    @with_repository(compatibility=(Manifest.Operation.READ,))
    def do_list(self, args, repository, manifest):
        """List archive contents."""
        # omitting args.pattern_roots here, restricting to paths only by cli args.paths:
        matcher = build_matcher(args.patterns, args.paths)
        if args.format is not None:
            format = args.format
        elif args.short:
            format = "{path}{NL}"
        else:
            format = os.environ.get("BORG_LIST_FORMAT", "{mode} {user:6} {group:6} {size:8} {mtime} {path}{extra}{NL}")
        # check the format before doing any work with it (also: the ItemFormatter is only built later)
        ItemFormatter.validate_format(format)

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

            items = sorted_by_spec(archive.iter_items(item_filter), args.sort_by, item_sort_key)
            for item in items:
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
        <https://docs.python.org/3.11/library/string.html#formatstrings>`_.

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
            + textwrap.dedent(
                """

        Sorting
        +++++++
        Use ``--sort-by SPEC`` where SPEC is a comma-separated list of fields.
        Sorts are applied stably from last to first in the given list, thus the first
        field is the primary sort criterion. Prepend ">" for descending, "<" (or no
        prefix) for ascending order, e.g. ``--sort-by='>size,path'`` (quote it, ">" is
        a shell redirection).

        Supported fields, sorting by the same value that ``--format`` would print:

        - path: the item path
        - type, mode: the file type character resp. the full file mode string
        - user, group: the owner/group name, or the numeric id if the name is not known
        - uid, gid: the numeric owner/group id
        - size: the file size (same as {size}, 0 for items without content)
        - mtime, ctime, atime: the timestamps (atime/ctime fall back to mtime if not stored)

        There is no ``birthtime`` field, as there is no {birthtime} format key either.

        The sort fields are independent of ``--format``, you may sort by a field you do
        not print.

        Note: ``--sort-by`` needs to read all (matching) items into memory before it can
        print anything, so listing a huge archive this way needs a lot of memory and
        delays the first output line. Without ``--sort-by``, items are streamed and their
        order is undefined. If memory usage is a problem, consider
        ``borg list --format ... | sort`` instead.
        """
            )
        )
        subparser = ArgumentParser(parents=[common_parser], description=self.do_list.__doc__, epilog=list_epilog)
        subparsers.add_subcommand("list", subparser, help="list archive contents")
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
        subparser.add_argument(
            "--sort-by",
            metavar="SPEC",
            dest="sort_by",
            type=item_sort_spec,
            action=Highlander,
            help="sort output by comma-separated fields (e.g. '>size,path'), see Sorting below",
        )
        subparser.add_argument("name", metavar="NAME", type=archivename_validator, help="specify the archive name")
        subparser.add_argument(
            "paths", metavar="PATH", nargs="*", type=PathSpec, help="paths to list; patterns are supported"
        )
        define_exclusion_group(subparser)

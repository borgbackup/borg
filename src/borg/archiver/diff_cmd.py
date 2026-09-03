import textwrap
import json
import logging
import sys
import os

from ._common import with_repository, build_matcher, Highlander
from ..archive import Archive
from ..constants import *  # NOQA
from ..helpers import BaseFormatter, DiffFormatter, archivename_validator, PathSpec, BorgJsonEncoder
from ..helpers import IncludePatternNeverMatchedWarning, remove_surrogates
from ..helpers import format_file_size, log_multi
from ..helpers.argparsing import ArgumentParser
from ..helpers.sorting import sort_spec_validator, sorted_by_spec
from ..item import ItemDiff
from ..manifest import Manifest
from ..logger import create_logger

logger = create_logger()

# item diff fields "borg diff --sort-by" can sort by
DIFF_SORT_KEYS = (
    "path",
    "size_added",
    "size_removed",
    "size_diff",
    "size",
    "user",
    "group",
    "uid",
    "gid",
    "ctime",
    "mtime",
    "ctime_diff",
    "mtime_diff",
)
diff_sort_spec = sort_spec_validator(DIFF_SORT_KEYS, name="diff_sort_spec")


class DiffStats:
    """Aggregated statistics over all reported item diffs, for ``borg diff --stats``."""

    def __init__(self):
        self.added_items = 0  # items present in ARCHIVE2 only
        self.removed_items = 0  # items present in ARCHIVE1 only
        self.changed_items = 0  # items present in both archives, but not equal
        self.added_chunk_volume = 0  # size of the content chunks added (by added and by changed items)
        self.removed_chunk_volume = 0  # size of the content chunks removed (by removed and by changed items)
        self.unknown_size_items = 0  # items whose content changed by an unknown amount

    def add(self, diff: ItemDiff, changes: dict) -> None:
        """Account for one item diff, using the already filtered/reported changes."""
        content = changes.get("content")
        if content is not None:
            info = content.to_dict()
            if "added" in info or "removed" in info:
                self.added_chunk_volume += info.get("added", 0)
                self.removed_chunk_volume += info.get("removed", 0)
            else:
                # a "modified" that was determined by comparing the content: no byte counts.
                self.unknown_size_items += 1
        if diff._item1.get("deleted"):
            self.added_items += 1
        elif diff._item2.get("deleted"):
            self.removed_items += 1
        else:
            self.changed_items += 1

    def as_dict(self) -> dict:
        return {
            "added_items": self.added_items,
            "removed_items": self.removed_items,
            "changed_items": self.changed_items,
            "added_chunk_volume": self.added_chunk_volume,
            "removed_chunk_volume": self.removed_chunk_volume,
            "unknown_size_items": self.unknown_size_items,
        }

    def __str__(self) -> str:
        lines = [
            f"Added items: {self.added_items}",
            f"Removed items: {self.removed_items}",
            f"Changed items: {self.changed_items}",
            f"Added chunk volume: {format_file_size(self.added_chunk_volume)}",
            f"Removed chunk volume: {format_file_size(self.removed_chunk_volume)}",
        ]
        if self.unknown_size_items:
            # these items are not accounted for in the added/removed data above, so say so.
            lines.append(f"Items with unknown size changes: {self.unknown_size_items}")
        return "\n".join(lines)


class DiffMixIn:
    @with_repository(compatibility=(Manifest.Operation.READ,))
    def do_diff(self, args, repository, manifest):
        """Finds differences between two archives."""

        def actual_change(j):
            j = j.to_dict()
            if j["type"] == "modified":
                # Added/removed keys will not exist if chunker params differ
                # between the two archives. Err on the side of caution and assume
                # a real modification in this case (short-circuiting retrieving
                # non-existent keys).
                return not {"added", "removed"} <= j.keys() or not (j["added"] == 0 and j["removed"] == 0)
            else:
                # All other change types are indeed changes.
                return True

        def reported_changes(diff):
            """The changes of diff that are actually shown to the user."""
            return {
                name: change
                for name, change in diff.changes().items()
                if actual_change(change) and (not args.content_only or (name not in DiffFormatter.METADATA))
            }

        def print_json_output(diff, changes):
            print(
                json.dumps(
                    {"path": diff.path, "changes": [change.to_dict() for change in changes.values()]},
                    sort_keys=True,
                    cls=BorgJsonEncoder,
                )
            )

        def print_text_output(diff, changes, formatter):
            diff._changes = changes
            res: str = formatter.format_item(diff)
            if res.strip():
                sys.stdout.write(res)

        if args.format is not None:
            format = args.format
        elif args.content_only:
            format = "{content}{link}{directory}{blkdev}{chrdev}{fifo} {path}{NL}"
        else:
            format = os.environ.get("BORG_DIFF_FORMAT", "{change} {path}{NL}")

        archive1_info = manifest.archives.get_one([args.name])
        archive2_info = manifest.archives.get_one([args.other_name])
        archive1 = Archive(manifest, archive1_info.id)
        archive2 = Archive(manifest, archive2_info.id)

        can_compare_chunk_ids = (
            archive1.metadata.get("chunker_params", False) == archive2.metadata.get("chunker_params", True)
            or args.same_chunker_params
        )
        if not can_compare_chunk_ids:
            self.print_warning(
                "--chunker-params might be different between archives, diff will be slow.\n"
                "If you know for certain that they are the same, pass --same-chunker-params "
                "to override this check.",
                wc=None,
            )

        # omitting args.pattern_roots here, restricting to paths only by cli args.paths:
        matcher = build_matcher(args.patterns, args.paths)

        diffs_iter = Archive.compare_archives_iter(
            archive1, archive2, matcher, can_compare_chunk_ids=can_compare_chunk_ids, numeric_ids=args.numeric_ids
        )
        # Filter out equal items early (keep as generator; listify only if sorting)
        diffs = (diff for diff in diffs_iter if not diff.equal(args.content_only))

        def key_for(field: str, d: "ItemDiff"):
            # path
            if field == "path":
                return remove_surrogates(d.path)
            # compute size_* from changes
            if field in ("size_diff", "size_added", "size_removed"):
                added = removed = 0
                ch = d.changes().get("content")
                if ch is not None:
                    info = ch.to_dict()
                    t = info.get("type")
                    if t == "modified":
                        added = info.get("added", 0)
                        removed = info.get("removed", 0)
                    elif t and t.startswith("added"):
                        added = info.get("added", info.get("size", 0))
                        removed = 0
                    elif t and t.startswith("removed"):
                        added = 0
                        removed = info.get("removed", info.get("size", 0))
                if field == "size_diff":
                    return added - removed
                if field == "size_added":
                    return added
                if field == "size_removed":
                    return removed
            # timestamp diffs
            if field in ("ctime_diff", "mtime_diff"):
                ts = field.split("_")[0]
                t1 = d._item1.get(ts, 0)
                t2 = d._item2.get(ts, 0)
                return t2 - t1
            # size of item in archive2
            if field == "size":
                it = d._item2
                if it is None or it.get("deleted"):
                    return 0
                return it.get_size()
            # direct attributes from current item (prefer item2)
            it = d._item2 or d._item1
            attr_defaults = {"user": "", "group": "", "uid": -1, "gid": -1, "ctime": 0, "mtime": 0}
            if field in attr_defaults:
                if it is None:
                    return attr_defaults[field]
                return it.get(field, attr_defaults[field])
            raise ValueError(f"Invalid field name: {field}")

        diffs = sorted_by_spec(diffs, args.sort_by, key_for)

        formatter = DiffFormatter(format, args.content_only)
        stats = DiffStats() if args.stats else None
        for diff in diffs:
            changes = reported_changes(diff)
            if stats is not None and changes:
                # items without any reported change do not show up in the output, so don't count them.
                stats.add(diff, changes)
            if args.json_lines:
                print_json_output(diff, changes)
            else:
                print_text_output(diff, changes, formatter)

        if stats is not None:
            if args.json_lines:
                # a final line of a different shape than the per-path lines, so it is easy to tell apart.
                print(json.dumps({"stats": stats.as_dict()}, sort_keys=True, cls=BorgJsonEncoder))
            else:
                log_multi(str(stats), logger=logging.getLogger("borg.output.stats"))

        for pattern in matcher.get_unmatched_include_patterns():
            self.print_warning_instance(IncludePatternNeverMatchedWarning(pattern))

    def build_parser_diff(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog
        from ._common import define_exclusion_group

        diff_epilog = process_epilog(
            textwrap.dedent(
                """
        This command finds differences (file contents, metadata) between ARCHIVE1 and ARCHIVE2.

        For more help on include/exclude patterns, see the output of the :ref:`borg_patterns` command.

        .. man NOTES

        The FORMAT specifier syntax
        +++++++++++++++++++++++++++

        The ``--format`` option uses Python's `format string syntax
        <https://docs.python.org/3.11/library/string.html#formatstrings>`_.

        Examples:
        ::

            $ borg diff --format '{content:30} {path}{NL}' ArchiveFoo ArchiveBar
            modified:  +4.1 kB  -1.0 kB    file-diff
            ...

            # {VAR:<NUMBER} - pad to NUMBER columns left-aligned.
            # {VAR:>NUMBER} - pad to NUMBER columns right-aligned.
            $ borg diff --format '{content:>30} {path}{NL}' ArchiveFoo ArchiveBar
               modified:  +4.1 kB  -1.0 kB file-diff
            ...

        The following keys are always available:

        """
            )
            + BaseFormatter.keys_help()
            + textwrap.dedent(
                """

        Keys available only when showing differences between archives:

        """
            )
            + DiffFormatter.keys_help()
            + textwrap.dedent(
                """

        What is compared
        +++++++++++++++++
        For each matching item in both archives, Borg reports:

        - Content changes: total added/removed bytes within files. If chunker parameters are comparable,
          Borg compares chunk IDs quickly; otherwise, it compares the content. In the latter case, borg
          can only tell that a file was modified, not by how much: no byte counts are given for it, the
          text output shows "modified:  (can't get size)" instead.
        - Metadata changes: user, group, mode, and other metadata shown inline as "[old -> new]", like
          "[-rw-r--r-- -> -rwxr-xr-x]" for a mode change. Use ``--content-only`` to suppress metadata changes.
        - Added/removed items: printed as "added: SIZE path" or "removed: SIZE path".

        Output formats
        ++++++++++++++
        The default (text) output shows one line per changed path, e.g.::

            modified:    +23 B     -5 B [-rwxr-xr-x -> -rw-r--r--] path/to/file
            added:                  4 B path/to/added-file
            removed:                5 B path/to/removed-file

        JSON Lines output (``--json-lines``) prints one JSON object per changed path, with a list of
        change objects. Each change object has a "type" plus type-specific data: content changes
        ("added", "removed", "modified") carry "added"/"removed" byte counts - except for a
        "modified" that was determined by comparing the content, which carries no counts at all;
        metadata changes ("changed mode", "changed owner", "mtime", ...) carry the old and new
        values as "item1" and "item2". Example::

            {"changes": [{"added": 23, "removed": 5, "type": "modified"}], "path": "path/to/file"}
            {"changes": [{"type": "modified"}], "path": "path/to/other-file"}
            {"changes": [{"item1": "-rw-r--r--", "item2": "-rwxr-xr-x", "type": "changed mode"}], "path": "some/file"}
            {"changes": [{"added": 4, "removed": 0, "type": "added"}], "path": "path/to/added-file"}
            {"changes": [{"added": 0, "removed": 5, "type": "removed"}], "path": "path/to/removed-file"}

        Statistics
        ++++++++++
        With ``--stats``, borg prints a summary of the differences after the per-path output::

            Added items: 23
            Removed items: 2
            Changed items: 315
            Added chunk volume: 53.70 MB
            Removed chunk volume: 51.10 MB

        "Added"/"Removed" items only exist in ARCHIVE2/ARCHIVE1, "changed" items exist in both
        archives but differ. "Added chunk volume"/"Removed chunk volume" sum up the size of the
        content chunks added/removed by all of these items. Items whose content borg could only
        compare byte by byte (see "Performance considerations" below) contribute no byte counts;
        if there are any, an additional "Items with unknown size changes" line reports how many.

        Together with ``--json-lines``, the summary is emitted as a final JSON line of the shape
        ``{"stats": {...}}`` instead, so it is easy to tell apart from the per-path lines
        (wrapped here for readability, borg prints it as a single line)::

            {"stats": {"added_chunk_volume": 53700000, "added_items": 23, "changed_items": 315,
                       "removed_chunk_volume": 51100000, "removed_items": 2, "unknown_size_items": 0}}

        Sorting
        ++++++++
        Use ``--sort-by FIELDS`` where FIELDS is a comma-separated list of fields.
        Sorts are applied stably from last to first in the given list. Prepend ">" for
        descending, "<" (or no prefix) for ascending, for example ``--sort-by=">size_added,path"``.
        Supported fields include:

        - path: the item path
        - size_added: total bytes added for the item content
        - size_removed: total bytes removed for the item content
        - size_diff: size_added - size_removed (net content change)
        - size: size of the item as stored in ARCHIVE2 (0 for removed items)
        - user, group, uid, gid, ctime, mtime: taken from the item state in ARCHIVE2 when present
        - ctime_diff, mtime_diff: timestamp difference (ARCHIVE2 - ARCHIVE1)

        Performance considerations
        ++++++++++++++++++++++++++
        diff automatically detects whether the archives were created with the same chunker
        parameters. If so, only chunk IDs are compared, which is very fast.
        """
            )
        )

        subparser = ArgumentParser(parents=[common_parser], description=self.do_diff.__doc__, epilog=diff_epilog)
        subparsers.add_subcommand("diff", subparser, help="find differences in archive contents")
        subparser.add_argument(
            "--numeric-ids",
            dest="numeric_ids",
            action="store_true",
            help="only consider numeric user and group identifiers",
        )
        subparser.add_argument(
            "--same-chunker-params",
            dest="same_chunker_params",
            action="store_true",
            help="override the check of chunker parameters",
        )
        subparser.add_argument(
            "--format",
            metavar="FORMAT",
            dest="format",
            action=Highlander,
            help='specify format for differences between archives (default: "{change} {path}{NL}")',
        )
        subparser.add_argument("--json-lines", action="store_true", help="Format output as JSON Lines.")
        subparser.add_argument(
            "-s", "--stats", dest="stats", action="store_true", help="print a summary of the differences at the end"
        )
        subparser.add_argument(
            "--sort-by",
            dest="sort_by",
            type=diff_sort_spec,
            action=Highlander,
            help="Sort output by comma-separated fields (e.g., '>size_added,path').",
        )
        subparser.add_argument(
            "--content-only",
            action="store_true",
            help="Only compare differences in content (exclude metadata differences)",
        )
        subparser.add_argument("name", metavar="ARCHIVE1", type=archivename_validator, help="ARCHIVE1 name")
        subparser.add_argument("other_name", metavar="ARCHIVE2", type=archivename_validator, help="ARCHIVE2 name")
        subparser.add_argument(
            "paths",
            metavar="PATH",
            nargs="*",
            type=PathSpec,
            help="paths of items inside the archives to compare; patterns are supported.",
        )
        define_exclusion_group(subparser)

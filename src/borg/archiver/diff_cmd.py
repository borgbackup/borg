import argparse

import textwrap
import json
import sys
import os

from ._common import with_repository, build_matcher
from ..archive import Archive
from ..constants import *  # NOQA
from ..helpers import BaseFormatter, DiffFormatter, archivename_validator, PathSpec, BorgJsonEncoder
from ..helpers import IncludePatternNeverMatchedWarning, remove_surrogates
from ..helpers.jap_wrapper import ArgumentParser
from ..item import ItemDiff
from ..manifest import Manifest
from ..logger import create_logger

logger = create_logger()


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

        def print_json_output(diff):
            print(
                json.dumps(
                    {
                        "path": diff.path,
                        "changes": [
                            change.to_dict()
                            for name, change in diff.changes().items()
                            if actual_change(change) and (not args.content_only or (name not in DiffFormatter.METADATA))
                        ],
                    },
                    sort_keys=True,
                    cls=BorgJsonEncoder,
                )
            )

        def print_text_output(diff, formatter):
            actual_changes = {
                name: change
                for name, change in diff.changes().items()
                if actual_change(change) and (not args.content_only or (name not in DiffFormatter.METADATA))
            }
            diff._changes = actual_changes
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

        matcher = build_matcher(args.patterns, args.paths)

        diffs_iter = Archive.compare_archives_iter(
            archive1, archive2, matcher, can_compare_chunk_ids=can_compare_chunk_ids
        )
        # Filter out equal items early (keep as generator; listify only if sorting)
        diffs = (diff for diff in diffs_iter if not diff.equal(args.content_only))

        sort_specs = []
        if args.sort_by:
            for spec in args.sort_by.split(","):
                spec = spec.strip()
                if spec:
                    sort_specs.append(spec)

        def key_for(field: str, d: "ItemDiff"):
            # strip direction markers if present
            if field and field[0] in ("<", ">"):
                field = field[1:]
            # path
            if field in (None, "", "path"):
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

        if sort_specs:
            diffs = list(diffs)
            # Apply stable sorts from last to first
            for spec in reversed(sort_specs):
                desc = False
                field = spec
                if field and field[0] in ("<", ">"):
                    desc = field[0] == ">"
                diffs.sort(key=lambda di: key_for(field, di), reverse=desc)

        formatter = DiffFormatter(format, args.content_only)
        for diff in diffs:
            if args.json_lines:
                print_json_output(diff)
            else:
                print_text_output(diff, formatter)

        for pattern in matcher.get_unmatched_include_patterns():
            self.print_warning_instance(IncludePatternNeverMatchedWarning(pattern))

    def build_parser_diff(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog
        from ._common import define_exclusion_group

        diff_epilog = (
            process_epilog(
                """
        This command finds differences (file contents, metadata) between ARCHIVE1 and ARCHIVE2.

        For more help on include/exclude patterns, see the output of the :ref:`borg_patterns` command.

        .. man NOTES

        The FORMAT specifier syntax
        +++++++++++++++++++++++++++

        The ``--format`` option uses Python's `format string syntax
        <https://docs.python.org/3.10/library/string.html#formatstrings>`_.

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
          Borg compares chunk IDs quickly; otherwise, it compares the content.
        - Metadata changes: user, group, mode, and other metadata shown inline, like
          "[old_mode -> new_mode]" for mode changes. Use ``--content-only`` to suppress metadata changes.
        - Added/removed items: printed as "added SIZE path" or "removed SIZE path".

        Output formats
        ++++++++++++++
        The default (text) output shows one line per changed path, e.g.::

            +135 B    -252 B [ -rw-r--r-- -> -rwxr-xr-x ] path/to/file

        JSON Lines output (``--json-lines``) prints one JSON object per changed path, e.g.::

            {"path": "PATH", "changes": [
                {"type": "modified", "added": BYTES, "removed": BYTES},
                {"type": "mode", "old_mode": "-rw-r--r--", "new_mode": "-rwxr-xr-x"},
                {"type": "added", "size": SIZE},
                {"type": "removed", "size": SIZE}
            ]}

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

        def diff_sort_spec_validator(s):
            if not isinstance(s, str):
                raise argparse.ArgumentTypeError("unsupported sort field (not a string)")
            allowed = {
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
            }
            parts = [p.strip() for p in s.split(",") if p.strip()]
            if not parts:
                raise argparse.ArgumentTypeError("unsupported sort field: empty spec")
            for spec in parts:
                field = spec[1:] if spec and spec[0] in (">", "<") else spec
                if field not in allowed:
                    raise argparse.ArgumentTypeError(f"unsupported sort field: {field}")
            return ",".join(parts)

        subparser = ArgumentParser(
            parents=[common_parser],
            add_help=False,
            description=self.do_diff.__doc__,
            epilog=diff_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )

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
            help='specify format for differences between archives (default: "{change} {path}{NL}")',
        )
        subparser.add_argument("--json-lines", action="store_true", help="Format output as JSON Lines.")
        subparser.add_argument(
            "--sort-by",
            dest="sort_by",
            type=diff_sort_spec_validator,
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

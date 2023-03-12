import argparse
import textwrap
import json
from typing import Dict

from ._common import with_repository, with_archive, build_matcher
from ..archive import Archive
from ..constants import *  # NOQA
from ..helpers import BaseFormatter, DiffFormatter, archivename_validator
from ..manifest import Manifest
from ..helpers.parseformat import BorgJsonEncoder
from ..item import DiffChange
from ..logger import create_logger

logger = create_logger()


class DiffMixIn:
    @with_repository(compatibility=(Manifest.Operation.READ,))
    @with_archive
    def do_diff(self, args, repository, manifest, archive):
        """Diff contents of two archives"""
        if args.format is not None:
            format: str = args.format
        elif args.content_only:
            format = "{change} {path}{NL}"
        else:
            format = "{flag} {change} {mtime} {path}{NL}"

        def print_json_output(diffs: Dict[str, DiffChange], path: str):
            print(json.dumps({"path": path, "changes": [diff.to_dict() for diff in diffs.values()]}, sort_keys=True, cls=BorgJsonEncoder))

        def print_text_output(diffs: Dict[str, DiffChange], path: str):
            changes = []
            # TODO: use DiffFormatter
            for name, diff in diffs.items():
                if name == "ctime":
                    changes.append("[{}: {} -> {}]".format(diff.flag, diff.origin['past'], diff.origin['current']))
                if name == "mtime":
                    changes.append("[{}: {} -> {}]".format(diff.flag, diff.origin['past'], diff.origin['current']))
                if name == "content":
                    if diff.flag == "added":
                        changes.append("{}: {}".format(diff.flag, diff.origin['added']))
                    elif diff.flag == "removed":
                        changes.append("{}: {}".format(diff.flag, diff.origin['removed']))
                    else:
                        changes.append("{}: +{} -{}".format(diff.flag, diff.origin['added'], diff.origin['removed']))
            print("{:<19} {}".format(" ".join(changes), path))

        print_output = print_json_output if args.json_lines else print_text_output

        archive1 = archive
        archive2 = Archive(manifest, args.other_name)

        can_compare_chunk_ids = (
            archive1.metadata.get("chunker_params", False) == archive2.metadata.get("chunker_params", True)
            or args.same_chunker_params
        )
        if not can_compare_chunk_ids:
            self.print_warning(
                "--chunker-params might be different between archives, diff will be slow.\n"
                "If you know for certain that they are the same, pass --same-chunker-params "
                "to override this check."
            )

        matcher = build_matcher(args.patterns, args.paths)
        
        diffs_iter = Archive.compare_archives_iter(
            archive1, archive2, matcher, can_compare_chunk_ids=can_compare_chunk_ids
        )
        # Conversion to string and filtering for diff.equal to save memory if sorting
        diffs_list = [(diff.path, diff.changes()) for diff in diffs_iter if not diff.equal]

        if args.sort:
            diffs_list.sort()

        for path, diffs in diffs_list:
            print_output(diffs, path)

        for pattern in matcher.get_unmatched_include_patterns():
            self.print_warning("Include pattern '%s' never matched.", pattern)

        return self.exit_code

    def build_parser_diff(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog
        from ._common import define_exclusion_group

        diff_epilog = (
            process_epilog(
                """
        This command finds differences (file contents, user/group/mode) between archives.

        A repository location and an archive name must be specified for REPO::ARCHIVE1.
        ARCHIVE2 is just another archive name in same repository (no repository location
        allowed).

        For archives created with Borg 1.1 or newer diff automatically detects whether
        the archives are created with the same chunker params. If so, only chunk IDs
        are compared, which is very fast.

        For archives prior to Borg 1.1 chunk contents are compared by default.
        If you did not create the archives with different chunker params,
        pass ``--same-chunker-params``.
        Note that the chunker params changed from Borg 0.xx to 1.0.

        For more help on include/exclude patterns, see the :ref:`borg_patterns` command output.
        
        .. man NOTES

        The FORMAT specifier syntax
        +++++++++++++++++++++++++++

        The ``--format`` option uses python's `format string syntax
        <https://docs.python.org/3.9/library/string.html#formatstrings>`_.

        Examples:
        ::

            $ borg diff --format '{flag} {content:8} {mtime} {path}{NL}' ArchiveFoo ArchiveBar
            modified +1.7 kB -1.7 kB Wed, 2023-02-22 00:06:51 +0800 -> Sat, 2023-03-11 13:34:35 +0800 file-diff
            ...

            # {VAR:<NUMBER} - pad to NUMBER columns left-aligned.
            # {VAR:>NUMBER} - pad to NUMBER columns right-aligned.
            $ borg diff --format '{flag} {content:<8} {mtime} {path}{NL}' ArchiveFoo ArchiveBar
            modified +1.7 kB -1.7 kB Wed, 2023-02-22 00:06:51 +0800 -> Sat, 2023-03-11 13:34:35 +0800 file-diff
            ...

        The following keys are always available:


        """
            )
            + BaseFormatter.keys_help()
            + textwrap.dedent(
                """

        Keys available only when show differences between archives:

        """
            )
            # TODO: impl DiffFormatter
            + DiffFormatter.keys_help()
        )
        subparser = subparsers.add_parser(
            "diff",
            parents=[common_parser],
            add_help=False,
            description=self.do_diff.__doc__,
            epilog=diff_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="find differences in archive contents",
        )
        subparser.set_defaults(func=self.do_diff)
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
            help="Override check of chunker parameters.",
        )
        subparser.add_argument("--sort", dest="sort", action="store_true", help="Sort the output lines by file path.")
        subparser.add_argument(
            "--format",
            metavar="FORMAT",
            dest="format",
            help="specify format for differences between archives"
            '(default: "{flag} {content} {mtime} {path}{NL}")',
        )
        subparser.add_argument("--json-lines", action="store_true", help="Format output as JSON Lines. ")
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
            type=str,
            help="paths of items inside the archives to compare; patterns are supported",
        )
        define_exclusion_group(subparser)

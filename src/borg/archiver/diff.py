import argparse
import json

from .common import with_repository, with_archive, build_matcher
from ..archive import Archive
from ..constants import *  # NOQA
from ..helpers import archivename_validator
from ..helpers import Manifest

from ..logger import create_logger

logger = create_logger()


class DiffMixIn:
    @with_repository(compatibility=(Manifest.Operation.READ,))
    @with_archive
    def do_diff(self, args, repository, manifest, key, archive):
        """Diff contents of two archives"""

        def print_json_output(diff, path):
            print(json.dumps({"path": path, "changes": [j for j, str in diff]}))

        def print_text_output(diff, path):
            print("{:<19} {}".format(" ".join([str for j, str in diff]), path))

        print_output = print_json_output if args.json_lines else print_text_output

        archive1 = archive
        archive2 = Archive(repository, key, manifest, args.other_name, consider_part_files=args.consider_part_files)

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

        diffs = Archive.compare_archives_iter(archive1, archive2, matcher, can_compare_chunk_ids=can_compare_chunk_ids)
        # Conversion to string and filtering for diff.equal to save memory if sorting
        diffs = ((path, diff.changes()) for path, diff in diffs if not diff.equal)

        if args.sort:
            diffs = sorted(diffs)

        for path, diff in diffs:
            print_output(diff, path)

        for pattern in matcher.get_unmatched_include_patterns():
            self.print_warning("Include pattern '%s' never matched.", pattern)

        return self.exit_code

    def build_parser_diff(self, subparsers, common_parser, mid_common_parser):

        from .common import process_epilog
        from .common import define_exclusion_group

        diff_epilog = process_epilog(
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
            """
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
        subparser.add_argument("--json-lines", action="store_true", help="Format output as JSON Lines. ")
        subparser.add_argument("name", metavar="ARCHIVE1", type=archivename_validator(), help="ARCHIVE1 name")
        subparser.add_argument("other_name", metavar="ARCHIVE2", type=archivename_validator(), help="ARCHIVE2 name")
        subparser.add_argument(
            "paths",
            metavar="PATH",
            nargs="*",
            type=str,
            help="paths of items inside the archives to compare; patterns are supported",
        )
        define_exclusion_group(subparser)

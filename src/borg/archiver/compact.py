import argparse

from .common import with_repository
from ..constants import *  # NOQA
from ..helpers import EXIT_SUCCESS
from ..helpers import Manifest

from ..logger import create_logger

logger = create_logger()


class CompactMixIn:
    @with_repository(manifest=False, exclusive=True)
    def do_compact(self, args, repository):
        """compact segment files in the repository"""
        # see the comment in do_with_lock about why we do it like this:
        data = repository.get(Manifest.MANIFEST_ID)
        repository.put(Manifest.MANIFEST_ID, data)
        threshold = args.threshold / 100
        repository.commit(compact=True, threshold=threshold)
        return EXIT_SUCCESS

    def build_parser_compact(self, subparsers, common_parser, mid_common_parser):

        from .common import process_epilog

        compact_epilog = process_epilog(
            """
        This command frees repository space by compacting segments.

        Use this regularly to avoid running out of space - you do not need to use this
        after each borg command though. It is especially useful after deleting archives,
        because only compaction will really free repository space.

        borg compact does not need a key, so it is possible to invoke it from the
        client or also from the server.

        Depending on the amount of segments that need compaction, it may take a while,
        so consider using the ``--progress`` option.

        A segment is compacted if the amount of saved space is above the percentage value
        given by the ``--threshold`` option. If omitted, a threshold of 10% is used.
        When using ``--verbose``, borg will output an estimate of the freed space.

        See :ref:`separate_compaction` in Additional Notes for more details.
        """
        )
        subparser = subparsers.add_parser(
            "compact",
            parents=[common_parser],
            add_help=False,
            description=self.do_compact.__doc__,
            epilog=compact_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="compact segment files / free space in repo",
        )
        subparser.set_defaults(func=self.do_compact)
        subparser.add_argument(
            "--threshold",
            metavar="PERCENT",
            dest="threshold",
            type=int,
            default=10,
            help="set minimum threshold for saved space in PERCENT (Default: 10)",
        )

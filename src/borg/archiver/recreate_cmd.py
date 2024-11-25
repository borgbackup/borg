import argparse

from ._common import with_repository, Highlander
from ._common import build_matcher
from ..archive import ArchiveRecreater
from ..constants import *  # NOQA
from ..compress import CompressionSpec
from ..helpers import archivename_validator, comment_validator, PathSpec, ChunkerParams, bin_to_hex
from ..helpers import timestamp
from ..manifest import Manifest

from ..logger import create_logger

logger = create_logger()


class RecreateMixIn:
    @with_repository(cache=True, compatibility=(Manifest.Operation.CHECK,))
    def do_recreate(self, args, repository, manifest, cache):
        """Re-create archives"""
        matcher = build_matcher(args.patterns, args.paths)
        self.output_list = args.output_list
        self.output_filter = args.output_filter

        recreater = ArchiveRecreater(
            manifest,
            cache,
            matcher,
            exclude_caches=args.exclude_caches,
            exclude_if_present=args.exclude_if_present,
            keep_exclude_tags=args.keep_exclude_tags,
            chunker_params=args.chunker_params,
            compression=args.compression,
            progress=args.progress,
            stats=args.stats,
            file_status_printer=self.print_file_status,
            dry_run=args.dry_run,
            timestamp=args.timestamp,
        )
        archive_infos = manifest.archives.list_considering(args)
        archive_infos = [ai for ai in archive_infos if "@PROT" not in ai.tags]
        for archive_info in archive_infos:
            if recreater.is_temporary_archive(archive_info.name):
                continue
            name, hex_id = archive_info.name, bin_to_hex(archive_info.id)
            print(f"Processing {name} {hex_id}")
            if args.target:
                target = args.target
                delete_original = False
            else:
                target = archive_info.name
                delete_original = True
            if not recreater.recreate(archive_info.id, target, delete_original, args.comment):
                logger.info(f"Skipped archive {name} {hex_id}: Nothing to do.")
        if not args.dry_run:
            manifest.write()

    def build_parser_recreate(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog
        from ._common import define_exclusion_group, define_archive_filters_group

        recreate_epilog = process_epilog(
            """
        Recreate the contents of existing archives.

        recreate is a potentially dangerous function and might lead to data loss
        (if used wrongly). BE VERY CAREFUL!

        Important: Repository disk space is **not** freed until you run ``borg compact``.

        ``--exclude``, ``--exclude-from``, ``--exclude-if-present``, ``--keep-exclude-tags``
        and PATH have the exact same semantics as in "borg create", but they only check
        for files in the archives and not in the local file system. If PATHs are specified,
        the resulting archives will only contain files from these PATHs.

        Note that all paths in an archive are relative, therefore absolute patterns/paths
        will *not* match (``--exclude``, ``--exclude-from``, PATHs).

        ``--chunker-params`` will re-chunk all files in the archive, this can be
        used to have upgraded Borg 0.xx archives deduplicate with Borg 1.x archives.

        **USE WITH CAUTION.**
        Depending on the PATHs and patterns given, recreate can be used to
        delete files from archives permanently.
        When in doubt, use ``--dry-run --verbose --list`` to see how patterns/PATHS are
        interpreted. See :ref:`list_item_flags` in ``borg create`` for details.

        The archive being recreated is only removed after the operation completes. The
        archive that is built during the operation exists at the same time at
        "<ARCHIVE>.recreate". The new archive will have a different archive ID.

        With ``--target`` the original archive is not replaced, instead a new archive is created.

        When rechunking, space usage can be substantial - expect
        at least the entire deduplicated size of the archives using the previous
        chunker params.

        If your most recent borg check found missing chunks, please first run another
        backup for the same data, before doing any rechunking. If you are lucky, that
        will re-create the missing chunks. Optionally, do another borg check, to see
        if the chunks are still missing).
        """
        )
        subparser = subparsers.add_parser(
            "recreate",
            parents=[common_parser],
            add_help=False,
            description=self.do_recreate.__doc__,
            epilog=recreate_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help=self.do_recreate.__doc__,
        )
        subparser.set_defaults(func=self.do_recreate)
        subparser.add_argument(
            "--list", dest="output_list", action="store_true", help="output verbose list of items (files, dirs, ...)"
        )
        subparser.add_argument(
            "--filter",
            metavar="STATUSCHARS",
            dest="output_filter",
            action=Highlander,
            help="only display items with the given status characters (listed in borg create --help)",
        )
        subparser.add_argument("-n", "--dry-run", dest="dry_run", action="store_true", help="do not change anything")
        subparser.add_argument("-s", "--stats", dest="stats", action="store_true", help="print statistics at end")

        define_exclusion_group(subparser, tag_files=True)

        archive_group = define_archive_filters_group(subparser)
        archive_group.add_argument(
            "--target",
            dest="target",
            metavar="TARGET",
            default=None,
            type=archivename_validator,
            action=Highlander,
            help="create a new archive with the name ARCHIVE, do not replace existing archive",
        )
        archive_group.add_argument(
            "--comment",
            metavar="COMMENT",
            dest="comment",
            type=comment_validator,
            default=None,
            action=Highlander,
            help="add a comment text to the archive",
        )
        archive_group.add_argument(
            "--timestamp",
            metavar="TIMESTAMP",
            dest="timestamp",
            type=timestamp,
            default=None,
            action=Highlander,
            help="manually specify the archive creation date/time (yyyy-mm-ddThh:mm:ss[(+|-)HH:MM] format, "
            "(+|-)HH:MM is the UTC offset, default: local time zone). Alternatively, give a reference file/directory.",
        )
        archive_group.add_argument(
            "-C",
            "--compression",
            metavar="COMPRESSION",
            dest="compression",
            type=CompressionSpec,
            default=CompressionSpec("lz4"),
            action=Highlander,
            help="select compression algorithm, see the output of the " '"borg help compression" command for details.',
        )
        archive_group.add_argument(
            "--chunker-params",
            metavar="PARAMS",
            dest="chunker_params",
            type=ChunkerParams,
            default=None,
            action=Highlander,
            help="rechunk using given chunker parameters (ALGO, CHUNK_MIN_EXP, CHUNK_MAX_EXP, "
            "HASH_MASK_BITS, HASH_WINDOW_SIZE) or `default` to use the chunker defaults. "
            "default: do not rechunk",
        )

        subparser.add_argument(
            "paths", metavar="PATH", nargs="*", type=PathSpec, help="paths to recreate; patterns are supported"
        )

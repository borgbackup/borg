import argparse

from .common import with_repository, Highlander
from .common import build_matcher
from ..archive import ArchiveRecreater
from ..constants import *  # NOQA
from ..compress import CompressionSpec
from ..helpers import archivename_validator, ChunkerParams
from ..helpers import CommentSpec
from ..helpers import timestamp
from ..helpers import Manifest

from ..logger import create_logger

logger = create_logger()


class RecreateMixIn:
    @with_repository(cache=True, exclusive=True, compatibility=(Manifest.Operation.CHECK,))
    def do_recreate(self, args, repository, manifest, key, cache):
        """Re-create archives"""
        matcher = build_matcher(args.patterns, args.paths)
        self.output_list = args.output_list
        self.output_filter = args.output_filter
        recompress = args.recompress != "never"
        always_recompress = args.recompress == "always"

        recreater = ArchiveRecreater(
            repository,
            manifest,
            key,
            cache,
            matcher,
            exclude_caches=args.exclude_caches,
            exclude_if_present=args.exclude_if_present,
            keep_exclude_tags=args.keep_exclude_tags,
            chunker_params=args.chunker_params,
            compression=args.compression,
            recompress=recompress,
            always_recompress=always_recompress,
            progress=args.progress,
            stats=args.stats,
            file_status_printer=self.print_file_status,
            checkpoint_interval=args.checkpoint_interval,
            dry_run=args.dry_run,
            timestamp=args.timestamp,
        )

        archive_names = tuple(archive.name for archive in manifest.archives.list_considering(args))
        if args.target is not None and len(archive_names) != 1:
            self.print_error("--target: Need to specify single archive")
            return self.exit_code
        for name in archive_names:
            if recreater.is_temporary_archive(name):
                continue
            print("Processing", name)
            if not recreater.recreate(name, args.comment, args.target):
                logger.info("Skipped archive %s: Nothing to do. Archive was not processed.", name)
        if not args.dry_run:
            manifest.write()
            repository.commit(compact=False)
            cache.commit()
        return self.exit_code

    def build_parser_recreate(self, subparsers, common_parser, mid_common_parser):
        from .common import process_epilog
        from .common import define_exclusion_group, define_archive_filters_group

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

        ``--recompress`` allows one to change the compression of existing data in archives.
        Due to how Borg stores compressed size information this might display
        incorrect information for archives that were not recreated at the same time.
        There is no risk of data loss by this.

        ``--chunker-params`` will re-chunk all files in the archive, this can be
        used to have upgraded Borg 0.xx archives deduplicate with Borg 1.x archives.

        **USE WITH CAUTION.**
        Depending on the PATHs and patterns given, recreate can be used to permanently
        delete files from archives.
        When in doubt, use ``--dry-run --verbose --list`` to see how patterns/PATHS are
        interpreted. See :ref:`list_item_flags` in ``borg create`` for details.

        The archive being recreated is only removed after the operation completes. The
        archive that is built during the operation exists at the same time at
        "<ARCHIVE>.recreate". The new archive will have a different archive ID.

        With ``--target`` the original archive is not replaced, instead a new archive is created.

        When rechunking (or recompressing), space usage can be substantial - expect
        at least the entire deduplicated size of the archives using the previous
        chunker (or compression) params.

        If you recently ran borg check --repair and it had to fix lost chunks with all-zero
        replacement chunks, please first run another backup for the same data and re-run
        borg check --repair afterwards to heal any archives that had lost chunks which are
        still generated from the input data.

        Important: running borg recreate to re-chunk will remove the chunks_healthy
        metadata of all items with replacement chunks, so healing will not be possible
        any more after re-chunking (it is also unlikely it would ever work: due to the
        change of chunking parameters, the missing chunk likely will never be seen again
        even if you still have the data that produced it).
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
            type=archivename_validator(),
            help="create a new archive with the name ARCHIVE, do not replace existing archive "
            "(only applies for a single archive)",
        )
        archive_group.add_argument(
            "-c",
            "--checkpoint-interval",
            dest="checkpoint_interval",
            type=int,
            default=1800,
            metavar="SECONDS",
            help="write checkpoint every SECONDS seconds (Default: 1800)",
        )
        archive_group.add_argument(
            "--comment",
            dest="comment",
            metavar="COMMENT",
            type=CommentSpec,
            default=None,
            help="add a comment text to the archive",
        )
        archive_group.add_argument(
            "--timestamp",
            metavar="TIMESTAMP",
            dest="timestamp",
            type=timestamp,
            default=None,
            help="manually specify the archive creation date/time (UTC, yyyy-mm-ddThh:mm:ss format). "
            "alternatively, give a reference file/directory.",
        )
        archive_group.add_argument(
            "-C",
            "--compression",
            metavar="COMPRESSION",
            dest="compression",
            type=CompressionSpec,
            default=CompressionSpec("lz4"),
            help="select compression algorithm, see the output of the " '"borg help compression" command for details.',
        )
        archive_group.add_argument(
            "--recompress",
            metavar="MODE",
            dest="recompress",
            nargs="?",
            default="never",
            const="if-different",
            choices=("never", "if-different", "always"),
            help="recompress data chunks according to `MODE` and ``--compression``. "
            "Possible modes are "
            "`if-different`: recompress if current compression is with a different "
            "compression algorithm or different level; "
            "`always`: recompress unconditionally; and "
            "`never`: do not recompress (use this option to explicitly prevent "
            "recompression). "
            "If no MODE is given, `if-different` will be used. "
            'Not passing --recompress is equivalent to "--recompress never".',
        )
        archive_group.add_argument(
            "--chunker-params",
            metavar="PARAMS",
            dest="chunker_params",
            action=Highlander,
            type=ChunkerParams,
            default=CHUNKER_PARAMS,
            help="specify the chunker parameters (ALGO, CHUNK_MIN_EXP, CHUNK_MAX_EXP, "
            "HASH_MASK_BITS, HASH_WINDOW_SIZE) or `default` to use the current defaults. "
            "default: %s,%d,%d,%d,%d" % CHUNKER_PARAMS,
        )

        subparser.add_argument(
            "paths", metavar="PATH", nargs="*", type=str, help="paths to recreate; patterns are supported"
        )

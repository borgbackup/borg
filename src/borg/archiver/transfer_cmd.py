import argparse

from ._common import with_repository, with_other_repository, Highlander
from ..archive import Archive
from ..compress import CompressionSpec
from ..constants import *  # NOQA
from ..crypto.key import uses_same_id_hash, uses_same_chunker_secret
from ..helpers import Error
from ..helpers import location_validator, Location, archivename_validator, comment_validator
from ..helpers import format_file_size
from ..manifest import Manifest

from ..logger import create_logger

logger = create_logger()


class TransferMixIn:
    @with_other_repository(manifest=True, compatibility=(Manifest.Operation.READ,))
    @with_repository(exclusive=True, manifest=True, cache=True, compatibility=(Manifest.Operation.WRITE,))
    def do_transfer(self, args, *, repository, manifest, cache, other_repository=None, other_manifest=None):
        """archives transfer from other repository, optionally upgrade data format"""
        key = manifest.key
        other_key = other_manifest.key
        if not uses_same_id_hash(other_key, key):
            raise Error(
                "You must keep the same ID hash ([HMAC-]SHA256 or BLAKE2b) or deduplication will break. "
                "Use a related repository!"
            )
        if not uses_same_chunker_secret(other_key, key):
            raise Error(
                "You must use the same chunker secret or deduplication will break. " "Use a related repository!"
            )

        dry_run = args.dry_run
        args.consider_checkpoints = True
        archive_names = tuple(x.name for x in other_manifest.archives.list_considering(args))
        if not archive_names:
            return

        an_errors = []
        for archive_name in archive_names:
            try:
                archivename_validator(archive_name)
            except argparse.ArgumentTypeError as err:
                an_errors.append(str(err))
        if an_errors:
            an_errors.insert(0, "Invalid archive names detected, please rename them before transfer:")
            raise Error("\n".join(an_errors))

        ac_errors = []
        for archive_name in archive_names:
            archive = Archive(other_manifest, archive_name)
            try:
                comment_validator(archive.metadata.get("comment", ""))
            except argparse.ArgumentTypeError as err:
                ac_errors.append(f"{archive_name}: {err}")
        if ac_errors:
            ac_errors.insert(0, "Invalid archive comments detected, please fix them before transfer:")
            raise Error("\n".join(ac_errors))

        from .. import upgrade as upgrade_mod

        try:
            UpgraderCls = getattr(upgrade_mod, f"Upgrader{args.upgrader}")
        except AttributeError:
            raise Error(f"No such upgrader: {args.upgrader}")

        if UpgraderCls is not upgrade_mod.UpgraderFrom12To20 and other_manifest.repository.version == 1:
            raise Error("To transfer from a borg 1.x repo, you need to use: --upgrader=From12To20")

        upgrader = UpgraderCls(cache=cache)

        for name in archive_names:
            transfer_size = 0
            present_size = 0
            if name in manifest.archives and not dry_run:
                print(f"{name}: archive is already present in destination repo, skipping.")
            else:
                if not dry_run:
                    print(f"{name}: copying archive to destination repo...")
                other_archive = Archive(other_manifest, name)
                archive = (
                    Archive(manifest, name, cache=cache, create=True, progress=args.progress) if not dry_run else None
                )
                upgrader.new_archive(archive=archive)
                for item in other_archive.iter_items():
                    is_part = bool(item.get("part", False))
                    if is_part:
                        # borg 1.x created part files while checkpointing (in addition to the full
                        # file in the final archive), like <filename>.borg_part_<part> with item.part >= 1.
                        # borg2 archives do not have such special part items anymore.
                        # so let's remove them from old archives also, considering there is no
                        # code any more that deals with them in special ways (e.g. to get stats right).
                        continue
                    if "chunks" in item:
                        chunks = []
                        for chunk_id, size in item.chunks:
                            refcount = cache.seen_chunk(chunk_id, size)
                            if refcount == 0:  # target repo does not yet have this chunk
                                if not dry_run:
                                    cdata = other_repository.get(chunk_id)
                                    if args.recompress == "never":
                                        # keep compressed payload same, verify via assert_id (that will
                                        # decompress, but avoid needing to compress it again):
                                        meta, data = other_manifest.repo_objs.parse(
                                            chunk_id,
                                            cdata,
                                            decompress=True,
                                            want_compressed=True,
                                            ro_type=ROBJ_FILE_STREAM,
                                        )
                                        meta, data = upgrader.upgrade_compressed_chunk(meta, data)
                                        chunk_entry = cache.add_chunk(
                                            chunk_id,
                                            meta,
                                            data,
                                            stats=archive.stats,
                                            wait=False,
                                            compress=False,
                                            size=size,
                                            ctype=meta["ctype"],
                                            clevel=meta["clevel"],
                                            ro_type=ROBJ_FILE_STREAM,
                                        )
                                    elif args.recompress == "always":
                                        # always decompress and re-compress file data chunks
                                        meta, data = other_manifest.repo_objs.parse(
                                            chunk_id, cdata, ro_type=ROBJ_FILE_STREAM
                                        )
                                        chunk_entry = cache.add_chunk(
                                            chunk_id,
                                            meta,
                                            data,
                                            stats=archive.stats,
                                            wait=False,
                                            ro_type=ROBJ_FILE_STREAM,
                                        )
                                    else:
                                        raise ValueError(f"unsupported recompress mode: {args.recompress}")
                                    cache.repository.async_response(wait=False)
                                    chunks.append(chunk_entry)
                                transfer_size += size
                            else:
                                if not dry_run:
                                    chunk_entry = cache.chunk_incref(chunk_id, archive.stats)
                                    chunks.append(chunk_entry)
                                present_size += size
                        if not dry_run:
                            item.chunks = chunks  # TODO: overwrite? IDs and sizes are same.
                            archive.stats.nfiles += 1
                    if not dry_run:
                        item = upgrader.upgrade_item(item=item)
                        archive.add_item(item, show_progress=args.progress)
                if not dry_run:
                    if args.progress:
                        archive.stats.show_progress(final=True)
                    additional_metadata = upgrader.upgrade_archive_metadata(metadata=other_archive.metadata)
                    archive.save(additional_metadata=additional_metadata)
                    print(
                        f"{name}: finished. "
                        f"transfer_size: {format_file_size(transfer_size)} "
                        f"present_size: {format_file_size(present_size)}"
                    )
                else:
                    print(
                        f"{name}: completed"
                        if transfer_size == 0
                        else f"{name}: incomplete, "
                        f"transfer_size: {format_file_size(transfer_size)} "
                        f"present_size: {format_file_size(present_size)}"
                    )

    def build_parser_transfer(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog
        from ._common import define_archive_filters_group

        transfer_epilog = process_epilog(
            """
        This command transfers archives from one repository to another repository.
        Optionally, it can also upgrade the transferred data.
        Optionally, it can also recompress the transferred data.

        It is easiest (and fastest) to give ``--compression=COMPRESSION --recompress=never`` using
        the same COMPRESSION mode as in the SRC_REPO - borg will use that COMPRESSION for metadata (in
        any case) and keep data compressed "as is" (saves time as no data compression is needed).

        If you want to globally change compression while transferring archives to the DST_REPO,
        give ``--compress=WANTED_COMPRESSION --recompress=always``.

        Suggested use for general purpose archive transfer (not repo upgrades)::

            # create a related DST_REPO (reusing key material from SRC_REPO), so that
            # chunking and chunk id generation will work in the same way as before.
            borg --repo=DST_REPO rcreate --other-repo=SRC_REPO --encryption=DST_ENC

            # transfer archives from SRC_REPO to DST_REPO
            borg --repo=DST_REPO transfer --other-repo=SRC_REPO --dry-run  # check what it would do
            borg --repo=DST_REPO transfer --other-repo=SRC_REPO            # do it!
            borg --repo=DST_REPO transfer --other-repo=SRC_REPO --dry-run  # check! anything left?

        The default is to transfer all archives, including checkpoint archives.

        You could use the misc. archive filter options to limit which archives it will
        transfer, e.g. using the ``-a`` option. This is recommended for big
        repositories with multiple data sets to keep the runtime per invocation lower.

        For repository upgrades (e.g. from a borg 1.2 repo to a related borg 2.0 repo), usage is
        quite similar to the above::

            # fast: compress metadata with zstd,3, but keep data chunks compressed as they are:
            borg --repo=DST_REPO transfer --other-repo=SRC_REPO --upgrader=From12To20 \\
                 --compress=zstd,3 --recompress=never

            # compress metadata and recompress data with zstd,3
            borg --repo=DST_REPO transfer --other-repo=SRC_REPO --upgrader=From12To20 \\
                 --compress=zstd,3 --recompress=always


        """
        )
        subparser = subparsers.add_parser(
            "transfer",
            parents=[common_parser],
            add_help=False,
            description=self.do_transfer.__doc__,
            epilog=transfer_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="transfer of archives from another repository",
        )
        subparser.set_defaults(func=self.do_transfer)
        subparser.add_argument(
            "-n", "--dry-run", dest="dry_run", action="store_true", help="do not change repository, just check"
        )
        subparser.add_argument(
            "--other-repo",
            metavar="SRC_REPOSITORY",
            dest="other_location",
            type=location_validator(other=True),
            default=Location(other=True),
            action=Highlander,
            help="transfer archives from the other repository",
        )
        subparser.add_argument(
            "--upgrader",
            metavar="UPGRADER",
            dest="upgrader",
            type=str,
            default="NoOp",
            action=Highlander,
            help="use the upgrader to convert transferred data (default: no conversion)",
        )
        subparser.add_argument(
            "-C",
            "--compression",
            metavar="COMPRESSION",
            dest="compression",
            type=CompressionSpec,
            default=CompressionSpec("lz4"),
            action=Highlander,
            help="select compression algorithm, see the output of the " '"borg help compression" command for details.',
        )
        subparser.add_argument(
            "--recompress",
            metavar="MODE",
            dest="recompress",
            nargs="?",
            default="never",
            const="always",
            choices=("never", "always"),
            action=Highlander,
            help="recompress data chunks according to `MODE` and ``--compression``. "
            "Possible modes are "
            "`always`: recompress unconditionally; and "
            "`never`: do not recompress (faster: re-uses compressed data chunks w/o change)."
            "If no MODE is given, `always` will be used. "
            'Not passing --recompress is equivalent to "--recompress never".',
        )

        define_archive_filters_group(subparser)

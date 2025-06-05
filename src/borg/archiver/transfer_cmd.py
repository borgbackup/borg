import argparse

from ._common import with_repository, with_other_repository, Highlander
from ..archive import Archive, cached_hash, DownloadPipeline
from ..chunkers import get_chunker
from ..compress import CompressionSpec
from ..constants import *  # NOQA
from ..crypto.key import uses_same_id_hash, uses_same_chunker_secret
from ..helpers import Error
from ..helpers import location_validator, Location, archivename_validator, comment_validator
from ..helpers import format_file_size, bin_to_hex
from ..helpers import ChunkerParams, ChunkIteratorFileWrapper
from ..manifest import Manifest
from ..legacyrepository import LegacyRepository
from ..repository import Repository

from ..logger import create_logger

logger = create_logger()


def transfer_chunks(
    upgrader, other_repository, other_manifest, other_chunks, archive, cache, recompress, dry_run, chunker_params=None
):
    """
    Transfer chunks from another repository to the current repository.

    If chunker_params is provided, the chunks will be re-chunked using the specified parameters.
    """
    transfer = 0
    present = 0
    chunks = []

    # Determine if re-chunking is needed
    rechunkify = chunker_params is not None

    if rechunkify:
        # Similar to ArchiveRecreater.iter_chunks
        pipeline = DownloadPipeline(other_manifest.repository, other_manifest.repo_objs)
        chunk_iterator = pipeline.fetch_many(other_chunks, ro_type=ROBJ_FILE_STREAM)
        file = ChunkIteratorFileWrapper(chunk_iterator)

        # Create a chunker with the specified parameters
        chunker = get_chunker(*chunker_params, key=archive.key, sparse=False)
        for chunk in chunker.chunkify(file):
            if not dry_run:
                chunk_id, data = cached_hash(chunk, archive.key.id_hash)
                size = len(data)
                # Check if the chunk is already in the repository
                chunk_present = cache.seen_chunk(chunk_id, size)
                if chunk_present:
                    chunk_entry = cache.reuse_chunk(chunk_id, size, archive.stats)
                    present += size
                else:
                    # Add the new chunk to the repository
                    chunk_entry = cache.add_chunk(
                        chunk_id, {}, data, stats=archive.stats, wait=False, ro_type=ROBJ_FILE_STREAM
                    )
                    cache.repository.async_response(wait=False)
                    transfer += size
                chunks.append(chunk_entry)
            else:
                # In dry-run mode, just estimate the size
                size = len(chunk.data) if chunk.data is not None else chunk.size
                transfer += size
    else:
        # Original implementation without re-chunking
        for chunk_id, size in other_chunks:
            chunk_present = cache.seen_chunk(chunk_id, size)
            if not chunk_present:  # target repo does not yet have this chunk
                if not dry_run:
                    try:
                        cdata = other_repository.get(chunk_id)
                    except (Repository.ObjectNotFound, LegacyRepository.ObjectNotFound):
                        # missing correct chunk in other_repository (source) will result in
                        # a missing chunk in repository (destination).
                        # we do NOT want to transfer all-zero replacement chunks from borg1 repos.
                        pass
                    else:
                        if recompress == "never":
                            # keep compressed payload same, verify via assert_id (that will
                            # decompress, but avoid needing to compress it again):
                            meta, data = other_manifest.repo_objs.parse(
                                chunk_id, cdata, decompress=True, want_compressed=True, ro_type=ROBJ_FILE_STREAM
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
                        elif recompress == "always":
                            # always decompress and re-compress file data chunks
                            meta, data = other_manifest.repo_objs.parse(chunk_id, cdata, ro_type=ROBJ_FILE_STREAM)
                            chunk_entry = cache.add_chunk(
                                chunk_id, meta, data, stats=archive.stats, wait=False, ro_type=ROBJ_FILE_STREAM
                            )
                        else:
                            raise ValueError(f"unsupported recompress mode: {recompress}")
                    cache.repository.async_response(wait=False)
                    chunks.append(chunk_entry)
                transfer += size
            else:
                if not dry_run:
                    chunk_entry = cache.reuse_chunk(chunk_id, size, archive.stats)
                    chunks.append(chunk_entry)
                present += size

    return chunks, transfer, present


class TransferMixIn:
    @with_other_repository(manifest=True, compatibility=(Manifest.Operation.READ,))
    @with_repository(manifest=True, cache=True, compatibility=(Manifest.Operation.WRITE,))
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
        archive_infos = other_manifest.archives.list_considering(args)
        count = len(archive_infos)
        if count == 0:
            return

        an_errors = []
        for archive_info in archive_infos:
            try:
                archivename_validator(archive_info.name)
            except argparse.ArgumentTypeError as err:
                an_errors.append(str(err))
        if an_errors:
            an_errors.insert(0, "Invalid archive names detected, please rename them before transfer:")
            raise Error("\n".join(an_errors))

        ac_errors = []
        for archive_info in archive_infos:
            archive = Archive(other_manifest, archive_info.id)
            try:
                comment_validator(archive.metadata.get("comment", ""))
            except argparse.ArgumentTypeError as err:
                ac_errors.append(f"{archive_info.name}: {err}")
        if ac_errors:
            ac_errors.insert(0, "Invalid archive comments detected, please fix them before transfer:")
            raise Error("\n".join(ac_errors))

        from .. import upgrade as upgrade_mod

        v1_or_v2 = getattr(args, "v1_or_v2", False)
        upgrader = args.upgrader
        if upgrader == "NoOp" and v1_or_v2:
            upgrader = "From12To20"

        try:
            UpgraderCls = getattr(upgrade_mod, f"Upgrader{upgrader}")
        except AttributeError:
            raise Error(f"No such upgrader: {upgrader}")

        if UpgraderCls is not upgrade_mod.UpgraderFrom12To20 and other_manifest.repository.version == 1:
            raise Error("To transfer from a borg 1.x repo, you need to use: --upgrader=From12To20")

        upgrader = UpgraderCls(cache=cache, args=args)

        for archive_info in archive_infos:
            name, id, ts = archive_info.name, archive_info.id, archive_info.ts
            id_hex, ts_str = bin_to_hex(id), ts.isoformat()
            transfer_size = 0
            present_size = 0
            # at least for borg 1.x -> borg2 transfers, we can not use the id to check for
            # already transferred archives (due to upgrade of metadata stream, id will be
            # different anyway). so we use archive name and timestamp.
            # the name alone might be sufficient for borg 1.x -> 2 transfers, but isn't
            # for 2 -> 2 transfers, because borg2 allows duplicate names ("series" feature).
            # so, best is to check for both name/ts and name/id.
            if not dry_run and manifest.archives.exists_name_and_ts(name, archive_info.ts):
                # useful for borg 1.x -> 2 transfers, we have unique names in borg 1.x.
                # also useful for borg 2 -> 2 transfers with metadata changes (id changes).
                print(f"{name} {ts_str}: archive is already present in destination repo, skipping.")
            elif not dry_run and manifest.archives.exists_name_and_id(name, id):
                # useful for borg 2 -> 2 transfers without changes (id stays the same)
                print(f"{name} {id_hex}: archive is already present in destination repo, skipping.")
            else:
                if not dry_run:
                    print(f"{name} {ts_str} {id_hex}: copying archive to destination repo...")
                other_archive = Archive(other_manifest, id)
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
                    if "chunks_healthy" in item:  # legacy
                        other_chunks = item.chunks_healthy  # chunks_healthy has the CORRECT chunks list, if present.
                    elif "chunks" in item:
                        other_chunks = item.chunks
                    else:
                        other_chunks = None
                    if other_chunks is not None:
                        chunks, transfer, present = transfer_chunks(
                            upgrader,
                            other_repository,
                            other_manifest,
                            other_chunks,
                            archive,
                            cache,
                            args.recompress,
                            dry_run,
                            args.chunker_params,
                        )
                        if not dry_run:
                            item.chunks = chunks
                            archive.stats.nfiles += 1
                        transfer_size += transfer
                        present_size += present
                    if not dry_run:
                        item = upgrader.upgrade_item(item=item)
                        archive.add_item(item, show_progress=args.progress)
                if not dry_run:
                    if args.progress:
                        archive.stats.show_progress(final=True)
                    additional_metadata = upgrader.upgrade_archive_metadata(metadata=other_archive.metadata)
                    archive.save(additional_metadata=additional_metadata)
                    print(
                        f"{name} {ts_str} {id_hex}: finished. "
                        f"transfer_size: {format_file_size(transfer_size)} "
                        f"present_size: {format_file_size(present_size)}"
                    )
                else:
                    print(
                        f"{name} {ts_str} {id_hex}: completed"
                        if transfer_size == 0
                        else f"{name} {ts_str} {id_hex}: incomplete, "
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
        Optionally, it can also re-chunk the transferred data using different chunker parameters.

        It is easiest (and fastest) to give ``--compression=COMPRESSION --recompress=never`` using
        the same COMPRESSION mode as in the SRC_REPO - borg will use that COMPRESSION for metadata (in
        any case) and keep data compressed "as is" (saves time as no data compression is needed).

        If you want to globally change compression while transferring archives to the DST_REPO,
        give ``--compress=WANTED_COMPRESSION --recompress=always``.

        The default is to transfer all archives.

        You could use the misc. archive filter options to limit which archives it will
        transfer, e.g. using the ``-a`` option. This is recommended for big
        repositories with multiple data sets to keep the runtime per invocation lower.

        General purpose archive transfer
        ++++++++++++++++++++++++++++++++

        Transfer borg2 archives into a related other borg2 repository::

            # create a related DST_REPO (reusing key material from SRC_REPO), so that
            # chunking and chunk id generation will work in the same way as before.
            borg --repo=DST_REPO repo-create --encryption=DST_ENC --other-repo=SRC_REPO

            # transfer archives from SRC_REPO to DST_REPO
            borg --repo=DST_REPO transfer --other-repo=SRC_REPO --dry-run  # check what it would do
            borg --repo=DST_REPO transfer --other-repo=SRC_REPO            # do it!
            borg --repo=DST_REPO transfer --other-repo=SRC_REPO --dry-run  # check! anything left?


        Data migration / upgrade from borg 1.x
        ++++++++++++++++++++++++++++++++++++++

        To migrate your borg 1.x archives into a related, new borg2 repository, usage is quite similar
        to the above, but you need the ``--from-borg1`` option::

            borg --repo=DST_REPO repocreate --encryption=DST_ENC --other-repo=SRC_REPO --from-borg1

            # to continue using lz4 compression as you did in SRC_REPO:
            borg --repo=DST_REPO transfer --other-repo=SRC_REPO --from-borg1 \\
                 --compress=lz4 --recompress=never

            # alternatively, to recompress everything to zstd,3:
            borg --repo=DST_REPO transfer --other-repo=SRC_REPO --from-borg1 \\
                 --compress=zstd,3 --recompress=always

            # to re-chunk using different chunker parameters:
            borg --repo=DST_REPO transfer --other-repo=SRC_REPO \\
                 --chunker-params=buzhash,19,23,21,4095


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
            "--from-borg1", dest="v1_or_v2", action="store_true", help="other repository is borg 1.x"
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
        subparser.add_argument(
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

        define_archive_filters_group(subparser)

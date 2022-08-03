import argparse

from .common import with_repository, with_other_repository
from ..archive import Archive
from ..constants import *  # NOQA
from ..crypto.key import uses_same_id_hash, uses_same_chunker_secret
from ..helpers import EXIT_SUCCESS, EXIT_ERROR
from ..helpers import location_validator, Location
from ..helpers import format_file_size
from ..helpers import Manifest

from ..logger import create_logger

logger = create_logger()


class TransferMixIn:
    @with_other_repository(manifest=True, key=True, compatibility=(Manifest.Operation.READ,))
    @with_repository(exclusive=True, manifest=True, cache=True, compatibility=(Manifest.Operation.WRITE,))
    def do_transfer(
        self, args, *, repository, manifest, key, cache, other_repository=None, other_manifest=None, other_key=None
    ):
        """archives transfer from other repository, optionally upgrade data format"""
        if not uses_same_id_hash(other_key, key):
            self.print_error(
                "You must keep the same ID hash ([HMAC-]SHA256 or BLAKE2b) or deduplication will break. "
                "Use a related repository!"
            )
            return EXIT_ERROR
        if not uses_same_chunker_secret(other_key, key):
            self.print_error(
                "You must use the same chunker secret or deduplication will break. " "Use a related repository!"
            )
            return EXIT_ERROR

        dry_run = args.dry_run
        args.consider_checkpoints = True
        archive_names = tuple(x.name for x in other_manifest.archives.list_considering(args))
        if not archive_names:
            return EXIT_SUCCESS

        from .. import upgrade as upgrade_mod

        try:
            UpgraderCls = getattr(upgrade_mod, f"Upgrader{args.upgrader}")
        except AttributeError:
            self.print_error(f"No such upgrader: {args.upgrader}")
            return EXIT_ERROR

        upgrader = UpgraderCls(cache=cache)

        for name in archive_names:
            transfer_size = 0
            present_size = 0
            if name in manifest.archives and not dry_run:
                print(f"{name}: archive is already present in destination repo, skipping.")
            else:
                if not dry_run:
                    print(f"{name}: copying archive to destination repo...")
                other_archive = Archive(other_repository, other_key, other_manifest, name)
                archive = Archive(repository, key, manifest, name, cache=cache, create=True) if not dry_run else None
                upgrader.new_archive(archive=archive)
                for item in other_archive.iter_items():
                    if "chunks" in item:
                        chunks = []
                        for chunk_id, size in item.chunks:
                            refcount = cache.seen_chunk(chunk_id, size)
                            if refcount == 0:  # target repo does not yet have this chunk
                                if not dry_run:
                                    cdata = other_repository.get(chunk_id)
                                    # keep compressed payload same, avoid decompression / recompression
                                    data = other_key.decrypt(chunk_id, cdata, decompress=False)
                                    data = upgrader.upgrade_compressed_chunk(chunk=data)
                                    chunk_entry = cache.add_chunk(
                                        chunk_id, data, archive.stats, wait=False, compress=False, size=size
                                    )
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
                        archive.add_item(upgrader.upgrade_item(item=item))
                if not dry_run:
                    additional_metadata = upgrader.upgrade_archive_metadata(metadata=other_archive.metadata)
                    archive.save(stats=archive.stats, additional_metadata=additional_metadata)
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
        return EXIT_SUCCESS

    def build_parser_transfer(self, subparsers, common_parser, mid_common_parser):

        from .common import process_epilog
        from .common import define_archive_filters_group

        transfer_epilog = process_epilog(
            """
        This command transfers archives from one repository to another repository.
        Optionally, it can also upgrade the transferred data.

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
        transfer, e.g. using the -a option. This is recommended for big
        repositories with multiple data sets to keep the runtime per invocation lower.

        For repository upgrades (e.g. from a borg 1.2 repo to a related borg 2.0 repo), usage is
        quite similar to the above::

            borg --repo=DST_REPO transfer --other-repo=SRC_REPO --upgrader=From12To20


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
            help="transfer archives from the other repository",
        )
        subparser.add_argument(
            "--upgrader",
            metavar="UPGRADER",
            dest="upgrader",
            type=str,
            default="NoOp",
            help="use the upgrader to convert transferred data (default: no conversion)",
        )
        define_archive_filters_group(subparser)

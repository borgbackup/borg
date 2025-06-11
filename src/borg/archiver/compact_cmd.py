import argparse
from pathlib import Path

from ._common import with_repository
from ..archive import Archive
from ..cache import write_chunkindex_to_repo_cache, build_chunkindex_from_repo
from ..cache import files_cache_name, discover_files_cache_names
from ..helpers import get_cache_dir
from ..constants import *  # NOQA
from ..hashindex import ChunkIndex, ChunkIndexEntry
from ..helpers import set_ec, EXIT_ERROR, format_file_size, bin_to_hex
from ..helpers import ProgressIndicatorPercent
from ..manifest import Manifest
from ..remote import RemoteRepository
from ..repository import Repository, repo_lister

from ..logger import create_logger

logger = create_logger()


class ArchiveGarbageCollector:
    def __init__(self, repository, manifest, *, stats, iec):
        self.repository = repository
        assert isinstance(repository, (Repository, RemoteRepository))
        self.manifest = manifest
        self.chunks = None  # a ChunkIndex, here used for: id -> (is_used, stored_size)
        self.total_files = None  # overall number of source files written to all archives in this repo
        self.total_size = None  # overall size of source file content data written to all archives
        self.archives_count = None  # number of archives
        self.stats = stats  # compute repo space usage before/after - lists all repo objects, can be slow.
        self.iec = iec  # formats statistics using IEC units (1KiB = 1024B)

    @property
    def repository_size(self):
        if self.chunks is None or not self.stats:
            return None
        return sum(entry.size for id, entry in self.chunks.iteritems())  # sum of stored sizes

    def garbage_collect(self):
        """Removes unused chunks from a repository."""
        logger.info("Starting compaction / garbage collection...")
        self.chunks = self.get_repository_chunks()
        logger.info("Computing object IDs used by archives...")
        (self.missing_chunks, self.total_files, self.total_size, self.archives_count) = self.analyze_archives()
        self.report_and_delete()
        self.save_chunk_index()
        self.cleanup_files_cache()
        logger.info("Finished compaction / garbage collection...")

    def get_repository_chunks(self) -> ChunkIndex:
        """return a chunks index"""
        if self.stats:  # slow method: build a fresh chunks index, with stored chunk sizes.
            logger.info("Getting object IDs present in the repository...")
            chunks = ChunkIndex()
            for id, stored_size in repo_lister(self.repository, limit=LIST_SCAN_LIMIT):
                # we add this id to the chunks index (as unused chunk), because
                # we do not know yet whether it is actually referenced from some archives.
                # we "abuse" the size field here. usually there is the plaintext size,
                # but we use it for the size of the stored object here.
                chunks[id] = ChunkIndexEntry(flags=ChunkIndex.F_NONE, size=stored_size)
        else:  # faster: rely on existing chunks index (with flags F_NONE and size 0).
            logger.info("Getting object IDs from cached chunks index...")
            chunks = build_chunkindex_from_repo(self.repository, cache_immediately=True)
        return chunks

    def save_chunk_index(self):
        # as we may have deleted some chunks, we must write a full updated chunkindex to the repo
        # and also remove all older cached chunk indexes.
        # write_chunkindex_to_repo now removes all flags and size infos.
        # we need this, as we put the wrong size in there to support --stats computations.
        write_chunkindex_to_repo_cache(
            self.repository, self.chunks, incremental=False, clear=True, force_write=True, delete_other=True
        )
        self.chunks = None  # nothing there (cleared!)

    def cleanup_files_cache(self):
        """
        Clean up files cache files for archive series names that no longer exist in the repository.

        Note: this only works perfectly if the files cache filename suffixes are automatically generated
        and the user does not manually control them via more than one BORG_FILES_CACHE_SUFFIX env var value.
        """
        logger.info("Cleaning up files cache...")

        cache_dir = Path(get_cache_dir()) / self.repository.id_str
        if not cache_dir.exists():
            logger.debug("Cache directory does not exist, skipping files cache cleanup")
            return

        # Get all existing archive series names
        existing_series = set(self.manifest.archives.names())
        logger.debug(f"Found {len(existing_series)} existing archive series.")

        # Get the set of all existing files cache file names.
        try:
            files_cache_names = set(discover_files_cache_names(cache_dir))
            logger.debug(f"Found {len(files_cache_names)} files cache files.")
        except (FileNotFoundError, PermissionError) as e:
            logger.warning(f"Could not access cache directory: {e}")
            return

        used_files_cache_names = {files_cache_name(series_name) for series_name in existing_series}
        unused_files_cache_names = files_cache_names - used_files_cache_names

        for cache_filename in unused_files_cache_names:
            cache_path = cache_dir / cache_filename
            try:
                cache_path.unlink()
            except (FileNotFoundError, PermissionError) as e:
                logger.warning(f"Could not access cache file: {e}")
        logger.info(f"Removed {len(unused_files_cache_names)} unused files cache files.")

    def analyze_archives(self) -> tuple[set, int, int, int]:
        """Iterate over all items in all archives, create the dicts id -> size of all used chunks."""

        def use_it(id):
            entry = self.chunks.get(id)
            if entry is not None:
                # the chunk is in the repo, mark it used.
                self.chunks[id] = entry._replace(flags=entry.flags | ChunkIndex.F_USED)
            else:
                # with --stats: we do NOT have this chunk in the repository!
                # without --stats: we do not have this chunk or the chunks index is incomplete.
                missing_chunks.add(id)

        missing_chunks: set[bytes] = set()
        archive_infos = self.manifest.archives.list(sort_by=["ts"])
        num_archives = len(archive_infos)
        pi = ProgressIndicatorPercent(
            total=num_archives, msg="Computing used chunks %3.1f%%", step=0.1, msgid="compact.analyze_archives"
        )
        total_size, total_files = 0, 0
        for i, info in enumerate(archive_infos):
            pi.show(i)
            logger.info(
                f"Analyzing archive {info.name} {info.ts.astimezone()} {bin_to_hex(info.id)} ({i + 1}/{num_archives})"
            )
            archive = Archive(self.manifest, info.id, iec=self.iec)
            # archive metadata size unknown, but usually small/irrelevant:
            use_it(archive.id)
            for id in archive.metadata.item_ptrs:
                use_it(id)
            for id in archive.metadata.items:
                use_it(id)
            # archive items content data:
            for item in archive.iter_items():
                total_files += 1  # every fs object counts, not just regular files
                if "chunks" in item:
                    for id, size in item.chunks:
                        total_size += size  # original, uncompressed file content size
                        use_it(id)
        pi.finish()
        return missing_chunks, total_files, total_size, num_archives

    def report_and_delete(self):
        if self.missing_chunks:
            logger.error(f"Repository has {len(self.missing_chunks)} missing objects!")
            for id in sorted(self.missing_chunks):
                logger.debug(f"Missing object {bin_to_hex(id)}")
            set_ec(EXIT_ERROR)

        logger.info("Cleaning archives directory from soft-deleted archives...")
        archive_infos = self.manifest.archives.list(sort_by=["ts"], deleted=True)
        for archive_info in archive_infos:
            name, id, hex_id = archive_info.name, archive_info.id, bin_to_hex(archive_info.id)
            try:
                self.manifest.archives.nuke_by_id(id)
            except KeyError:
                self.print_warning(f"Archive {name} {hex_id} not found.")

        repo_size_before = self.repository_size
        logger.info("Determining unused objects...")
        unused = set()
        for id, entry in self.chunks.iteritems():
            if not (entry.flags & ChunkIndex.F_USED):
                unused.add(id)
        logger.info(f"Deleting {len(unused)} unused objects...")
        pi = ProgressIndicatorPercent(
            total=len(unused), msg="Deleting unused objects %3.1f%%", step=0.1, msgid="compact.report_and_delete"
        )
        for i, id in enumerate(unused):
            pi.show(i)
            self.repository.delete(id)
            del self.chunks[id]
        pi.finish()
        repo_size_after = self.repository_size

        count = len(self.chunks)
        logger.info(f"Overall statistics, considering all {self.archives_count} archives in this repository:")
        logger.info(
            f"Source data size was {format_file_size(self.total_size, precision=0, iec=self.iec)} "
            f"in {self.total_files} files."
        )
        if self.stats:
            logger.info(
                f"Repository size is {format_file_size(repo_size_after, precision=0, iec=self.iec)} "
                f"in {count} objects."
            )
            logger.info(
                f"Compaction saved "
                f"{format_file_size(repo_size_before - repo_size_after, precision=0, iec=self.iec)}."
            )
        else:
            logger.info(f"Repository has data stored in {count} objects.")


class CompactMixIn:
    @with_repository(exclusive=True, compatibility=(Manifest.Operation.DELETE,))
    def do_compact(self, args, repository, manifest):
        """Collect garbage in repository"""
        if not args.dry_run:  # support --dry-run to simplify scripting
            ArchiveGarbageCollector(repository, manifest, stats=args.stats, iec=args.iec).garbage_collect()

    def build_parser_compact(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        compact_epilog = process_epilog(
            """
            Free repository space by deleting unused chunks.

            borg compact analyzes all existing archives to find out which repository
            objects are actually used (referenced). It then deletes all unused objects
            from the repository to free space.

            Unused objects may result from:

            - borg delete or prune usage
            - interrupted backups (maybe retry the backup first before running compact)
            - backup of source files that had an I/O error in the middle of their contents
              and that were skipped due to this
            - corruption of the repository (e.g. the archives directory having lost
              entries, see notes below)

            You usually don't want to run ``borg compact`` after every write operation, but
            either regularly (e.g. once a month, possibly together with ``borg check``) or
            when disk space needs to be freed.

            **Important:**

            After compacting it is no longer possible to use ``borg undelete`` to recover
            previously soft-deleted archives.

            ``borg compact`` might also delete data from archives that were "lost" due to
            archives directory corruption. Such archives could potentially be restored with
            ``borg check --find-lost-archives [--repair]``, which is slow. You therefore
            might not want to do that unless there are signs of lost archives (e.g. when
            seeing fatal errors when creating backups or when archives are missing in
            ``borg repo-list``).

            When giving the ``--stats`` option, borg will internally list all repository
            objects to determine their existence AND stored size. It will build a fresh
            chunks index from that information and cache it in the repository. For some
            types of repositories, this might be very slow. It will tell you the sum of
            stored object sizes, before and after compaction.

            Without ``--stats``, borg will rely on the cached chunks index to determine
            existing object IDs (but there is no stored size information in the index,
            thus it can't compute before/after compaction size statistics).
            """
        )
        subparser = subparsers.add_parser(
            "compact",
            parents=[common_parser],
            add_help=False,
            description=self.do_compact.__doc__,
            epilog=compact_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="compact repository",
        )
        subparser.set_defaults(func=self.do_compact)
        subparser.add_argument("-n", "--dry-run", dest="dry_run", action="store_true", help="do nothing")
        subparser.add_argument(
            "-s", "--stats", dest="stats", action="store_true", help="print statistics (might be much slower)"
        )

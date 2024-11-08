import argparse
from typing import Tuple, Set

from ._common import with_repository
from ..archive import Archive
from ..cache import write_chunkindex_to_repo_cache
from ..constants import *  # NOQA
from ..hashindex import ChunkIndex, ChunkIndexEntry
from ..helpers import set_ec, EXIT_WARNING, EXIT_ERROR, format_file_size, bin_to_hex
from ..helpers import ProgressIndicatorPercent
from ..manifest import Manifest
from ..remote import RemoteRepository
from ..repository import Repository, repo_lister

from ..logger import create_logger

logger = create_logger()


class ArchiveGarbageCollector:
    def __init__(self, repository, manifest):
        self.repository = repository
        assert isinstance(repository, (Repository, RemoteRepository))
        self.manifest = manifest
        self.chunks = None  # a ChunkIndex, here used for: id -> (is_used, stored_size)
        self.total_files = None  # overall number of source files written to all archives in this repo
        self.total_size = None  # overall size of source file content data written to all archives
        self.archives_count = None  # number of archives

    @property
    def repository_size(self):
        if self.chunks is None:
            return None
        return sum(entry.size for id, entry in self.chunks.iteritems())  # sum of stored sizes

    def garbage_collect(self):
        """Removes unused chunks from a repository."""
        logger.info("Starting compaction / garbage collection...")
        logger.info("Getting object IDs present in the repository...")
        self.chunks = self.get_repository_chunks()
        logger.info("Computing object IDs used by archives...")
        (self.missing_chunks, self.reappeared_chunks, self.total_files, self.total_size, self.archives_count) = (
            self.analyze_archives()
        )
        self.report_and_delete()
        self.save_chunk_index()
        logger.info("Finished compaction / garbage collection...")

    def get_repository_chunks(self) -> ChunkIndex:
        """Build a dict id -> size of all chunks present in the repository"""
        chunks = ChunkIndex()
        for id, stored_size in repo_lister(self.repository, limit=LIST_SCAN_LIMIT):
            # we add this id to the chunks index (as unused chunk), because
            # we do not know yet whether it is actually referenced from some archives.
            # we "abuse" the size field here. usually there is the plaintext size,
            # but we use it for the size of the stored object here.
            chunks[id] = ChunkIndexEntry(flags=ChunkIndex.F_NONE, size=stored_size)
        return chunks

    def save_chunk_index(self):
        # first clean up:
        for id, entry in self.chunks.iteritems():
            # we already deleted the unused chunks, so everything left must be used:
            assert entry.flags & ChunkIndex.F_USED
            # as we put the wrong size in there, we need to clean up the size:
            self.chunks[id] = entry._replace(size=0)
        # now self.chunks is an uptodate ChunkIndex, usable for general borg usage!
        write_chunkindex_to_repo_cache(self.repository, self.chunks, clear=True, force_write=True)
        self.chunks = None  # nothing there (cleared!)

    def analyze_archives(self) -> Tuple[Set, Set, int, int, int]:
        """Iterate over all items in all archives, create the dicts id -> size of all used/wanted chunks."""

        def use_it(id, *, wanted=False):
            entry = self.chunks.get(id)
            if entry is not None:
                # the chunk is in the repo, mark it used.
                self.chunks[id] = entry._replace(flags=entry.flags | ChunkIndex.F_USED)
                if wanted:
                    # chunk id is from chunks_healthy list: a lost chunk has re-appeared!
                    reappeared_chunks.add(id)
            else:
                # we do NOT have this chunk in the repository!
                missing_chunks.add(id)

        missing_chunks: set[bytes] = set()
        reappeared_chunks: set[bytes] = set()
        archive_infos = self.manifest.archives.list(sort_by=["ts"])
        num_archives = len(archive_infos)
        pi = ProgressIndicatorPercent(
            total=num_archives, msg="Computing used/wanted chunks %3.1f%%", step=0.1, msgid="compact.analyze_archives"
        )
        total_size, total_files = 0, 0
        for i, info in enumerate(archive_infos):
            pi.show(i)
            logger.info(f"Analyzing archive {info.name} {info.ts} {bin_to_hex(info.id)} ({i + 1}/{num_archives})")
            archive = Archive(self.manifest, info.id)
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
                    if "chunks_healthy" in item:
                        # we also consider the chunks_healthy chunks as referenced - do not throw away
                        # anything that borg check --repair might still need.
                        for id, size in item.chunks_healthy:
                            use_it(id, wanted=True)
        pi.finish()
        return missing_chunks, reappeared_chunks, total_files, total_size, num_archives

    def report_and_delete(self):
        run_repair = " Run borg check --repair!"

        if self.missing_chunks:
            logger.error(f"Repository has {len(self.missing_chunks)} missing objects." + run_repair)
            set_ec(EXIT_ERROR)

        if self.reappeared_chunks:
            logger.warning(f"{len(self.reappeared_chunks)} previously missing objects re-appeared!" + run_repair)
            set_ec(EXIT_WARNING)

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
            f"Source data size was {format_file_size(self.total_size, precision=0)} in {self.total_files} files."
        )
        logger.info(f"Repository size is {format_file_size(repo_size_after, precision=0)} in {count} objects.")
        logger.info(f"Compaction saved {format_file_size(repo_size_before - repo_size_after, precision=0)}.")


class CompactMixIn:
    @with_repository(exclusive=True, compatibility=(Manifest.Operation.DELETE,))
    def do_compact(self, args, repository, manifest):
        """Collect garbage in repository"""
        ArchiveGarbageCollector(repository, manifest).garbage_collect()

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

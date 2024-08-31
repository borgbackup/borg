import argparse
from typing import Tuple, Dict

from ._common import with_repository
from ..archive import Archive
from ..constants import *  # NOQA
from ..helpers import set_ec, EXIT_WARNING, EXIT_ERROR, format_file_size, bin_to_hex
from ..helpers import ProgressIndicatorPercent
from ..manifest import Manifest
from ..remote import RemoteRepository
from ..repository import Repository

from ..logger import create_logger

logger = create_logger()


class ArchiveGarbageCollector:
    def __init__(self, repository, manifest):
        self.repository = repository
        assert isinstance(repository, (Repository, RemoteRepository))
        self.manifest = manifest
        self.repository_chunks = None  # what we have in the repository, id -> stored_size
        self.used_chunks = None  # what archives currently reference
        self.wanted_chunks = None  # chunks that would be nice to have for next borg check --repair
        self.total_files = None  # overall number of source files written to all archives in this repo
        self.total_size = None  # overall size of source file content data written to all archives
        self.archives_count = None  # number of archives

    @property
    def repository_size(self):
        if self.repository_chunks is None:
            return None
        return sum(self.repository_chunks.values())  # sum of stored sizes

    def garbage_collect(self):
        """Removes unused chunks from a repository."""
        logger.info("Starting compaction / garbage collection...")
        logger.info("Getting object IDs present in the repository...")
        self.repository_chunks = self.get_repository_chunks()
        logger.info("Computing object IDs used by archives...")
        (self.used_chunks, self.wanted_chunks, self.total_files, self.total_size, self.archives_count) = (
            self.analyze_archives()
        )
        self.report_and_delete()
        logger.info("Finished compaction / garbage collection...")

    def get_repository_chunks(self) -> Dict[bytes, int]:
        """Build a dict id -> size of all chunks present in the repository"""
        repository_chunks = {}
        marker = None
        while True:
            result = self.repository.list(limit=LIST_SCAN_LIMIT, marker=marker)
            if not result:
                break
            marker = result[-1][0]
            for id, stored_size in result:
                repository_chunks[id] = stored_size
        return repository_chunks

    def analyze_archives(self) -> Tuple[Dict[bytes, int], Dict[bytes, int], int, int, int]:
        """Iterate over all items in all archives, create the dicts id -> size of all used/wanted chunks."""
        used_chunks = {}  # chunks referenced by item.chunks
        wanted_chunks = {}  # additional "wanted" chunks seen in item.chunks_healthy
        archive_infos = self.manifest.archives.list()
        num_archives = len(archive_infos)
        pi = ProgressIndicatorPercent(
            total=num_archives, msg="Computing used/wanted chunks %3.1f%%", step=0.1, msgid="compact.analyze_archives"
        )
        total_size, total_files = 0, 0
        for i, info in enumerate(archive_infos):
            pi.show(i)
            logger.info(f"Analyzing archive {info.name} ({i + 1}/{num_archives})")
            archive = Archive(self.manifest, info.name)
            # archive metadata size unknown, but usually small/irrelevant:
            used_chunks[archive.id] = 0
            for id in archive.metadata.item_ptrs:
                used_chunks[id] = 0
            for id in archive.metadata.items:
                used_chunks[id] = 0
            # archive items content data:
            for item in archive.iter_items():
                total_files += 1  # every fs object counts, not just regular files
                if "chunks" in item:
                    for id, size in item.chunks:
                        total_size += size  # original, uncompressed file content size
                        used_chunks[id] = size
                    if "chunks_healthy" in item:
                        # we also consider the chunks_healthy chunks as referenced - do not throw away
                        # anything that borg check --repair might still need.
                        for id, size in item.chunks_healthy:
                            if id not in used_chunks:
                                wanted_chunks[id] = size
        pi.finish()
        return used_chunks, wanted_chunks, total_files, total_size, num_archives

    def report_and_delete(self):
        run_repair = " Run borg check --repair!"

        missing_new = set(self.used_chunks) - set(self.repository_chunks)
        if missing_new:
            logger.error(f"Repository has {len(missing_new)} new missing objects." + run_repair)
            set_ec(EXIT_ERROR)

        missing_known = set(self.wanted_chunks) - set(self.repository_chunks)
        if missing_known:
            logger.warning(f"Repository has {len(missing_known)} known missing objects.")
            set_ec(EXIT_WARNING)

        missing_found = set(self.wanted_chunks) & set(self.repository_chunks)
        if missing_found:
            logger.warning(f"{len(missing_found)} previously missing objects re-appeared!" + run_repair)
            set_ec(EXIT_WARNING)

        repo_size_before = self.repository_size
        referenced_chunks = set(self.used_chunks) | set(self.wanted_chunks)
        unused = set(self.repository_chunks) - referenced_chunks
        logger.info(f"Repository has {len(unused)} objects to delete.")
        if unused:
            logger.info(f"Deleting {len(unused)} unused objects...")
            pi = ProgressIndicatorPercent(
                total=len(unused), msg="Deleting unused objects %3.1f%%", step=0.1, msgid="compact.report_and_delete"
            )
            for i, id in enumerate(unused):
                pi.show(i)
                self.repository.delete(id)
                del self.repository_chunks[id]
            pi.finish()
        repo_size_after = self.repository_size

        count = len(self.repository_chunks)
        logger.info(f"Overall statistics, considering all {self.archives_count} archives in this repository:")
        logger.info(
            f"Source data size was {format_file_size(self.total_size, precision=0)} in {self.total_files} files."
        )
        dsize = 0
        for id in self.repository_chunks:
            if id in self.used_chunks:
                dsize += self.used_chunks[id]
            elif id in self.wanted_chunks:
                dsize += self.wanted_chunks[id]
            else:
                raise KeyError(bin_to_hex(id))
        logger.info(f"Repository size is {format_file_size(self.repository_size, precision=0)} in {count} objects.")
        if self.total_size != 0:
            logger.info(f"Space reduction factor due to deduplication: {dsize / self.total_size:.3f}")
        if dsize != 0:
            logger.info(f"Space reduction factor due to compression: {self.repository_size / dsize:.3f}")
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

            borg compact analyzes all existing archives to find out which chunks are
            actually used. There might be unused chunks resulting from borg delete or prune,
            which can be removed to free space in the repository.

            Differently than borg 1.x, borg2's compact needs the borg key if the repo is
            encrypted.
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

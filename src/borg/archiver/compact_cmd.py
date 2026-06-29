from collections import defaultdict, namedtuple
import hashlib
import io
from pathlib import Path

from borghash import HashTableNT
from borgstore.store import ItemInfo

from ._common import with_repository
from ..archive import Archive
from ..cache import write_chunkindex_to_repo, build_chunkindex_from_repo, delete_chunkindex_from_repo
from ..cache import files_cache_name, discover_files_cache_names
from ..helpers import get_cache_dir
from ..helpers.argparsing import ArgumentParser
from ..constants import *  # NOQA
from ..hashindex import ChunkIndex
from ..helpers import set_ec, EXIT_ERROR, format_file_size, bin_to_hex
from ..helpers import ProgressIndicatorPercent
from ..manifest import Manifest
from ..repository import Repository, StoreObjectNotFound

from ..logger import create_logger

logger = create_logger()

# per-archive cache of the objects an archive references, stored in the repo as
# cache/referenced-by-archive.<archive id hex>. it is a serialized HashTableNT mapping object id
# (32 bytes) -> plaintext object size (uint32), with a sha256 of that content appended for integrity.
REFERENCED_BY_ARCHIVE = "referenced-by-archive."  # name prefix within the "cache" store namespace
ArchiveReferenceEntry = namedtuple("ArchiveReferenceEntry", "size")
ArchiveReferenceEntryFormatT = namedtuple("ArchiveReferenceEntryFormatT", "size")
ArchiveReferenceEntryFormat = ArchiveReferenceEntryFormatT(size="I")  # uint32 plaintext size


class ArchiveGarbageCollector:
    def __init__(self, repository, manifest, *, stats, iec, threshold, dry_run=False):
        self.repository = repository
        assert isinstance(repository, Repository)
        self.manifest = manifest
        self.chunks = None  # a ChunkIndex, here used for: id -> (is_used, stored_size)
        self.total_size = None  # overall size of source file content data written to all archives
        self.archives_count = None  # number of archives
        self.stats = stats  # compute repo space usage before/after - lists all repo objects, can be slow.
        self.threshold = threshold  # rewrite a mixed pack only when its wasted-bytes fraction reaches this percent
        self.iec = iec  # formats statistics using IEC units (1KiB = 1024B)
        self.dry_run = dry_run

    @property
    def repository_size(self):
        if self.chunks is None or not self.stats:
            return None
        return sum(entry.obj_size for id, entry in self.chunks.iteritems())  # sum of stored sizes

    def garbage_collect(self):
        """Removes unused chunks from a repository."""
        logger.info("Starting compaction / garbage collection...")
        self.chunks = self.get_repository_chunks()
        logger.info("Computing object IDs used by archives...")
        (self.missing_chunks, self.total_size, self.archives_count) = self.analyze_archives()
        self.report_and_delete()
        if not self.dry_run:
            self.save_chunk_index()
            self.cleanup_files_cache()
        logger.info("Finished compaction / garbage collection...")

    def get_repository_chunks(self) -> ChunkIndex:
        """return a chunks index"""
        # The cached index already has each object's obj_size and starts entries as F_NONE, so it
        # serves both GC and --stats; no need to force the slow pack-header scan just to get sizes.
        logger.info("Getting object IDs from the cached chunks index...")
        chunks = build_chunkindex_from_repo(self.repository, cache_immediately=not self.dry_run)
        return chunks

    def save_chunk_index(self):
        # as we may have deleted some chunks, we must write a full updated chunkindex to the repo
        # and also remove all older cached chunk indexes.
        # write_chunkindex_to_repo now removes all flags and size infos.
        # we need this, as we put the wrong size in there to support --stats computations.
        write_chunkindex_to_repo(
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

    def analyze_archives(self) -> tuple[set, int, int]:
        """Iterate over all archives, mark used chunks and add up the source files content size."""
        self.missing_chunks: set[bytes] = set()
        archive_infos = self.manifest.archives.list(sort_by=["ts"])
        num_archives = len(archive_infos)
        cached_hex_ids = self.list_archive_reference_caches()
        if not self.dry_run:
            # drop the reference caches of archives that do not exist anymore.
            valid_hex_ids = {bin_to_hex(info.id) for info in archive_infos}
            self.cleanup_archive_reference_caches(cached_hex_ids - valid_hex_ids)
        pi = ProgressIndicatorPercent(
            total=num_archives, msg="Computing used chunks %3.1f%%", step=0.1, msgid="compact.analyze_archives"
        )
        total_size = 0
        for i, info in enumerate(archive_infos):
            logger.info(
                f"Analyzing archive {info.name} {info.ts.astimezone()} {bin_to_hex(info.id)} ({i + 1}/{num_archives})"
            )
            archive = Archive(self.manifest, info.id, iec=self.iec)
            total_size += self.analyze_archive(archive, cached=bin_to_hex(info.id) in cached_hex_ids)
            pi.show(i + 1)  # report after each archive, so the last one lands on 100%
        pi.finish()
        return self.missing_chunks, total_size, num_archives

    def analyze_archive(self, archive: Archive, *, cached: bool) -> int:
        """Mark all objects the archive references as used; return its source files content size
        (in-archive duplicated chunks are only counted once).

        The set of referenced objects and their plaintext sizes is read from a per-archive cache in
        the repo if present, else computed by scanning the archive and then cached for next time.
        """
        references = self.load_archive_references(archive.id) if cached else None
        if references is None:
            references = self.scan_archive_references(archive)
            if not self.dry_run:
                self.store_archive_references(archive.id, references)
        # mark every referenced object used and add up the source content size. each object counts
        # once (the references mapping is deduplicated); metadata objects carry size 0.
        total_size = 0
        for id, entry in references.items():
            existing = self.chunks.get(id)
            if existing is not None:
                # the object is in the repo, mark it used.
                self.chunks[id] = existing._replace(flags=existing.flags | ChunkIndex.F_USED)
            else:
                # we do not have this object or the chunks index is incomplete.
                self.missing_chunks.add(id)
            total_size += entry.size
        return total_size

    def scan_archive_references(self, archive: Archive) -> HashTableNT:
        """Scan the archive's items, collecting the object ids it references and their plaintext sizes."""
        references = HashTableNT(
            key_size=32, value_type=ArchiveReferenceEntry, value_format=ArchiveReferenceEntryFormat
        )
        # archive metadata objects: only their ids matter for GC, their content size is not known here
        # and not part of the source data size, so record them with size 0.
        references[archive.id] = ArchiveReferenceEntry(size=0)
        for id in archive.metadata.item_ptrs:
            references[id] = ArchiveReferenceEntry(size=0)
        for id in archive.metadata.items:
            references[id] = ArchiveReferenceEntry(size=0)
        # archive items content data:
        for item in archive.iter_items():
            if "chunks" in item:
                for id, size in item.chunks:
                    references[id] = ArchiveReferenceEntry(size=size)  # original, uncompressed content size
        return references

    @staticmethod
    def archive_reference_cache_name(archive_id: bytes) -> str:
        """The store name of an archive's reference cache (well within borgstore's name length limit)."""
        return f"cache/{REFERENCED_BY_ARCHIVE}{bin_to_hex(archive_id)}"

    def list_archive_reference_caches(self) -> set[str]:
        """Return the set of archive ids (hex) that currently have a reference cache in the repo."""
        hex_ids = set()
        for info in self.repository.store_list("cache"):
            info = ItemInfo(*info)  # RPC does not give a namedtuple
            if info.name.startswith(REFERENCED_BY_ARCHIVE):
                hex_ids.add(info.name[len(REFERENCED_BY_ARCHIVE) :])
        return hex_ids

    def load_archive_references(self, archive_id: bytes) -> HashTableNT | None:
        """Load and verify an archive's references table; return it, or None if it is missing/corrupted."""
        try:
            data = self.repository.store_load(self.archive_reference_cache_name(archive_id))
        except StoreObjectNotFound:
            return None
        # the serialized table has a sha256 of its content appended (the store name cannot also carry it,
        # as borgstore's name length limit is too small for archive id hex + sha256 hex). a mismatch means
        # the cache is corrupted; we then return None so the caller falls back to scanning the archive.
        hex_id = bin_to_hex(archive_id)
        if len(data) < 32 or hashlib.sha256(data[:-32]).digest() != data[-32:]:
            logger.warning(f"Ignoring corrupted references cache of archive {hex_id}.")
            return None
        try:
            with io.BytesIO(data[:-32]) as f:
                return HashTableNT.read(f)
        except ValueError:
            logger.warning(f"Ignoring unreadable references cache of archive {hex_id}.")
            return None

    def store_archive_references(self, archive_id: bytes, references: HashTableNT) -> None:
        """Serialize the references table (with a sha256 of its content appended) and store it."""
        with io.BytesIO() as f:
            references.write(f)
            data = f.getvalue()
        data += hashlib.sha256(data).digest()
        self.repository.store_store(self.archive_reference_cache_name(archive_id), data)

    def cleanup_archive_reference_caches(self, stale_hex_ids: set[str]) -> None:
        """Delete reference caches belonging to archives that are not in the archives list anymore."""
        for hex_id in stale_hex_ids:
            try:
                self.repository.store_delete(f"cache/{REFERENCED_BY_ARCHIVE}{hex_id}")
            except StoreObjectNotFound:
                pass
        logger.debug(f"Removed {len(stale_hex_ids)} stale archive references caches.")

    def report_and_delete(self):
        if self.missing_chunks:
            logger.error(f"Repository has {len(self.missing_chunks)} missing objects!")
            for id in sorted(self.missing_chunks):
                logger.debug(f"Missing object {bin_to_hex(id)}")
            set_ec(EXIT_ERROR)
        if not self.dry_run:  # nuking removes the soft-deleted archives from the archives directory; skip on a dry run
            logger.info("Cleaning archives directory from soft-deleted archives...")
            archive_infos = self.manifest.archives.list(sort_by=["ts"], deleted=True)
            for archive_info in archive_infos:
                name, id, hex_id = archive_info.name, archive_info.id, bin_to_hex(archive_info.id)
                try:
                    self.manifest.archives.nuke_by_id(id)
                except self.repository.ObjectNotFound:
                    logger.warning(f"Soft-deleted archive {name} {hex_id} not found.")

        repo_size_before = self.repository_size
        self.compact_packs()
        repo_size_after = self.repository_size

        count = len(self.chunks)
        logger.info(f"Overall statistics, considering all {self.archives_count} archives in this repository:")
        logger.info(f"Source data size was {format_file_size(self.total_size, precision=0, iec=self.iec)}.")
        if self.stats:
            logger.info(
                f"Repository size is {format_file_size(repo_size_after, precision=0, iec=self.iec)} "
                f"in {count} objects."
            )
            if not self.dry_run:  # nothing was deleted on a dry run, so before == after
                logger.info(
                    f"Compaction saved "
                    f"{format_file_size(repo_size_before - repo_size_after, precision=0, iec=self.iec)}."
                )
        else:
            logger.info(f"Repository has data stored in {count} objects.")

    def compact_packs(self):
        """Free space one pack at a time (the store can only delete whole packs).

        analyze_archives() has flagged the used objects F_USED. Per pack:

        - all objects unused -> delete the pack.
        - all objects used   -> keep it.
        - mixed              -> rewrite only if the unused bytes reach --threshold percent: copy the
                                used objects into a new pack via compact_pack and drop the old one.
                                Below the threshold keep the pack, so we don't rewrite a large pack
                                to reclaim little.

        Two passes bound the memory use: the first keeps only per-pack byte counts to pick the packs
        to change, the second collects object ids for just those packs, not the whole index.
        """
        # Pass 1: one index scan, keep only per-pack byte tallies (two ints per pack, no id lists).
        pack_total, pack_unused = defaultdict(int), defaultdict(int)
        for id, entry in self.chunks.iteritems():
            pid = entry.pack_id
            pack_total[pid] += entry.obj_size
            if not (entry.flags & ChunkIndex.F_USED):
                pack_unused[pid] += entry.obj_size

        # decide each pack's fate from the tallies
        drop_packs, rewrite_packs = set(), set()
        for pid, total in pack_total.items():
            unused = pack_unused.get(pid, 0)  # .get, not [pid]: don't insert all-used packs into the dict
            if unused == 0:
                continue  # all used -> leave alone
            if unused == total:
                drop_packs.add(pid)  # all unused -> drop the whole file
            elif 100 * unused / total >= self.threshold:
                rewrite_packs.add(pid)  # mixed and wasteful enough -> copy survivors forward
            # else: mixed but below threshold -> leave alone
        if self.dry_run:
            freed = sum(pack_unused[pid] for pid in drop_packs) + sum(pack_unused[pid] for pid in rewrite_packs)
            logger.info(
                f"Would free {format_file_size(freed, iec=self.iec)} "
                f"by dropping {len(drop_packs)} packs and rewriting {len(rewrite_packs)} packs."
            )
            return  # dry run: report only, change nothing
        if not drop_packs and not rewrite_packs:
            logger.info("Deleting 0 unused objects...")
            return  # nothing to reclaim; do not touch the cached chunk indexes

        # crash-safety (#9748): invalidate cached chunk indexes before the first store change
        delete_chunkindex_from_repo(self.repository)

        # Pass 2: collect object ids only for the affected packs (a subset, not the whole index)
        keep = {pid: set() for pid in rewrite_packs}  # survivors to copy forward, per pack
        drop = {pid: set() for pid in rewrite_packs}  # unused objects in those same packs
        forget = []  # ids living in fully-unused packs we delete outright
        for id, entry in self.chunks.iteritems():
            pid = entry.pack_id
            if pid in rewrite_packs:
                (keep if entry.flags & ChunkIndex.F_USED else drop)[pid].add(id)
            elif pid in drop_packs:
                forget.append(id)

        # count what we remove: every object of a dropped pack, plus the unused objects cut from
        # rewritten packs. unused objects in below-threshold packs stay, so they don't count.
        deleted = len(forget) + sum(len(ids) for ids in drop.values())
        logger.info(f"Deleting {deleted} unused objects...")
        pi = ProgressIndicatorPercent(
            total=len(drop_packs) + len(rewrite_packs),
            msg="Compacting packs %3.1f%%",
            step=0.1,
            msgid="compact.compact_packs",
        )
        progress = 0
        for pid in drop_packs:
            self.repository.store_delete("packs/" + bin_to_hex(pid))
            progress += 1
            pi.show(progress)  # report after the work, so the final pack lands on 100%
        for id in forget:
            del self.chunks[id]  # their pack file is gone, so drop their index entries too
        for pid in rewrite_packs:
            self.repository.compact_pack(pid, keep_ids=keep[pid], drop_ids=drop[pid])  # helper owns index update
            progress += 1
            pi.show(progress)
        pi.finish()


class CompactMixIn:
    @with_repository(exclusive=True, compatibility=(Manifest.Operation.DELETE,))
    def do_compact(self, args, repository, manifest):
        """Collects garbage in the repository."""
        ArchiveGarbageCollector(
            repository, manifest, stats=args.stats, iec=args.iec, threshold=args.threshold, dry_run=args.dry_run
        ).garbage_collect()

    def build_parser_compact(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        compact_epilog = process_epilog(
            """
            Free repository space by deleting unused chunks.

            ``borg compact`` analyzes all existing archives to determine which repository
            objects are actually used (referenced). It then deletes all unused objects
            from the repository to free space.

            Unused objects may result from:

            - use of ``borg delete`` or ``borg prune``
            - interrupted backups (consider retrying the backup before running compact)
            - backups of source files that encountered an I/O error mid-transfer and were skipped
            - corruption of the repository (e.g., the archives directory lost entries; see notes below)

            You usually do not want to run ``borg compact`` after every write operation, but
            either regularly (e.g., once a month, possibly together with ``borg check``) or
            when disk space needs to be freed.

            **Important:**

            After compacting, it is no longer possible to use ``borg undelete`` to recover
            previously soft-deleted archives.

            ``borg compact`` might also delete data from archives that were "lost" due to
            archives directory corruption. Such archives could potentially be restored with
            ``borg check --find-lost-archives [--repair]``, which is slow. You therefore
            might not want to do that unless there are signs of lost archives (e.g., when
            seeing fatal errors when creating backups or when archives are missing in
            ``borg repo-list``).

            With ``--stats``, borg additionally reports the sum of stored object sizes
            before and after compaction.
            """
        )
        subparser = ArgumentParser(parents=[common_parser], description=self.do_compact.__doc__, epilog=compact_epilog)
        subparsers.add_subcommand("compact", subparser, help="compact the repository")
        subparser.add_argument(
            "-n",
            "--dry-run",
            dest="dry_run",
            action="store_true",
            help="do not change the repository, just show what compact would free",
        )
        subparser.add_argument(
            "-s", "--stats", dest="stats", action="store_true", help="print repository size statistics"
        )
        subparser.add_argument(
            "--threshold",
            metavar="PERCENT",
            dest="threshold",
            type=int,
            default=10,
            help="rewrite a pack when at least PERCENT of its bytes are unused (default: 10)",
        )

from collections import defaultdict
from pathlib import Path

from borgstore.store import ItemInfo, ObjectNotFound as StoreObjectNotFound

from ._common import with_repository
from ..archive import Archive
from ..cache import write_chunkindex_to_repo, build_chunkindex_from_repo, delete_chunkindex_from_repo
from ..cache import files_cache_name, discover_files_cache_names
from ..helpers import get_cache_dir
from ..helpers.argparsing import ArgumentParser
from ..constants import *  # NOQA
from ..hashindex import ChunkIndex
from ..helpers import set_ec, EXIT_ERROR, Error, sig_int, format_file_size, bin_to_hex, hex_to_bin, IntegrityError
from ..helpers import ProgressIndicatorPercent
from ..manifest import Manifest
from ..repository import Repository

from ..logger import create_logger

logger = create_logger()


class ArchiveGarbageCollector:
    def __init__(self, repository, manifest, *, stats, iec, threshold, dry_run=False):
        self.repository = repository
        assert isinstance(repository, Repository)
        self.manifest = manifest
        self.chunks = None  # a ChunkIndex, here used for: id -> (is_used, stored_size)
        self.missing_chunks = set()  # chunk ids referenced by archives but missing from the index
        self.total_files = None  # overall number of source files written to all archives in this repo
        self.total_size = None  # overall size of source file content data written to all archives
        self.archives_count = None  # number of archives
        self.stats = stats  # compute repo space usage before/after - lists all repo objects, can be slow.
        self.threshold = threshold  # rewrite a mixed pack only when its wasted-bytes fraction reaches this percent
        self.iec = iec  # formats statistics using IEC units (1KiB = 1024B)
        self.dry_run = dry_run

    def garbage_collect(self):
        """Removes unused chunks from a repository."""
        logger.info("Starting compaction / garbage collection...")
        self.chunks = self.get_repository_chunks()
        logger.info("Computing object IDs used by archives...")
        (self.missing_chunks, self.total_files, self.total_size, self.archives_count) = self.analyze_archives()
        self.report_and_delete()
        if not self.dry_run:
            self.save_chunk_index()
            if sig_int:  # raise after saving, so a Ctrl-C still leaves a valid index
                raise Error("Got Ctrl-C / SIGINT.")
            self.cleanup_files_cache()
        logger.info("Finished compaction / garbage collection...")

    def get_repository_chunks(self) -> ChunkIndex:
        """return a chunks index"""
        # Entries must start as unused (F_NONE); analyze_archives() marks the used ones afterwards.
        # The index loads entries with F_NONE flags and each object's obj_size (used by --stats).
        # init_flags applies when there is no index and the entries are read from the pack headers.
        logger.info("Getting object IDs from the index...")
        chunks = build_chunkindex_from_repo(
            self.repository, write_immediately=not self.dry_run, init_flags=ChunkIndex.F_NONE
        )
        return chunks

    def save_chunk_index(self):
        # as we may have deleted some chunks, we must write a full updated chunkindex to the repo
        # and also remove all older chunk indexes.
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

        cache_dir = Path(get_cache_dir(self.repository.id_str, create=False))
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

    def _mark_object_used(self, id, size=0) -> bool:
        """Mark object <id> used in the chunks index, updating its stored size. Return False if <id>
        is not in the index."""
        entry = self.chunks.get(id)
        if entry is None:
            return False
        new_size = size if entry.size == 0 and size != 0 else entry.size
        self.chunks[id] = entry._replace(flags=entry.flags | ChunkIndex.F_USED, size=new_size)
        return True

    def _archive_object_ids(self, archive):
        """Yield every object id an archive references: its metadata object, item metadata, and the
        content chunks of its items."""
        yield archive.id
        yield from archive.metadata.item_ptrs
        yield from archive.metadata.items
        for item in archive.iter_items():
            if "chunks" in item:
                for id, _ in item.chunks:
                    yield id

    def analyze_archives(self) -> tuple[set, int, int, int]:
        """Iterate over all items in all archives, create the dicts id -> size of all used chunks."""

        def use_it(id, size=0):
            if not self._mark_object_used(id, size):
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
                        use_it(id, size)
            pi.show(i + 1)  # report after each archive, so the last one lands on 100%
        pi.finish()
        return missing_chunks, total_files, total_size, num_archives

    def report_and_delete(self):
        if self.missing_chunks:
            logger.error(f"Repository has {len(self.missing_chunks)} missing objects!")
            for id in sorted(self.missing_chunks):
                logger.debug(f"Missing object {bin_to_hex(id)}")
            set_ec(EXIT_ERROR)
            # the repo is damaged: keep the soft-deleted archives so "borg undelete" stays possible
            # until "borg check --repair" has run.
            self.mark_soft_deleted_used()
        elif not self.dry_run:
            logger.info("Cleaning archives directory from soft-deleted archives...")
            archive_infos = self.manifest.archives.list(sort_by=["ts"], deleted=True)
            for archive_info in archive_infos:
                name, id, hex_id = archive_info.name, archive_info.id, bin_to_hex(archive_info.id)
                try:
                    self.manifest.archives.nuke_by_id(id)
                except self.repository.ObjectNotFound:
                    logger.warning(f"Soft-deleted archive {name} {hex_id} not found.")

        repo_size_before, repo_size_after = self.compact_packs()

        if self.stats:
            deduplicated_size = sum(
                entry.size for id, entry in self.chunks.iteritems() if entry.flags & ChunkIndex.F_USED
            )
            count = len(self.chunks)
            logger.info(f"Overall statistics, considering all {self.archives_count} archives in this repository:")
            logger.info(
                f"Source data size was {format_file_size(self.total_size, precision=0, iec=self.iec)} "
                f"in {self.total_files} files."
            )
            logger.info(f"Deduplicated size is {format_file_size(deduplicated_size, precision=0, iec=self.iec)}.")
            dedup_factor = deduplicated_size / self.total_size if self.total_size else 1.0
            logger.info(f"Deduplication factor is {dedup_factor:.2f}.")
            logger.info(
                f"Repository size is {format_file_size(repo_size_after, precision=0, iec=self.iec)} "
                f"in {count} objects."
            )
            comp_factor = repo_size_after / deduplicated_size if deduplicated_size else 1.0
            logger.info(f"Compression factor is {comp_factor:.2f}.")
            if not self.dry_run:  # nothing was deleted on a dry run, so before == after
                logger.info(
                    f"Compaction saved "
                    f"{format_file_size(repo_size_before - repo_size_after, precision=0, iec=self.iec)}."
                )

    def mark_soft_deleted_used(self):
        """Flag every chunk of the soft-deleted archives F_USED, so compaction keeps them.

        Keeps each soft-deleted archive's metadata object, item metadata and file content, so
        "borg undelete" can still recover it. An archive whose metadata object is itself already
        gone is skipped with a warning.
        """
        for archive_info in self.manifest.archives.list(sort_by=["ts"], deleted=True):
            try:
                archive = Archive(self.manifest, archive_info.id, iec=self.iec, deleted=True)
                for id in self._archive_object_ids(archive):
                    self._mark_object_used(id)
            except (Repository.ObjectNotFound, IntegrityError) as e:
                name, hex_id = archive_info.name, bin_to_hex(archive_info.id)
                logger.warning(f"Soft-deleted archive {name} {hex_id} cannot be fully preserved: {e}")

    def compact_packs(self):
        """Free space one pack at a time (the store can only delete whole packs).

        analyze_archives() has flagged the used objects F_USED. Only indexed-but-unused bytes are
        reclaimed; bytes no index entry covers are preserved (see below). Per pack:

        - all indexed objects unused, whole file indexed -> delete the pack.
        - some indexed objects unused                    -> rewrite if the unused bytes reach
                                --threshold percent: copy the used objects (and any unindexed bytes)
                                into a new pack via compact_pack and drop the old one. Below the
                                threshold keep the pack, so we don't rewrite a large pack to reclaim
                                little.
        - no indexed objects unused                      -> keep the pack.

        A pack can hold bytes no index entry covers (a chunk copy stored again elsewhere, or objects
        from a backup that crashed before writing its index). compact_pack keeps those; recovering or
        dropping them is "borg check --repair"'s job. See issue #9868.

        Two passes bound the memory use: the first keeps only per-pack byte counts to pick the packs
        to change, the second collects object ids for just those packs, not the whole index.

        A pack's size is the file size the store reports, so it also counts bytes no index entry covers.

        Returns (repo_size_before, repo_size_after), the on-disk pack size before and after this run.
        """
        # Pass 1: list the pack files and their sizes; these are the packs we consider.
        pack_total = {}  # pack_id -> file size in the store
        for info in self.repository.store_list("packs"):
            info = ItemInfo(*info)
            pack_total[hex_to_bin(info.name)] = info.size
        repo_size_before = sum(pack_total.values())  # on-disk pack size before compaction (for --stats)

        # sum the used bytes per pack from the index; also sum every entry's bytes (used or not) to
        # detect which packs hold unindexed bytes. collect index entries whose pack is not in the store.
        pack_used = defaultdict(int)
        pack_indexed = defaultdict(int)  # pack_id -> bytes of all its index entries, used or not
        stale_ids = []  # index entries referencing a pack file that is not in the store
        stale_used = 0  # how many of those were still flagged used (lost data)
        for id, entry in self.chunks.iteritems():
            pid = entry.pack_id
            if pid not in pack_total:
                stale_ids.append(id)
                if entry.flags & ChunkIndex.F_USED:
                    stale_used += 1
            else:
                pack_indexed[pid] += entry.obj_size
                if entry.flags & ChunkIndex.F_USED:
                    pack_used[pid] += entry.obj_size

        if stale_ids:
            # keep these entries: they may be an archive's only pointer to a chunk. dropping them is
            # "borg check --repair"'s call.
            logger.warning(f'{len(stale_ids)} index entries reference missing pack files; run "borg check --repair".')
            if stale_used:
                logger.error(f"{stale_used} of them are still in use: repository data is missing!")
                set_ec(EXIT_ERROR)

        # decide each pack's fate. compact reclaims only indexed-but-unused bytes; bytes no index entry
        # covers (total - indexed) are preserved by compact_pack, so they never count as reclaimable.
        drop_packs, rewrite_packs = set(), set()
        pack_reclaim = {}  # pack_id -> reclaimable bytes, for the packs we act on (drop or rewrite)
        for pid, total in pack_total.items():
            indexed = pack_indexed[pid]
            used = pack_used[pid]
            if indexed > total:
                # the index lists more bytes than the file holds.
                logger.error(f'Pack {bin_to_hex(pid)}: index claims more data than the file holds, run "borg check".')
                set_ec(EXIT_ERROR)
                continue  # leave this pack untouched
            reclaimable = indexed - used  # unused indexed bytes; the only bytes compact removes
            if reclaimable == 0:
                continue  # nothing to reclaim -> leave alone
            if used == 0 and indexed == total:
                drop_packs.add(pid)  # whole file is unused indexed bytes -> drop it
                pack_reclaim[pid] = reclaimable
            elif 100 * reclaimable / total >= self.threshold:
                rewrite_packs.add(pid)  # wasteful enough -> copy used objects (and unindexed bytes) forward
                pack_reclaim[pid] = reclaimable
            # else: below threshold -> leave alone
        if self.dry_run:
            freed = sum(pack_reclaim.values())
            logger.info(
                f"Would free {format_file_size(freed, iec=self.iec)} "
                f"by dropping {len(drop_packs)} packs and rewriting {len(rewrite_packs)} packs."
            )
            return repo_size_before, repo_size_before  # dry run: report only, change nothing
        if not drop_packs and not rewrite_packs:
            logger.info("Deleting 0 unused objects...")
            return repo_size_before, repo_size_before  # nothing to reclaim; chunk indexes stay valid

        # crash-safety (#9748): invalidate chunk indexes before the first store change
        delete_chunkindex_from_repo(self.repository)

        # Pass 2: collect object ids only for the affected packs (a subset, not the whole index)
        keep = defaultdict(set)  # rewrite pack_id -> its used objects, kept in the new pack
        drop = defaultdict(set)  # rewrite pack_id -> unused objects in that pack
        forget = defaultdict(set)  # drop pack_id -> objects to remove from the index
        for id, entry in self.chunks.iteritems():
            pid = entry.pack_id
            if pid in rewrite_packs:
                (keep if entry.flags & ChunkIndex.F_USED else drop)[pid].add(id)
            elif pid in drop_packs:
                forget[pid].add(id)

        # deleted counts index objects removed: every object of a dropped pack, plus the unused
        # objects cut from rewritten packs. reclaimed counts the bytes freed.
        deleted = sum(len(ids) for ids in forget.values()) + sum(len(ids) for ids in drop.values())
        reclaimed = sum(pack_reclaim.values())
        logger.info(f"Deleting {deleted} unused objects, freeing {format_file_size(reclaimed, iec=self.iec)}...")
        pi = ProgressIndicatorPercent(
            total=len(drop_packs) + len(rewrite_packs),
            msg="Compacting packs %3.1f%%",
            step=0.1,
            msgid="compact.compact_packs",
        )
        progress = 0
        # self.chunks stays consistent with the store after each pack, so Ctrl-C can stop between packs
        for pid in drop_packs:
            if sig_int:
                break
            try:
                self.repository.store_delete("packs/" + bin_to_hex(pid))
            except StoreObjectNotFound:
                # happens when a stale chunk index references an already deleted pack (#9850)
                logger.warning(f"Pack {bin_to_hex(pid)} to delete was already gone.")
            for id in forget[pid]:  # drop the deleted pack's index entries
                del self.chunks[id]
            progress += 1
            pi.show(progress)  # report after the work, so the final pack lands on 100%
        for pid in rewrite_packs:
            if sig_int:
                break
            # chunks=self.chunks: the index updates (repoint kept objects, remove dropped ones)
            # must land in the index that save_chunk_index() persists (#9850).
            self.repository.compact_pack(pid, keep_ids=keep[pid], drop_ids=drop[pid], chunks=self.chunks)
            progress += 1
            pi.show(progress)
        pi.finish()

        # a rewritten pack shrinks by exactly its dropped bytes, so reclaimed is the exact on-disk delta.
        return repo_size_before, repo_size_before - reclaimed


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

            ``borg compact`` only reclaims objects the chunk index knows about. Bytes no index entry
            covers (redundant copies written by concurrent backups, or packs left behind by a backup
            that crashed before recording its objects) are kept and reclaimed by ``borg check --repair``.

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

            With ``--stats``, borg additionally reports the on-disk size of the pack files
            before and after compaction (the reported compression factor is based on that size).
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

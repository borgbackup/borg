from collections import defaultdict
import os

from ._common import with_repository, define_archive_filters_group
from ..archive import Archive
from ..cache import get_archive_references, list_archive_reference_caches
from ..constants import *  # NOQA
from ..helpers import bin_to_hex, Error, format_file_size, use_iec_units
from ..helpers import ProgressIndicatorPercent
from ..helpers.argparsing import ArgumentParser
from ..manifest import Manifest
from ..repository import Repository

from ..logger import create_logger

logger = create_logger()

# Ephemeral (never persisted) user flag bits, used only while computing deduplication sizes.
# ChunkIndex.M_USER covers bits 0..23; bits 0..2 are taken by F_USED/F_COMPRESS/F_PENDING.
#
# Set mode (a set of archives is considered): F_CONSIDERED marks a chunk referenced by the
# considered set, F_REST one referenced by the rest of the archives (see issue #5741 and
# ThomasWaldmann's proposal there).
F_CONSIDERED = 2**3
F_REST = 2**4
# By-name mode: bits 5..22 hold the owning archive name (as index + 1, so 0 means "referenced by no
# archive"), bit 23 marks a chunk referenced by more than one name. This decomposes the repository
# in a single pass: each chunk is either exclusive to one name, shared, or unreferenced.
OWNER_SHIFT = 5
OWNER_MASK = 2**18 - 1  # bits 5..22
F_MULTI = 2**23
MAX_NAMES = OWNER_MASK - 1  # owner values are name index + 1


class ArchiveAnalyzer:
    def __init__(self, args, repository, manifest):
        self.args = args
        self.repository = repository
        assert isinstance(repository, Repository)
        self.manifest = manifest
        self.iec = use_iec_units()
        self.difference_by_path = defaultdict(int)  # directory path -> count of chunks changed

    def analyze(self):
        logger.info("Starting archives analysis...")
        if self.args.by_name:
            # the decomposition is inherently repository-wide: "shared" and "unreferenced" can only
            # be determined by looking at every archive, so archive filters must not be applied.
            filters = ["match_archives", "first", "last", "older", "newer", "oldest", "newest"]
            if any(getattr(self.args, name, None) for name in filters):
                raise Error("--by-name analyzes the whole repository and cannot be combined with archive filters.")
            self.analyze_by_name()
        else:
            considered_infos = self.manifest.archives.list_considering(self.args)
            if not considered_infos:
                raise Error("No archives match the given selection criteria.")
            self.analyze_dedup_size(considered_infos)
            if len(considered_infos) >= 2:
                self.analyze_hotspots(considered_infos)
                self.report_hotspots()
            else:
                logger.info("Skipping hot-spot analysis (needs at least 2 matching archives).")
        logger.info("Finished archives analysis.")

    def fmt(self, value):
        return format_file_size(value, iec=self.iec)

    def factor(self, stored, plaintext):
        """The compression factor stored/plaintext, or n/a if there is no plaintext size to relate to
        (unreferenced chunks, or chunks that are all archive metadata, which is recorded with size 0).
        """
        return f"{stored / plaintext:.2f}" if plaintext else "n/a"

    def mark_references(self, archive_infos, update_flags):
        """Walk the given archives' referenced chunks, updating their entry in the repository chunk
        index via update_flags(flags) -> flags. Also fills in the plaintext size, which is 0 in the
        repo index (it is only recorded in the archives referencing a chunk). Returns the number of
        referenced chunks that are missing from the index.

        The chunk ids and plaintext sizes come from the per-archive references cache (see borg
        compact), so unchanged archives are not opened/decrypted at all.
        """
        index = self.repository.chunks
        cached_hex_ids = list_archive_reference_caches(self.repository)
        missing = 0
        num = len(archive_infos)
        pi = ProgressIndicatorPercent(
            total=num, msg="Computing referenced chunks %3.1f%%", step=0.1, msgid="analyze.dedup_size"
        )
        for i, info in enumerate(archive_infos):
            references = get_archive_references(
                self.repository, self.manifest, info.id, cached=bin_to_hex(info.id) in cached_hex_ids, iec=self.iec
            )
            for id, ref in references.ids.items():
                entry = index.get(id)
                if entry is None:
                    missing += 1  # referenced by an archive but absent from the repo index
                    continue
                # _replace keeps pack_id/obj_offset/obj_size (esp. the stored size obj_size) intact.
                index[id] = entry._replace(flags=update_flags(entry.flags), size=ref.size or entry.size)
            pi.show(i + 1)
        pi.finish()
        return missing

    def analyze_by_name(self) -> None:
        """Decompose the whole repository by archive name.

        Archives sharing a name form a series, so a name usually groups all backups of one source;
        for old-style archives that do not form a series, each name is just one archive.

        Every chunk falls into exactly one bucket: exclusive to a single name (no archive of another
        name references it, so deleting all archives of that name would free it), shared by two or
        more names, or referenced by no non-deleted archive at all (reclaimable by borg compact).
        The buckets add up to the repository's deduplicated size.

        This needs only a single pass over all archives: each chunk records the name that first
        referenced it, and a reference from a different name sets the F_MULTI bit.
        """
        all_infos = self.manifest.archives.list()  # non-deleted archives
        if not all_infos:
            raise Error("The repository does not contain any archives.")
        archives_per_name: dict[str, int] = defaultdict(int)
        for info in all_infos:
            archives_per_name[info.name] += 1
        names = sorted(archives_per_name)
        if len(names) > MAX_NAMES:
            raise Error(f"Too many distinct archive names ({len(names)}) to decompose, limit is {MAX_NAMES}.")
        owner_of = {name: i + 1 for i, name in enumerate(names)}  # 0 means "unreferenced"

        missing = 0
        for info in all_infos:
            owner = owner_of[info.name]

            def update_flags(flags, owner=owner):
                previous = (flags >> OWNER_SHIFT) & OWNER_MASK
                if previous == 0:  # first name referencing this chunk becomes its owner
                    return flags | (owner << OWNER_SHIFT)
                if previous != owner:  # a second, different name references it: shared
                    return flags | F_MULTI
                return flags

            missing += self.mark_references([info], update_flags)

        exclusive = {name: [0, 0] for name in names}  # archive name -> [source size, stored size]
        shared = [0, 0]
        unref_count = unref_stored = total_count = 0
        for id, entry in self.repository.chunks.iteritems():
            total_count += 1
            owner = (entry.flags >> OWNER_SHIFT) & OWNER_MASK
            if owner == 0:
                unref_count += 1
                unref_stored += entry.obj_size
                continue
            bucket = shared if entry.flags & F_MULTI else exclusive[names[owner - 1]]
            bucket[0] += entry.size
            bucket[1] += entry.obj_size

        if missing:
            logger.warning(f"{missing} chunk(s) referenced by archives are missing from the repository index.")

        total_plaintext = shared[0] + sum(v[0] for v in exclusive.values())
        total_stored = shared[1] + sum(v[1] for v in exclusive.values())
        width = min(max([30] + [len(name) for name in names]), 60)

        def row(label, archives, source, stored, *, source_known=True):
            sizes = f"{self.fmt(source) if source_known else 'n/a':>14}{self.fmt(stored):>14}"
            ratio = self.factor(stored, source) if source_known else "n/a"
            print(f"{label:<{width}}{archives:>10}{sizes}{ratio:>13}")

        print()
        print("Repository decomposition by archive name")
        print("=" * (width + 51))
        print(f"{len(all_infos)} archive(s) with {len(names)} distinct name(s)")
        print()
        print(f"{'name':<{width}}{'archives':>10}{'source':>14}{'stored':>14}{'compression':>13}")
        # biggest exclusive consumer first - that is what one would act on
        for name in sorted(names, key=lambda n: exclusive[n][1], reverse=True):
            source, stored = exclusive[name]
            row(name, archives_per_name[name], source, stored)
        row("(shared by 2+ names)", "", shared[0], shared[1])
        row("(unreferenced)", "", 0, unref_stored, source_known=False)
        print("-" * (width + 51))
        row("total (deduplicated)", len(all_infos), total_plaintext, total_stored)
        print()
        print(f"Unreferenced: {unref_count} of {total_count} chunks in the repository index.")
        print()
        print("Each chunk is counted in exactly one row, so the rows add up to the total.")
        print("A name row shows what is exclusive to it: no archive of another name references these")
        print("chunks, so deleting all archives of that name would free them. Chunks used by several")
        print("names are counted in the shared row, not against any single name.")
        print()
        print(f"{'source':<12} = uncompressed source data size (each chunk counted once)")
        print(f"{'stored':<12} = deduplicated size as stored in the repository (compressed)")
        print(f"{'compression':<12} = stored / source (1.00 = not compressible)")
        print(f"{'unreferenced':<12} = referenced by no non-deleted archive; borg compact could free")
        print(f"{'':<12}   these. Their source size (n/a) is not known: it is only recorded")
        print(f"{'':<12}   in the archives referencing a chunk. Chunks of soft-deleted")
        print(f"{'':<12}   archives count as unreferenced (borg compact keeps them if the")
        print(f"{'':<12}   repository is damaged).")

    def analyze_dedup_size(self, considered_infos) -> None:
        """Compute and report the deduplicated size of the considered set of archives.

        For both the plaintext (uncompressed source) size and the stored (compressed, as stored in
        the repository) size, two figures are reported:

        - the set's deduplicated size: the summed size of the union of chunks the considered archives
          reference (chunks shared *within* the set are counted once);
        - the set's exclusive size: the summed size of chunks referenced *only* by the considered set
          and not by any other (rest) archive - i.e. the space that deleting the whole set would free
          (assuming the rest of the archives stay).

        As the considered set plus the rest covers all non-deleted archives, the chunks that end up
        with neither flag are referenced by no non-deleted archive at all: what `borg compact` could
        free in the current state of the repository. These are reported as well; only their stored
        size is known, as a chunk's plaintext size is only recorded in the archives referencing it.

        Following the model in issue #5741, we flag each chunk as referenced by the considered set
        (F_CONSIDERED) and/or by the rest of the archives (F_REST). Rather than building a second
        index, we reuse the repository's own chunk index (self.repository.chunks): it already holds
        every chunk's stored size (obj_size). We OR in the membership flag bits and fill in the
        plaintext size (which is 0 in the repo index) from the per-archive references cache. These
        in-memory mutations are never persisted: write_chunkindex_to_repo() zeroes flags and size,
        and close() only serializes F_NEW entries (there are none here).
        """
        considered_ids = {info.id for info in considered_infos}
        all_infos = self.manifest.archives.list()  # non-deleted archives; the rest = all - considered
        rest_infos = [info for info in all_infos if info.id not in considered_ids]

        missing = self.mark_references(considered_infos, lambda flags: flags | F_CONSIDERED)
        missing += self.mark_references(rest_infos, lambda flags: flags | F_REST)

        set_plaintext = set_stored = excl_plaintext = excl_stored = 0
        unref_count = unref_stored = total_count = 0
        for id, entry in self.repository.chunks.iteritems():
            total_count += 1
            flags = entry.flags
            if flags & F_CONSIDERED:
                set_plaintext += entry.size
                set_stored += entry.obj_size
                if not (flags & F_REST):
                    excl_plaintext += entry.size
                    excl_stored += entry.obj_size
            elif not (flags & F_REST):
                # neither flag: this chunk is referenced by no non-deleted archive at all.
                unref_count += 1
                unref_stored += entry.obj_size

        if missing:
            logger.warning(f"{missing} chunk(s) referenced by archives are missing from the repository index.")

        # with no archive left over, the considered set is the whole repository: every referenced
        # chunk is trivially exclusive to it, so that line would just repeat the deduplicated size.
        whole_repo = not rest_infos

        def row(label, source, stored, *, source_known=True):
            sizes = f"{self.fmt(source) if source_known else 'n/a':>14}{self.fmt(stored):>14}"
            ratio = self.factor(stored, source) if source_known else "n/a"
            print(f"{label:<26}{sizes}{ratio:>13}")

        print()
        if whole_repo:
            print("Deduplicated size of the whole repository")
            print("=" * 67)
            print(f"Archives: {len(all_infos)} (all archives in the repository)")
        else:
            print(f"Deduplicated size of the {len(considered_infos)} considered archive(s)")
            print("=" * 67)
            print(f"Considered archives: {len(considered_infos)} (of {len(all_infos)} in the repository)")
        print()
        print(f"{'':26}{'source':>14}{'stored':>14}{'compression':>13}")
        row("Deduplicated size:" if whole_repo else "Deduplicated size of set:", set_plaintext, set_stored)
        if not whole_repo:
            row("Exclusive size of set:", excl_plaintext, excl_stored)
        row("Unreferenced chunks:", 0, unref_stored, source_known=False)
        print()
        print(f"Unreferenced: {unref_count} of {total_count} chunks in the repository index.")
        print()
        if whole_repo:
            print(f"{'source':<12} = uncompressed source data size (each chunk counted once)")
        else:
            print(f"{'source':<12} = uncompressed source data size (chunks shared within the set counted once)")
        print(f"{'stored':<12} = deduplicated size as stored in the repository (compressed)")
        print(f"{'compression':<12} = stored / source (1.00 = not compressible)")
        if not whole_repo:
            print(f"{'exclusive':<12} = chunks referenced only by this set; would be freed by deleting the set")
        print(f"{'unreferenced':<12} = chunks referenced by no non-deleted archive; borg compact could free")
        print(f"{'':<12}   these. Their source size (n/a) is not known: it is only recorded in")
        print(f"{'':<12}   the archives referencing a chunk. Chunks of soft-deleted archives")
        print(f"{'':<12}   count as unreferenced (borg compact keeps them if the repo is damaged).")

    def analyze_hotspots(self, archive_infos) -> None:
        """Analyze all considered archives to find directory "hot spots" (chunk churn per directory)."""
        num_archives = len(archive_infos)
        pi = ProgressIndicatorPercent(
            total=num_archives, msg="Analyzing archives %3.1f%%", step=0.1, msgid="analyze.analyze_archives"
        )
        i = 0
        info = archive_infos[i]
        pi.show(i)
        logger.info(
            f"Analyzing archive {info.name} {info.ts.astimezone()} {bin_to_hex(info.id)} ({i + 1}/{num_archives})"
        )
        base = self.analyze_archive(info.id)
        for i, info in enumerate(archive_infos[1:]):
            pi.show(i + 1)
            logger.info(
                f"Analyzing archive {info.name} {info.ts.astimezone()} {bin_to_hex(info.id)} ({i + 2}/{num_archives})"
            )
            new = self.analyze_archive(info.id)
            self.analyze_change(base, new)
            base = new
        pi.finish()

    def analyze_archive(self, id):
        """compute the set of chunks for each directory in this archive"""
        archive = Archive(self.manifest, id)
        chunks_by_path = defaultdict(dict)  # collect all chunk IDs generated from files in this directory path
        for item in archive.iter_items():
            if "chunks" in item:
                item_chunks = dict(item.chunks)  # chunk id -> plaintext size
                directory_path = os.path.dirname(item.path)
                chunks_by_path[directory_path] |= item_chunks
        return chunks_by_path

    def analyze_change(self, base, new):
        """for each directory path, sum up the changed (removed or added) chunks' sizes between base and new."""

        def analyze_path_change(path):
            base_chunks = base[path]
            new_chunks = new[path]
            # add up added chunks' sizes
            for id in new_chunks.keys() - base_chunks.keys():
                self.difference_by_path[directory_path] += new_chunks[id]
            # add up removed chunks' sizes
            for id in base_chunks.keys() - new_chunks.keys():
                self.difference_by_path[directory_path] += base_chunks[id]

        for directory_path in base:
            analyze_path_change(directory_path)
        for directory_path in new:
            if directory_path not in base:
                analyze_path_change(directory_path)

    def report_hotspots(self):
        print()
        print("chunks added or removed by directory path")
        print("=========================================")
        for directory_path in sorted(self.difference_by_path, key=lambda p: self.difference_by_path[p], reverse=True):
            difference = self.difference_by_path[directory_path]
            print(f"{directory_path}: {difference}")


class AnalyzeMixIn:
    @with_repository(compatibility=(Manifest.Operation.READ,))
    def do_analyze(self, args, repository, manifest):
        """Analyzes archives."""
        ArchiveAnalyzer(args, repository, manifest).analyze()

    def build_parser_analyze(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        analyze_epilog = process_epilog(
            """
            Analyze the archives matching the usual archive selection options (e.g. ``-a series_name``).

            **Deduplicated size of a set of archives**

            For the considered (matching) set of archives, ``borg analyze`` reports the *source*
            (uncompressed source data) and *stored* (compressed, as stored in the repository) size,
            plus the *compression* factor relating the two (stored / source):

            - the *deduplicated size of the set*: the summed size of the union of chunks the
              considered archives reference (chunks shared *within* the set are counted once);
            - the *exclusive size of the set*: the summed size of chunks referenced *only* by the
              considered set and by no other archive - i.e. the space that deleting the whole set
              would free (assuming the other archives stay).

            Additionally, the *unreferenced chunks* are reported: chunks in the repository that no
            non-deleted archive references, i.e. what ``borg compact`` could free in the current
            state of the repository. Only their stored size is known - a chunk's source size is
            only recorded in the archives that reference it. Note that chunks belonging to
            soft-deleted archives count as unreferenced here, although ``borg compact`` keeps them
            when the repository is damaged (so ``borg undelete`` stays possible).

            If no archive filter is given, all archives are considered - every referenced chunk is
            then trivially exclusive to them, so only the repository-wide deduplicated size is shown.

            The stored sizes come from the repository's chunk index; the chunk membership and the
            source sizes come from the per-archive references cache that ``borg compact``
            maintains, so unchanged archives usually do not need to be opened.

            **Decomposition by archive name (--by-name)**

            With ``--by-name``, the whole repository is decomposed by archive name instead. Archives
            sharing a name form a series, so a name usually groups all backups of one source; for
            old-style archives that do not form a series, each name is just one archive.

            Every chunk is counted in exactly one row, so the rows add up to the repository's
            deduplicated size:

            - one row per archive name, showing what is *exclusive* to it: no archive of another name
              references these chunks, so deleting all archives of that name would free them;
            - one row for the chunks shared by two or more names;
            - one row for the unreferenced chunks (see above).

            This answers "which name costs how much, and what would I get back by dropping it" for
            all names at once, in a single pass over the archives. As the shared and unreferenced
            rows can only be determined by looking at every archive, ``--by-name`` always covers the
            whole repository and cannot be combined with archive filters.

            **Hot spots**

            If at least two archives match, ``borg analyze`` additionally iterates over all matching
            archives, over all contained files, and collects information about chunks stored in all
            directories it encounters. It considers chunk IDs and their plaintext sizes and adds up
            the sizes of added and removed chunks per direct parent directory, and outputs a list of
            "directory: size".

            You can use that list to find directories with a lot of "activity" — maybe some of these
            are temporary or cache directories you forgot to exclude. To avoid including these unwanted
            directories in your backups, you can carefully exclude them in ``borg create`` (for future
            backups) or use ``borg recreate`` to recreate existing archives without them.
            """
        )
        subparser = ArgumentParser(parents=[common_parser], description=self.do_analyze.__doc__, epilog=analyze_epilog)
        subparsers.add_subcommand("analyze", subparser, help="analyze archives")
        subparser.add_argument(
            "--by-name",
            dest="by_name",
            action="store_true",
            help="decompose the whole repository by archive name (not combinable with archive filters)",
        )
        define_archive_filters_group(subparser)

import logging
from collections import defaultdict

from borgstore.store import ItemInfo

from ._common import with_repository, Highlander
from ..cache import build_chunkindex_from_repo, delete_chunkindex_from_repo, write_chunkindex_to_repo
from ..compress import ObfuscateSize, Auto, COMPRESSOR_TABLE
from ..constants import *  # NOQA
from ..helpers import sig_int, ProgressIndicatorPercent, Error, CompressionSpec
from ..helpers import format_file_size, hex_to_bin
from ..helpers.argparsing import ArgumentParser
from ..manifest import Manifest
from ..repoobj import object_validator
from ..repository import Repository

from ..logger import create_logger

logger = create_logger()


def get_csettings(c):
    """Return the (ctype, clevel, olevel) compression settings a compressor is configured for.

    clevel is the *stored* level byte, so that it can be compared against the clevel of an
    existing repo object as-is - see PackRecompressor.transform.
    """
    if isinstance(c, Auto):
        return get_csettings(c.compressor)
    if isinstance(c, ObfuscateSize):
        ctype, clevel, _ = get_csettings(c.compressor)
        olevel = c.level
        return ctype, clevel, olevel
    ctype, clevel, olevel = c.ID, c.encode_level(c.level), -1
    return ctype, clevel, olevel


def format_compression_spec(ctype, clevel, olevel):
    obfuscation = "" if olevel == -1 else f"obfuscate,{olevel},"
    for cname, cls in COMPRESSOR_TABLE.items():
        if cls.ID == ctype:
            cname = f"{cname}"
            break
    else:
        cname, cls = f"{ctype}", None
    if cls is not None:
        # decode before checking for 255 ("level not applicable"): for zstd the byte is an
        # int8_t, so 255 there is level -1 and has to be shown.
        clevel = cls.decode_level(clevel)
    clevel = f",{clevel}" if clevel != 255 else ""
    return obfuscation + cname + clevel


class PackRecompressor:
    """Recompress a repository's objects to the desired compression, one pack at a time.

    Each pack is loaded once (via Repository.transform_pack); objects not stored with the desired
    compression get recompressed, the others are carried into the rewritten pack unchanged. A pack
    whose objects all already match is not rewritten at all.
    """

    def __init__(self, repository, manifest, *, print_stats):
        self.repository = repository
        assert isinstance(repository, Repository)
        self.repo_objs = manifest.repo_objs
        self.print_stats = print_stats
        self.wanted = get_csettings(self.repo_objs.compressor)  # desired compression set by --compression
        self.chunks = None  # a ChunkIndex: chunk id -> pack location
        self.store_changed = False  # True once the store (and thus any stored chunk index) was modified
        # per-object outcomes; the three counters are disjoint, their sum is the objects seen
        self.objects_ok = 0  # already stored with the desired compression
        self.objects_kept = 0  # recompression yielded what is already stored -> old object kept
        self.objects_recompressed = 0  # recompressed and rewritten
        self.packs_count = 0
        self.packs_rewritten = 0

    def recompress(self):
        """Recompress the repository pack after pack; Ctrl-C stops cleanly at a pack boundary."""
        logger.info(f"Recompressing repository to {format_compression_spec(*self.wanted)}...")
        self.chunks = build_chunkindex_from_repo(self.repository, write_immediately=True)

        # group the indexed objects per pack; transform_pack requires each pack's complete id list.
        per_pack = defaultdict(list)  # pack_id -> [chunk_id, ...]
        for id, entry in self.chunks.iteritems():
            per_pack[entry.pack_id].append(id)

        # the pack files actually in the store; sorted, so the processing order is reproducible.
        packs = sorted(
            (hex_to_bin(info.name), info.size) for info in map(ItemInfo._make, self.repository.store_list("packs"))
        )
        self.packs_count = len(packs)
        size_before = sum(size for _, size in packs)
        size_after = size_before

        stale_packs = set(per_pack) - {pack_id for pack_id, _ in packs}
        if stale_packs:
            # keep these entries: they may be an archive's only pointer to a chunk. dropping them
            # (repairing the index) is not implemented yet, refs #8572.
            stale = sum(len(per_pack[pack_id]) for pack_id in stale_packs)
            logger.warning(
                f"index entries referencing a missing pack file: {stale}. Repairing the index "
                "(dropping the stale references) is tracked in https://github.com/borgbackup/borg/issues/8572."
            )

        pi = ProgressIndicatorPercent(
            total=len(packs), msg="Recompressing %3.1f%%", step=0.1, msgid="repo_compress.recompress"
        )
        validate = object_validator(self.repo_objs)
        for i, (pack_id, pack_size) in enumerate(packs):
            if sig_int:
                break  # stop cleanly at a pack boundary: save the index below, then raise
            ids = per_pack.get(pack_id)
            # a pack without indexed objects (all-gap) is left for "borg check --repair", see #9868.
            if ids:
                new_pack_id, new_size = self.repository.transform_pack(
                    pack_id,
                    ids,
                    self.transform,
                    chunks=self.chunks,
                    before_change=self.invalidate_stored_index,
                    validate=validate,
                )
                if new_pack_id != pack_id:
                    self.packs_rewritten += 1
                    size_after += new_size - pack_size
            pi.show(i + 1)  # report after the work, so the final pack lands on 100%
        pi.finish()
        if self.store_changed:
            # the stored chunk indexes were invalidated (invalidate_stored_index), so write a full
            # updated index back to the repo; entries were repointed by transform_pack along the way.
            write_chunkindex_to_repo(
                self.repository, self.chunks, incremental=False, clear=True, force_write=True, delete_other=True
            )
            self.chunks = None  # nothing there (cleared!)
        if sig_int:
            # Ctrl-C / SIGINT: raise after saving, so an interrupted run still leaves a valid index
            raise Error("Got Ctrl-C / SIGINT.")
        if self.print_stats:
            self.report(size_before, size_after)

    def invalidate_stored_index(self):
        """Called by transform_pack just before its first store change (crash-safety, see #9748)."""
        if not self.store_changed:
            delete_chunkindex_from_repo(self.repository)
            self.store_changed = True

    def transform(self, id, obj_bytes):
        """Return the recompressed object, or obj_bytes unchanged if recompression is not needed."""
        meta = self.repo_objs.parse_meta(id, obj_bytes, ro_type=ROBJ_DONTCARE)
        found = meta["ctype"], meta["clevel"], meta.get("olevel", -1)
        if found == self.wanted:
            self.objects_ok += 1
            return obj_bytes
        meta, data = self.repo_objs.parse(id, obj_bytes, ro_type=ROBJ_DONTCARE)
        ro_type = meta.pop("type", None)
        if self.wanted[2] == -1:
            # if the object was obfuscated, but should not be in future, remove related metadata
            meta.pop("olevel", None)
            meta.pop("psize", None)
        new_bytes = self.repo_objs.format(id, meta, data, ro_type=ro_type)
        # format() filled meta with the compression actually done - not always the desired one: a
        # DecidingCompressor stores data that does not compress well differently than told.
        done = meta["ctype"], meta["clevel"], meta.get("olevel", -1)
        if done == found:
            # the outcome is what is already stored: keep the old object, otherwise such objects
            # would get recompressed and rewritten **again and again** with no gain.
            self.objects_kept += 1
            return obj_bytes
        self.objects_recompressed += 1
        return new_bytes

    def report(self, size_before, size_after):
        # "borg.output.stats" is enabled at INFO level whenever --stats is given (implied logging).
        stats_logger = logging.getLogger("borg.output.stats")
        objects = self.objects_ok + self.objects_kept + self.objects_recompressed
        stats_logger.info("Recompression stats:")
        stats_logger.info(f"Packs: {self.packs_count} total, {self.packs_rewritten} rewritten.")
        stats_logger.info(
            f"Objects: {objects} total, {self.objects_recompressed} recompressed, "
            f"{self.objects_ok} already had the desired compression, "
            f"{self.objects_kept} kept as-is (recompression brings no gain)."
        )
        delta = size_before - size_after
        change = "shrunk" if delta >= 0 else "grew"
        stats_logger.info(
            f"Repository size: {format_file_size(size_before)} before, {format_file_size(size_after)} after, "
            f"{change} by {format_file_size(abs(delta))}."
        )


class RepoCompressMixIn:
    @with_repository(manifest=True, exclusive=True, compatibility=(Manifest.Operation.CHECK,))
    def do_repo_compress(self, args, repository, manifest):
        """Repository (re-)compression."""
        if not isinstance(repository, Repository):
            raise Error("repo-compress not supported for legacy repositories.")
        # refuse up front on a repo opened read-only, before a fully-compliant repo could make
        # recompression a silent no-op.
        repository.assert_writable()
        PackRecompressor(repository, manifest, print_stats=args.stats).recompress()

    def build_parser_repo_compress(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        repo_compress_epilog = process_epilog(
            """
        Repository (re-)compression (and/or re-obfuscation).

        Reads all repository objects and recompresses the ones that are not already using
        the compression type/level and obfuscation level given via ``--compression``.

        The repository is processed one pack file at a time: a pack is read as a whole and,
        if it holds objects that need recompression, rewritten as a whole - objects already
        using the desired compression are copied into the rewritten pack unchanged. A pack
        whose objects all already use the desired compression is not touched at all.
        Please note that the outcome of recompressing a chunk might not always be the
        desired compression type/level - if no compression gives a shorter output, that
        might be chosen; such chunks are kept as they are.

        Rewriting a pack invalidates every client's cached chunk index, so the next borg
        operation of each client will re-fetch the chunk index from the repository.

        This command needs free space in the repository for the rewritten pack files
        (roughly one pack file size while running).

        If the ``borg repo-compress`` process receives a SIGINT signal (Ctrl-C), it stops
        at the next pack boundary, leaving the repository and its chunk index in a
        consistent state; running it again later processes the remaining packs.

        Both ``--progress`` and ``--stats`` are recommended when ``borg repo-compress``
        is used interactively.

        You do **not** need to run ``borg compact`` after ``borg repo-compress``.
        """
        )
        subparser = ArgumentParser(
            parents=[common_parser], description=self.do_repo_compress.__doc__, epilog=repo_compress_epilog
        )
        subparsers.add_subcommand("repo-compress", subparser, help=self.do_repo_compress.__doc__)

        subparser.add_argument(
            "-C",
            "--compression",
            metavar="COMPRESSION",
            dest="compression",
            type=CompressionSpec,
            default=CompressionSpec("lz4"),
            action=Highlander,
            help='select compression algorithm, see the output of the "borg help compression" command for details.',
        )

        subparser.add_argument("-s", "--stats", dest="stats", action="store_true", help="print statistics")

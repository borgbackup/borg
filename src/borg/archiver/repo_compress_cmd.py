import argparse
from collections import defaultdict

from ._common import with_repository, Highlander
from ..constants import *  # NOQA
from ..compress import CompressionSpec, ObfuscateSize, Auto, COMPRESSOR_TABLE
from ..hashindex import ChunkIndex
from ..helpers import sig_int, ProgressIndicatorPercent, Error
from ..repository import Repository
from ..remote import RemoteRepository
from ..manifest import Manifest

from ..logger import create_logger

logger = create_logger()


def find_chunks(repository, repo_objs, cache, stats, ctype, clevel, olevel):
    """find and flag chunks that need processing (usually: recompression)."""
    compr_keys = stats["compr_keys"] = set()
    compr_wanted = ctype, clevel, olevel
    recompress_count = 0
    for id, cie in cache.chunks.iteritems():
        chunk_no_data = repository.get(id, read_data=False)
        meta = repo_objs.parse_meta(id, chunk_no_data, ro_type=ROBJ_DONTCARE)
        compr_found = meta["ctype"], meta["clevel"], meta.get("olevel", -1)
        if compr_found != compr_wanted:
            flags_compress = cie.flags | ChunkIndex.F_COMPRESS
            cache.chunks[id] = cie._replace(flags=flags_compress)
            recompress_count += 1
        compr_keys.add(compr_found)
        stats[compr_found] += 1
        stats["checked_count"] += 1
    return recompress_count


def process_chunks(repository, repo_objs, stats, recompress_ids, olevel):
    """process some chunks (usually: recompress)"""
    compr_keys = stats["compr_keys"]
    if compr_keys == 0:  # work around defaultdict(int)
        compr_keys = stats["compr_keys"] = set()
    for id, chunk in zip(recompress_ids, repository.get_many(recompress_ids, read_data=True)):
        old_size = len(chunk)
        stats["old_size"] += old_size
        meta, data = repo_objs.parse(id, chunk, ro_type=ROBJ_DONTCARE)
        ro_type = meta.pop("type", None)
        compr_old = meta["ctype"], meta["clevel"], meta.get("olevel", -1)
        if olevel == -1:
            # if the chunk was obfuscated, but should not be in future, remove related metadata
            meta.pop("olevel", None)
            meta.pop("psize", None)
        chunk = repo_objs.format(id, meta, data, ro_type=ro_type)
        compr_done = meta["ctype"], meta["clevel"], meta.get("olevel", -1)
        if compr_done != compr_old:
            # we actually changed something
            repository.put(id, chunk, wait=False)
            repository.async_response(wait=False)
            stats["new_size"] += len(chunk)
            compr_keys.add(compr_done)
            stats[compr_done] += 1
            stats["recompressed_count"] += 1
        else:
            # It might be that the old chunk used compression none or lz4 (for whatever reason,
            # including the old compressor being a DecidingCompressor) AND we used a
            # DecidingCompressor now, which did NOT compress like we wanted, but decided
            # to use the same compression (and obfuscation) we already had.
            # In this case, we just keep the old chunk and do not rewrite it -
            # This is important to avoid rewriting such chunks **again and again**.
            stats["new_size"] += old_size
            compr_keys.add(compr_old)
            stats[compr_old] += 1
            stats["kept_count"] += 1


def format_compression_spec(ctype, clevel, olevel):
    obfuscation = "" if olevel == -1 else f"obfuscate,{olevel},"
    for cname, cls in COMPRESSOR_TABLE.items():
        if cls.ID == ctype:
            cname = f"{cname}"
            break
    else:
        cname = f"{ctype}"
    clevel = f",{clevel}" if clevel != 255 else ""
    return obfuscation + cname + clevel


class RepoCompressMixIn:
    @with_repository(cache=True, manifest=True, compatibility=(Manifest.Operation.CHECK,))
    def do_repo_compress(self, args, repository, manifest, cache):
        """Repository (re-)compression"""

        def get_csettings(c):
            if isinstance(c, Auto):
                return get_csettings(c.compressor)
            if isinstance(c, ObfuscateSize):
                ctype, clevel, _ = get_csettings(c.compressor)
                olevel = c.level
                return ctype, clevel, olevel
            ctype, clevel, olevel = c.ID, c.level, -1
            return ctype, clevel, olevel

        if not isinstance(repository, (Repository, RemoteRepository)):
            raise Error("repo-compress not supported for legacy repositories.")

        repo_objs = manifest.repo_objs
        ctype, clevel, olevel = get_csettings(repo_objs.compressor)  # desired compression set by --compression

        stats_find = defaultdict(int)
        stats_process = defaultdict(int)
        recompress_candidate_count = find_chunks(repository, repo_objs, cache, stats_find, ctype, clevel, olevel)

        pi = ProgressIndicatorPercent(
            total=recompress_candidate_count,
            msg="Recompressing %3.1f%%",
            step=0.1,
            msgid="repo_compress.process_chunks",
        )
        for id, cie in cache.chunks.iteritems():
            if sig_int and sig_int.action_done():
                break
            if cie.flags & ChunkIndex.F_COMPRESS:
                process_chunks(repository, repo_objs, stats_process, [id], olevel)
            pi.show()
        pi.finish()
        if sig_int:
            # Ctrl-C / SIGINT: do not commit
            raise Error("Got Ctrl-C / SIGINT.")
        else:
            while repository.async_response(wait=True) is not None:
                pass
        if args.stats:
            print()
            print("Recompression stats:")
            print(f"Size: previously {stats_process['old_size']} -> now {stats_process['new_size']} bytes.")
            print(
                f"Change: "
                f"{stats_process['new_size'] - stats_process['old_size']} bytes == "
                f"{100.0 * stats_process['new_size'] / stats_process['old_size']:3.2f}%"
            )
            print("Found chunks stats (before processing):")
            for ck in stats_find["compr_keys"]:
                pretty_ck = format_compression_spec(*ck)
                print(f"{pretty_ck}: {stats_find[ck]}")
            print(f"Total: {stats_find['checked_count']}")

            print(f"Candidates for recompression: {recompress_candidate_count}")

            print("Processed chunks stats (after processing):")
            for ck in stats_process["compr_keys"]:
                pretty_ck = format_compression_spec(*ck)
                print(f"{pretty_ck}: {stats_process[ck]}")
            print(f"Recompressed and rewritten: {stats_process['recompressed_count']}")
            print(f"Kept as is: {stats_process['kept_count']}")
            print(f"Total: {stats_process['recompressed_count'] + stats_process['kept_count']}")

    def build_parser_repo_compress(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        repo_compress_epilog = process_epilog(
            """
        Repository (re-)compression (and/or re-obfuscation).

        Reads all chunks in the repository and recompresses them if they are not already
        using the compression type/level and obfuscation level given via ``--compression``.

        If the outcome of the chunk processing indicates a change in compression
        type/level or obfuscation level, the processed chunk is written to the repository.
        Please note that the outcome might not always be the desired compression
        type/level - if no compression gives a shorter output, that might be chosen.

        Please note that this command can not work in low (or zero) free disk space
        conditions.

        If the ``borg repo-compress`` process receives a SIGINT signal (Ctrl-C), the repo
        will be committed and compacted and borg will terminate cleanly afterwards.

        Both ``--progress`` and ``--stats`` are recommended when ``borg repo-compress``
        is used interactively.

        You do **not** need to run ``borg compact`` after ``borg repo-compress``.
        """
        )
        subparser = subparsers.add_parser(
            "repo-compress",
            parents=[common_parser],
            add_help=False,
            description=self.do_repo_compress.__doc__,
            epilog=repo_compress_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help=self.do_repo_compress.__doc__,
        )
        subparser.set_defaults(func=self.do_repo_compress)

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

        subparser.add_argument("-s", "--stats", dest="stats", action="store_true", help="print statistics")

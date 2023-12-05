import argparse
from collections import defaultdict

from ._common import with_repository, Highlander
from ..constants import *  # NOQA
from ..compress import CompressionSpec, ObfuscateSize, Auto, COMPRESSOR_TABLE
from ..helpers import sig_int, ProgressIndicatorPercent

from ..manifest import Manifest

from ..logger import create_logger

logger = create_logger()


def find_chunks(repository, repo_objs, stats, ctype, clevel, olevel):
    """find chunks that need processing (usually: recompression)."""
    # to do it this way is maybe not obvious, thus keeping the essential design criteria here:
    # - determine the chunk ids at one point in time (== do a **full** scan in one go) **before**
    # writing to the repo (and especially before doing a compaction, which moves segment files around)
    # - get the chunk ids in **on-disk order** (so we can efficiently compact while processing the chunks)
    # - only put the ids into the list that actually need recompression (keeps it a little shorter in some cases)
    recompress_ids = []
    compr_keys = stats["compr_keys"] = set()
    compr_wanted = ctype, clevel, olevel
    state = None
    chunks_count = len(repository)
    chunks_limit = min(1000, max(100, chunks_count // 1000))
    pi = ProgressIndicatorPercent(
        total=chunks_count,
        msg="Searching for recompression candidates %3.1f%%",
        step=0.1,
        msgid="rcompress.find_chunks",
    )
    while True:
        chunk_ids, state = repository.scan(limit=chunks_limit, state=state)
        if not chunk_ids:
            break
        for id, chunk_no_data in zip(chunk_ids, repository.get_many(chunk_ids, read_data=False)):
            meta = repo_objs.parse_meta(id, chunk_no_data, ro_type=ROBJ_DONTCARE)
            compr_found = meta["ctype"], meta["clevel"], meta.get("olevel", -1)
            if compr_found != compr_wanted:
                recompress_ids.append(id)
            compr_keys.add(compr_found)
            stats[compr_found] += 1
            stats["checked_count"] += 1
            pi.show(increase=1)
    pi.finish()
    return recompress_ids


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


class RCompressMixIn:
    @with_repository(cache=False, manifest=True, exclusive=True, compatibility=(Manifest.Operation.CHECK,))
    def do_rcompress(self, args, repository, manifest):
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

        repo_objs = manifest.repo_objs
        ctype, clevel, olevel = get_csettings(repo_objs.compressor)  # desired compression set by --compression

        def checkpoint_func():
            while repository.async_response(wait=True) is not None:
                pass
            repository.commit(compact=True)

        stats_find = defaultdict(int)
        stats_process = defaultdict(int)
        recompress_ids = find_chunks(repository, repo_objs, stats_find, ctype, clevel, olevel)
        recompress_candidate_count = len(recompress_ids)
        chunks_limit = min(1000, max(100, recompress_candidate_count // 1000))
        uncommitted_chunks = 0

        # start a new transaction
        data = repository.get(Manifest.MANIFEST_ID)
        repository.put(Manifest.MANIFEST_ID, data)
        uncommitted_chunks += 1

        pi = ProgressIndicatorPercent(
            total=len(recompress_ids), msg="Recompressing %3.1f%%", step=0.1, msgid="rcompress.process_chunks"
        )
        while recompress_ids:
            if sig_int and sig_int.action_done():
                break
            ids, recompress_ids = recompress_ids[:chunks_limit], recompress_ids[chunks_limit:]
            process_chunks(repository, repo_objs, stats_process, ids, olevel)
            pi.show(increase=len(ids))
            checkpointed = self.maybe_checkpoint(
                checkpoint_func=checkpoint_func, checkpoint_interval=args.checkpoint_interval
            )
            uncommitted_chunks = 0 if checkpointed else (uncommitted_chunks + len(ids))
        pi.finish()
        if sig_int:
            # Ctrl-C / SIGINT: do not checkpoint (commit) again, we already have a checkpoint in this case.
            self.print_error("Got Ctrl-C / SIGINT.")
        elif uncommitted_chunks > 0:
            checkpoint_func()
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

    def build_parser_rcompress(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        rcompress_epilog = process_epilog(
            """
        Repository (re-)compression (and/or re-obfuscation).

        Reads all chunks in the repository (in on-disk order, this is important for
        compaction) and recompresses them if they are not already using the compression
        type/level and obfuscation level given via ``--compression``.

        If the outcome of the chunk processing indicates a change in compression
        type/level or obfuscation level, the processed chunk is written to the repository.
        Please note that the outcome might not always be the desired compression
        type/level - if no compression gives a shorter output, that might be chosen.

        Every ``--checkpoint-interval``, progress is committed to the repository and
        the repository is compacted (this is to keep temporary repo space usage in bounds).
        A lower checkpoint interval means lower temporary repo space usage, but also
        slower progress due to higher overhead (and vice versa).

        Please note that this command can not work in low (or zero) free disk space
        conditions.

        If the ``borg rcompress`` process receives a SIGINT signal (Ctrl-C), the repo
        will be committed and compacted and borg will terminate cleanly afterwards.

        Both ``--progress`` and ``--stats`` are recommended when ``borg rcompress``
        is used interactively.

        You do **not** need to run ``borg compact`` after ``borg rcompress``.
        """
        )
        subparser = subparsers.add_parser(
            "rcompress",
            parents=[common_parser],
            add_help=False,
            description=self.do_rcompress.__doc__,
            epilog=rcompress_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help=self.do_rcompress.__doc__,
        )
        subparser.set_defaults(func=self.do_rcompress)

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

        subparser.add_argument(
            "-c",
            "--checkpoint-interval",
            metavar="SECONDS",
            dest="checkpoint_interval",
            type=int,
            default=1800,
            action=Highlander,
            help="write checkpoint every SECONDS seconds (Default: 1800)",
        )

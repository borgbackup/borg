#!/usr/bin/env python3
"""
buzhash64 chunker evaluation harness.

Purpose
-------
Establish an *evidence baseline* for the current buzhash64 chunker (and buzhash32
for reference) so that any future change to buzhash64 can be judged against real
numbers instead of intuition.

It measures, for a given chunker config and corpus:

  * chunk-size distribution: count, mean, stddev, coefficient of variation (CV),
    and how many chunks were clamped at min_size / max_size,
  * deduplication ratio: unique-chunk-bytes / total-bytes (lower is better dedup),
  * throughput in MB/s,
  * shift resilience: re-chunk a mutated copy (bytes inserted/deleted at random
    offsets) and report what fraction of chunks (by content) survive. This is the
    property content-defined chunking exists for; size-distribution changes can
    help or hurt it, so we must watch it.

Corpora
-------
  --path FILE_OR_DIR   use real data (a dir is concatenated, file order sorted)
  --synthetic random:N        N bytes of os.urandom (incompressible, worst case)
  --synthetic lcg:N           N bytes of a cheap LCG stream (deterministic)
  --synthetic textish:N       N bytes of low-entropy, repetitive ascii-ish data

Examples
--------
  python scripts/chunker_bench.py --synthetic lcg:67108864
  python scripts/chunker_bench.py --path /usr/lib --max-bytes 268435456
  python scripts/chunker_bench.py --path ./some.tar --algo buzhash64 buzhash

This script imports the *compiled* borg chunkers, so build borg first.
It does not modify borg in any way; it is a measurement tool only.
"""

import argparse
import hashlib
import os
import random
import statistics
import sys
import time
from io import BytesIO

from borg.chunkers import get_chunker
from borg.constants import CHUNK_MIN_EXP, CHUNK_MAX_EXP, HASH_MASK_BITS, HASH_WINDOW_SIZE


def gen_synthetic(spec):
    kind, _, rest = spec.partition(":")
    if kind == "versioned":
        # parsed below from the full spec (it has two numeric fields)
        n = 0
    else:
        n = int(rest)
    if kind == "random":
        return os.urandom(n)
    if kind == "lcg":
        a = bytearray(n)
        x = 1
        for i in range(n):
            x = (x * 1103515245 + 12345) & 0x7FFFFFFF
            a[i] = x & 0xFF
        return bytes(a)
    if kind == "versioned":
        # "versioned:N[:E]" -> corpus = v1 ++ v2, where v2 is v1 with E scattered single-byte
        # inserts/deletes (default E=64). Models backing up a slightly-changed large file: the
        # dedup ratio shows how much of v2 is re-deduplicated against v1, which is exactly what
        # shift-resilient chunk boundaries (and normalized chunking) affect.
        parts = spec.split(":")
        n = int(parts[1])
        edits = int(parts[2]) if len(parts) > 2 else 64
        v1 = os.urandom(n)
        v2 = mutate(v1, edits, random.Random(42))
        corpus = v1 + v2
        del v1, v2
        return corpus
    if kind == "textish":
        # low-entropy, repetitive: stresses buzhash window cancellation and
        # tends to produce many min/max-clamped chunks.
        words = [
            b"the ",
            b"quick ",
            b"brown ",
            b"fox ",
            b"jumps ",
            b"over ",
            b"lazy ",
            b"dog ",
            b"lorem ",
            b"ipsum ",
            b"dolor ",
            b"sit ",
        ]
        rng = random.Random(1234)
        out = bytearray()
        while len(out) < n:
            out += rng.choice(words)
        return bytes(out[:n])
    raise SystemExit(f"unknown synthetic spec: {spec!r}")


def load_path(path, max_bytes):
    if os.path.isfile(path):
        with open(path, "rb") as f:
            return f.read(max_bytes if max_bytes else -1)
    buf = bytearray()
    for root, _, files in os.walk(path):
        for name in sorted(files):
            fp = os.path.join(root, name)
            try:
                with open(fp, "rb") as f:
                    buf += f.read()
            except OSError:
                continue
            if max_bytes and len(buf) >= max_bytes:
                return bytes(buf[:max_bytes])
    return bytes(buf)


def chunk_stats(algo, data, min_exp, max_exp, mask_bits, win, nc_level=0, normal_size=0):
    """Chunk data and return (sizes, hashes, chunking_time) without materializing chunk bytes.

    Memory-lean: only a size (int) and a sha256 digest are kept per chunk, so very large
    corpora can be processed. key=None -> zero key (deterministic)."""
    params = [min_exp, max_exp, mask_bits, win]
    kw = dict(key=None, sparse=False)
    if algo == "buzhash64":
        params.append(nc_level)  # nc_level is a positional buzhash64 param
        kw["normal_size"] = normal_size
    chunker = get_chunker(algo, *params, **kw)
    sizes = []
    hashes = []
    for c in chunker.chunkify(BytesIO(data)):
        if c.data is None:  # hole / all-zero alloc chunk
            n = c.meta["size"]
            sizes.append(n)
            hashes.append(hashlib.sha256(b"\0" * n).digest())
        else:
            b = c.data
            sizes.append(len(b))
            hashes.append(hashlib.sha256(b).digest())
    return sizes, hashes, getattr(chunker, "chunking_time", 0.0)


def mutate(data, n_edits, rng):
    """Insert and delete a few single bytes at random offsets (boundary shift test)."""
    b = bytearray(data)
    for _ in range(n_edits):
        pos = rng.randrange(len(b))
        if rng.random() < 0.5:
            b.insert(pos, rng.randrange(256))
        else:
            del b[pos]
    return bytes(b)


def analyze(algo, data, params, shift_edits, rng, nc_level=0, normal_size=0):
    min_exp, max_exp, mask_bits, win = params
    min_size, max_size = 1 << min_exp, 1 << max_exp

    t0 = time.monotonic()
    sizes, hashes, internal_t = chunk_stats(algo, data, *params, nc_level=nc_level, normal_size=normal_size)
    wall = time.monotonic() - t0

    # drop last chunk for distribution stats (it is a remainder, often < min)
    dist_sizes = sizes[:-1] if len(sizes) > 1 else sizes
    total = sum(sizes)

    mean = statistics.fmean(dist_sizes) if dist_sizes else 0
    stdev = statistics.pstdev(dist_sizes) if len(dist_sizes) > 1 else 0.0
    cv = (stdev / mean) if mean else 0.0
    min_clamped = sum(1 for s in dist_sizes if s == min_size)
    max_clamped = sum(1 for s in dist_sizes if s == max_size)

    # dedup ratio: unique chunk content / total (lower = more dedup)
    seen = set()
    unique_bytes = 0
    for h, n in zip(hashes, sizes):
        if h not in seen:
            seen.add(h)
            unique_bytes += n
    dedup_ratio = unique_bytes / total if total else 0.0

    # shift resilience: re-chunk a mutated copy, fraction of chunks (by content) that survive
    shift_survival = None
    if shift_edits:
        mutated = mutate(data, shift_edits, rng)
        _, mhashes, _ = chunk_stats(algo, mutated, *params, nc_level=nc_level, normal_size=normal_size)
        del mutated
        orig_set = set(hashes)
        survived = sum(1 for h in mhashes if h in orig_set)
        shift_survival = survived / len(mhashes) if mhashes else 0.0

    mb = total / (1024 * 1024)
    secs = internal_t or wall
    label = algo if not nc_level else f"{algo}/nc{nc_level}"
    return {
        "algo": label,
        "count": len(sizes),
        "total_mb": mb,
        "mean": mean,
        "stdev": stdev,
        "cv": cv,
        "min_clamped": min_clamped,
        "max_clamped": max_clamped,
        "min_obs": min(dist_sizes) if dist_sizes else 0,
        "max_obs": max(dist_sizes) if dist_sizes else 0,
        "dedup_ratio": dedup_ratio,
        "throughput_mbps": mb / secs if secs else float("inf"),
        "shift_survival": shift_survival,
    }


def fmt(r):
    line = (
        f"{r['algo']:>13}  "
        f"n={r['count']:>6}  "
        f"mean={r['mean']/1024:8.1f}K  "
        f"stdev={r['stdev']/1024:8.1f}K  "
        f"CV={r['cv']:5.3f}  "
        f"min/max-clamp={r['min_clamped']:>4}/{r['max_clamped']:<4}  "
        f"dedup={r['dedup_ratio']:6.4f}  "
        f"{r['throughput_mbps']:7.1f} MB/s"
    )
    if r["shift_survival"] is not None:
        line += f"  shift-survive={r['shift_survival']:6.4f}"
    return line


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--path", help="file or directory to use as corpus")
    src.add_argument("--synthetic", help="random:N | lcg:N | textish:N")
    ap.add_argument("--max-bytes", type=int, default=0, help="cap corpus size (0 = no cap)")
    ap.add_argument(
        "--algo",
        nargs="+",
        default=["buzhash64", "buzhash"],
        help="chunker algos to compare (default: buzhash64 buzhash)",
    )
    ap.add_argument("--min-exp", type=int, default=CHUNK_MIN_EXP)
    ap.add_argument("--max-exp", type=int, default=CHUNK_MAX_EXP)
    ap.add_argument("--mask-bits", type=int, default=HASH_MASK_BITS)
    ap.add_argument("--window", type=int, default=HASH_WINDOW_SIZE)
    ap.add_argument(
        "--nc-level",
        type=int,
        default=2,
        help="normalized chunking level for buzhash64; runs nc=0 AND this level (0 to disable)",
    )
    ap.add_argument(
        "--normal-size",
        type=int,
        default=0,
        help="explicit NC transition size in bytes (0 = auto = min_size + 2**mask_bits)",
    )
    ap.add_argument(
        "--shift-edits", type=int, default=8, help="number of random insert/delete edits for shift test (0 to skip)"
    )
    ap.add_argument("--repeat", type=int, default=1, help="repeat runs (throughput stability)")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    if args.synthetic:
        data = gen_synthetic(args.synthetic)
        corpus_desc = args.synthetic
    else:
        data = load_path(args.path, args.max_bytes)
        corpus_desc = args.path
    if args.max_bytes:
        data = data[: args.max_bytes]

    params = (args.min_exp, args.max_exp, args.mask_bits, args.window)

    print(f"corpus: {corpus_desc}  size: {len(data)/(1024*1024):.1f} MiB")
    print(
        f"params: min_exp={params[0]} max_exp={params[1]} mask_bits={params[2]} "
        f"window={params[3]}  (target ~{(1<<params[2])/(1024*1024):.2f} MiB)"
    )
    print(f"shift test: {args.shift_edits} edits   repeats: {args.repeat}")
    print("-" * 118)

    # build (algo, nc_level) variants; for buzhash64 also run the requested NC level
    variants = []
    for algo in args.algo:
        variants.append((algo, 0))
        if algo == "buzhash64" and args.nc_level > 0:
            variants.append((algo, args.nc_level))

    for algo, nc in variants:
        best_tput = 0.0
        last = None
        for _ in range(args.repeat):
            r = analyze(
                algo,
                data,
                params,
                args.shift_edits,
                random.Random(args.seed),
                nc_level=nc,
                normal_size=args.normal_size,
            )
            best_tput = max(best_tput, r["throughput_mbps"])
            last = r
        last["throughput_mbps"] = best_tput  # report best (least-noisy) throughput
        print(fmt(last))

    print("-" * 118)
    print(
        "notes: dedup<1.0 only if corpus has duplicate content; CV lower = tighter "
        "size distribution; shift-survive higher = better."
    )


if __name__ == "__main__":
    sys.exit(main())

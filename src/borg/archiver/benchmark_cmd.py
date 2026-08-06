from contextlib import contextmanager
import json
import logging
import os
import tempfile
import time

from ..constants import *  # NOQA
from ..helpers import format_file_size, CompressionSpec
from ..helpers import sizeof_fmt_iec
from ..helpers import FilesystemDirSpec
from ..helpers import json_print
from ..helpers import msgpack
from ..helpers import get_reset_ec
from ..helpers.argparsing import ArgumentParser
from ..item import Item
from ..platform import SyncFile


class BenchmarkMixIn:
    def do_benchmark_crud(self, args):
        """Benchmark Create, Read, Update, Delete for archives."""

        def measurement_run(repo, path):
            # Suppress "Done. Run borg compact..." warnings from internal do_delete() calls —
            # they clutter benchmark output and are irrelevant here (repo is temporary).
            archiver_logger = logging.getLogger("borg.archiver")
            original_level = archiver_logger.level
            archiver_logger.setLevel(logging.ERROR)
            try:
                compression = "--compression=none"
                # measure create perf (without files cache to always have it chunking)
                t_start = time.monotonic()
                rc = get_reset_ec(
                    self.do_create(
                        self.parse_args(
                            [
                                f"--repo={repo}",
                                "create",
                                compression,
                                "--files-cache=disabled",
                                "borg-benchmark-crud1",
                                path,
                            ]
                        )
                    )
                )
                t_end = time.monotonic()
                dt_create = t_end - t_start
                assert rc == 0
                # now build files cache
                rc1 = get_reset_ec(
                    self.do_create(
                        self.parse_args([f"--repo={repo}", "create", compression, "borg-benchmark-crud2", path])
                    )
                )
                rc2 = get_reset_ec(
                    self.do_delete(self.parse_args([f"--repo={repo}", "delete", "-a", "borg-benchmark-crud2"]))
                )
                assert rc1 == rc2 == 0
                # measure a no-change update (archive1 is still present)
                t_start = time.monotonic()
                rc1 = get_reset_ec(
                    self.do_create(
                        self.parse_args([f"--repo={repo}", "create", compression, "borg-benchmark-crud3", path])
                    )
                )
                t_end = time.monotonic()
                dt_update = t_end - t_start
                rc2 = get_reset_ec(
                    self.do_delete(self.parse_args([f"--repo={repo}", "delete", "-a", "borg-benchmark-crud3"]))
                )
                assert rc1 == rc2 == 0
                # measure extraction (dry-run: without writing result to disk)
                t_start = time.monotonic()
                rc = get_reset_ec(
                    self.do_extract(self.parse_args([f"--repo={repo}", "extract", "borg-benchmark-crud1", "--dry-run"]))
                )
                t_end = time.monotonic()
                dt_extract = t_end - t_start
                assert rc == 0
                # measure archive deletion (of LAST present archive with the data)
                t_start = time.monotonic()
                rc = get_reset_ec(
                    self.do_delete(self.parse_args([f"--repo={repo}", "delete", "-a", "borg-benchmark-crud1"]))
                )
                t_end = time.monotonic()
                dt_delete = t_end - t_start
                assert rc == 0
                return dt_create, dt_update, dt_extract, dt_delete
            finally:
                archiver_logger.setLevel(original_level)

        @contextmanager
        def test_files(path, count, size, random):
            with tempfile.TemporaryDirectory(prefix="borg-test-data-", dir=path) as path:
                z_buff = None if random else memoryview(zeros)[:size] if size <= len(zeros) else b"\0" * size
                for i in range(count):
                    fname = os.path.join(path, "file_%d" % i)
                    data = z_buff if not random else os.urandom(size)
                    with SyncFile(fname, binary=True) as fd:  # used for posix_fadvise's sake
                        fd.write(data)
                yield path

        if "_BORG_BENCHMARK_CRUD_TEST" in os.environ:
            tests = [("Z-TEST", 1, 1, False), ("R-TEST", 1, 1, True)]
        else:
            tests = [
                ("Z-BIG", 10, 100000000, False),
                ("R-BIG", 10, 100000000, True),
                ("Z-MEDIUM", 1000, 1000000, False),
                ("R-MEDIUM", 1000, 1000000, True),
                ("Z-SMALL", 10000, 10000, False),
                ("R-SMALL", 10000, 10000, True),
            ]

        for msg, count, size, random in tests:
            with test_files(args.path, count, size, random) as path:
                dt_create, dt_update, dt_extract, dt_delete = measurement_run(args.location.canonical_path(), path)
            total_size = count * size
            if args.json_lines:
                for cmd_letter, cmd_name, dt in [
                    ("C", "create1", dt_create),
                    ("R", "extract", dt_extract),
                    ("U", "create2", dt_update),
                    ("D", "delete", dt_delete),
                ]:
                    print(
                        json.dumps(
                            {
                                "id": f"{cmd_letter}-{msg}",
                                "command": cmd_name,
                                "sample": msg,
                                "sample_count": count,
                                "sample_size": size,
                                "sample_random": random,
                                "time": dt,
                                "io": int(total_size / dt),
                            },
                            sort_keys=True,
                        )
                    )
            else:
                total_size_MB = total_size / 1e06
                file_size_formatted = format_file_size(size)
                content = "random" if random else "all-zero"
                fmt = "%s-%-10s %9.2f MB/s (%d * %s %s files: %.2fs)"
                print(fmt % ("C", msg, total_size_MB / dt_create, count, file_size_formatted, content, dt_create))
                print(fmt % ("R", msg, total_size_MB / dt_extract, count, file_size_formatted, content, dt_extract))
                print(fmt % ("U", msg, total_size_MB / dt_update, count, file_size_formatted, content, dt_update))
                print(fmt % ("D", msg, total_size_MB / dt_delete, count, file_size_formatted, content, dt_delete))

    def do_benchmark_cpu(self, args):
        """Benchmark CPU-bound operations."""
        from timeit import timeit

        result = {} if args.json else None

        # no section selected means: run them all
        sections = ("chunking", "hashing", "encryption", "compression", "msgpack")
        selected = {name for name in sections if getattr(args, name)}
        if not selected:
            selected = set(sections)

        KIB, MIB, GIB = 1024, 1024 * 1024, 1024 * 1024 * 1024

        is_test = "_BORG_BENCHMARK_CPU_TEST" in os.environ
        # Use minimal data and one iteration in test mode to keep CI fast.
        chunk_data_size = 128 * KIB if is_test else 8 * MIB
        number_default = 1 if is_test else GIB // chunk_data_size

        # Buffer sizes matter where an algorithm switches to multiple threads:
        # blake3 and zstd do so above a threshold, so a size below it, one the
        # size of a typical borg chunk and one the size of a borg pack behave
        # quite differently. Every row processes the same total either way, so
        # the throughput column stays comparable across sizes.
        # powers of two, so every row processes exactly 1 GiB (or 10 MiB for the
        # compressors) rather than an awkward fraction of it
        SMALL, CHUNK, PACK = ("128kiB", 128 * KIB), ("2MiB", 2 * MIB), ("64MiB", 64 * MIB)
        if is_test:
            hash_sizes = comp_sizes = one_size = [SMALL]
            hash_total = comp_total = SMALL[1]
        else:
            hash_sizes = [SMALL, CHUNK, PACK]
            comp_sizes = [SMALL, CHUNK]
            one_size = [CHUNK]  # for algorithms where the buffer size does not change behaviour
            hash_total = GIB
            # compressible data means the codecs actually work, so the slow ones
            # (lzma, high zstd levels) need fewer bytes to stay bearable
            comp_total = 10 * MIB

        buffers = {}

        def buffer(nbytes):
            """Random data of the given size, made once and reused."""
            if nbytes not in buffers:
                buffers[nbytes] = os.urandom(nbytes)
            return buffers[nbytes]

        compressible = {}

        def compressible_buffer(nbytes):
            """Deterministic, text-like, compressible data of the given size.

            Random bytes are the worst possible input for a compression benchmark:
            nothing compresses, so every codec takes its incompressible fast path,
            the levels barely differ, and zstd's multi-threading looks like a large
            loss when on real data it is a 1.7 .. 3x win. This is a word soup built
            from a fixed seed - identical on every machine and every run, so numbers
            stay comparable - which compresses about 4x at zstd,3.

            The xorshift is written out rather than using random.Random so that the
            bytes do not depend on the Python version's PRNG internals.
            """
            if nbytes not in compressible:
                words = (
                    b"backup archive chunk repository compress encrypt index cache manifest "
                    b"the and of a to in is it for with data borg file path size key id hash "
                    b"item repo object segment directory user group mtime mode owner content"
                ).split()
                out = bytearray()
                state = 0x2545F4914F6CDD1D
                mask = 0xFFFFFFFFFFFFFFFF
                while len(out) < nbytes:
                    state ^= (state << 13) & mask
                    state ^= state >> 7
                    state ^= (state << 17) & mask
                    out += words[state % len(words)]
                    out += b"\n" if state & 0xF == 0 else b" "
                compressible[nbytes] = bytes(out[:nbytes])
            return compressible[nbytes]

        def data_size_str(size):
            """The benchmark's own data volumes, always in IEC units.

            These are fixed constants of the benchmark rather than user data, so
            they do not follow BORG_UNITS - that would make two people's output
            incomparable and would render binary sizes as awkward decimals
            (1 GiB as "1.07 GB").
            """
            return sizeof_fmt_iec(size, suffix="B", sep=" ", precision=2)

        def throughput(size, dt):
            """Rate as MB/s, always - so numbers stay comparable between rows."""
            return f"{size / dt / 1e6:>8.1f} MB/s"

        def report(section, spec, size, dt, width, **extra):
            if args.json:
                result[section].append({"size": size, "time": dt, **extra})
            else:
                print(f"{spec:<{width}} {data_size_str(size):<11} {dt:.3f}s  {throughput(size, dt)}")

        def section_header(section, title):
            if args.json:
                result[section] = []
            else:
                print(f"{title} ".ljust(64, "="))

        random_10M = buffer(chunk_data_size)
        key_256 = os.urandom(32)
        key_128 = os.urandom(16)
        key_96 = os.urandom(12)

        if "chunking" in selected:
            import io
            from ..chunkers import get_chunker, release_chunk_data  # noqa

            section_header("chunkers", "Chunkers")
            size = chunk_data_size * number_default

            def chunkit(ch):
                with io.BytesIO(random_10M) as data_file:
                    for chunk in ch.chunkify(fd=data_file):
                        release_chunk_data(chunk.data)

            for spec, setup, func, vars in [
                ("fixed,1048576", "ch = get_chunker('fixed', 1048576, sparse=False)", "chunkit(ch)", locals()),
                # fastcdc (window-less keyed gear hash); gear table creation is slow, keep it in setup
                (
                    "fastcdc,19,23,21,2",
                    "ch = get_chunker('fastcdc', 19, 23, 21, 2, sparse=False)",
                    "chunkit(ch)",
                    locals(),
                ),
                # note: the buzhash64 chunker creation is rather slow, so we must keep it in setup
                (
                    "buzhash64,19,23,21,4095,2",
                    "ch = get_chunker('buzhash64', 19, 23, 21, 4095, 2, sparse=False)",
                    "chunkit(ch)",
                    locals(),
                ),
                (
                    "buzhash,19,23,21,4095",
                    "ch = get_chunker('buzhash', 19, 23, 21, 4095, sparse=False)",
                    "chunkit(ch)",
                    locals(),
                ),
                # toeplitz-aes (UHF-then-PRF, tabulated Toeplitz hash); table creation in setup
                (
                    "toeplitz-aes,19,23,21,2",
                    "ch = get_chunker('toeplitz-aes', 19, 23, 21, 2, sparse=False)",
                    "chunkit(ch)",
                    locals(),
                ),
                # rabin-aes (UHF-then-PRF); polynomial sampling / table creation is slow, keep it in setup
                (
                    "rabin-aes,19,23,21,2",
                    "ch = get_chunker('rabin-aes', 19, 23, 21, 2, sparse=False)",
                    "chunkit(ch)",
                    locals(),
                ),
                # goldilocks-aes (UHF-then-PRF, prime-field comparison chunker); table creation in setup
                (
                    "goldilocks-aes,19,23,21,2",
                    "ch = get_chunker('goldilocks-aes', 19, 23, 21, 2, sparse=False)",
                    "chunkit(ch)",
                    locals(),
                ),
            ]:
                dt = timeit(func, setup, number=number_default, globals=vars)
                algo, _, algo_params = spec.partition(",")
                report("chunkers", spec, size, dt, 26, algo=algo, algo_params=algo_params)

        if "hashing" in selected:
            from ..crypto.low_level import hmac_sha256, blake2b_256
            from ..crypto.key import get_blake3_mt_threshold
            import blake3

            def blake3_hash(d):
                # mirror what borg does per chunk (see AESKeyBase.id_hash): below the
                # threshold multi-threading costs more than it gains, so it is not used
                max_threads = blake3.blake3.AUTO if len(d) >= get_blake3_mt_threshold() else 1
                return blake3.blake3(d, key=key_256, max_threads=max_threads).digest()

            section_header("hashes", "Cryptographic hashes / MACs")
            # only blake3 uses multiple threads, and only above a size threshold,
            # so it is the one worth measuring at several buffer sizes.
            hashes_tests = [
                ("hmac-sha256", one_size, lambda d: hmac_sha256(key_256, d)),
                ("blake2b-256", one_size, lambda d: blake2b_256(key_256, d)),
                ("blake3", hash_sizes, blake3_hash),
            ]
            for spec, sizes, func in hashes_tests:
                for label, nbytes in sizes:
                    data = buffer(nbytes)
                    number = max(1, hash_total // nbytes)
                    dt = timeit(lambda: func(data), number=number)
                    report("hashes", f"{spec} ({label})", nbytes * number, dt, 26, algo=spec, buffer_size=nbytes)

        if "encryption" in selected:
            from ..crypto.low_level import AES256_CTR_BLAKE2b, AES256_CTR_HMAC_SHA256
            from ..crypto.low_level import AES256_OCB, CHACHA20_POLY1305

            section_header("encryption", "Encryption")
            size = chunk_data_size * number_default
            # AEAD modes first (what borg uses by default), then the legacy
            # encrypt-then-MAC ones
            tests = [
                (
                    "aes-256-ocb",
                    lambda: AES256_OCB(key_256, iv=key_96, header_len=1, aad_offset=1).encrypt(random_10M, header=b"X"),
                ),
                (
                    "chacha20-poly1305",
                    lambda: CHACHA20_POLY1305(key_256, iv=key_96, header_len=1, aad_offset=1).encrypt(
                        random_10M, header=b"X"
                    ),
                ),
                (
                    "aes-256-ctr-hmac-sha256",
                    lambda: AES256_CTR_HMAC_SHA256(key_256, key_256, iv=key_128, header_len=1, aad_offset=1).encrypt(
                        random_10M, header=b"X"
                    ),
                ),
                (
                    "aes-256-ctr-blake2b",
                    lambda: AES256_CTR_BLAKE2b(key_256 * 4, key_256, iv=key_128, header_len=1, aad_offset=1).encrypt(
                        random_10M, header=b"X"
                    ),
                ),
            ]
            for spec, func in tests:
                dt = timeit(func, number=number_default)
                report("encryption", spec, size, dt, 26, algo=spec)

        if "compression" in selected:
            section_header("compression", "Compression")
            if not args.json:
                sample = compressible_buffer(comp_sizes[-1][1])
                ratio = len(sample) / len(CompressionSpec("zstd,3").compressor.compress({}, sample)[1])
                print(f"(test data is compressible, {ratio:.1f}x at zstd,3)")
            # grouped by buffer size rather than by codec, so the codecs can be
            # compared against each other at a glance; chunk-sized first, as
            # that is what borg actually compresses
            for label, nbytes in reversed(comp_sizes):
                data = compressible_buffer(nbytes)
                number = max(3, comp_total // nbytes)  # a few reps even for the fast codecs
                for spec in [
                    "lz4",
                    "zstd,1",
                    "zstd,3",
                    "zstd,5",
                    "zstd,10",
                    "zstd,16",
                    "zstd,22",
                    "zlib,0",
                    "zlib,6",
                    "zlib,9",
                    "lzma,0",
                    "lzma,6",
                    "lzma,9",
                ]:
                    compressor = CompressionSpec(spec).compressor
                    dt = timeit(lambda: compressor.compress({}, data), number=number)
                    algo, _, algo_params = spec.partition(",")
                    report(
                        "compression",
                        f"{spec} ({label})",
                        nbytes * number,
                        dt,
                        20,
                        algo=algo,
                        algo_params=algo_params,
                        buffer_size=nbytes,
                    )

        if "msgpack" in selected:
            section_header("msgpack", "msgpack")
            item = Item(path="foo/bar/baz", mode=660, mtime=1234567)
            items = [item.as_dict()] * 1000
            count = 1000 * number_default
            spec = "msgpack"
            dt = timeit(lambda: msgpack.packb(items), number=number_default)
            if args.json:
                result["msgpack"].append({"algo": spec, "count": count, "time": dt})
            else:
                # this one packs items, not bytes, so it gets a rate in its own unit
                size = "%dk Items" % (count // 1000)
                print(f"{spec:<20} {size:<10} {dt:.3f}s  {count / dt / 1000:>8.1f} kItems/s")

        if args.json:
            json_print(result)

    def build_parser_benchmarks(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        benchmark_epilog = process_epilog("These commands do various benchmarks.")

        subparser = ArgumentParser(
            parents=[mid_common_parser], description="benchmark command", epilog=benchmark_epilog
        )
        subparsers.add_subcommand("benchmark", subparser, help="benchmark command")

        benchmark_parsers = subparser.add_subcommands(required=False, title="required arguments", metavar="<command>")

        bench_crud_epilog = process_epilog(
            """
        This command benchmarks borg CRUD (create, read, update, delete) operations.

        It creates input data below the given PATH and backs up this data into the given REPO.
        The REPO must already exist (it could be a fresh empty repo or an existing repo, the
        command will create / read / update / delete some archives named borg-benchmark-crud\\* there.

        Make sure you have free space there; you will need about 1 GB each (+ overhead).

        If your repository is encrypted and borg needs a passphrase to unlock the key, use::

            BORG_PASSPHRASE=mysecret borg benchmark crud REPO PATH

        Measurements are done with different input file sizes and counts.
        The file contents are very artificial (either all zero or all random),
        thus the measurement results do not necessarily reflect performance with real data.
        Also, due to the kind of content used, no compression is used in these benchmarks.

        C- == borg create (1st archive creation, no compression, do not use files cache)
              C-Z- == all-zero files. full dedup, this is primarily measuring reader/chunker/hasher.
              C-R- == random files. no dedup, measuring throughput through all processing stages.

        R- == borg extract (extract archive, dry-run, do everything, but do not write files to disk)
              R-Z- == all zero files. Measuring heavily duplicated files.
              R-R- == random files. No duplication here, measuring throughput through all processing
              stages, except writing to disk.

        U- == borg create (2nd archive creation of unchanged input files, measure files cache speed)
              The throughput value is kind of virtual here, it does not actually read the file.
              U-Z- == needs to check the 2 all-zero chunks' existence in the repo.
              U-R- == needs to check existence of a lot of different chunks in the repo.

        D- == borg delete archive (delete last remaining archive, measure deletion + compaction)
              D-Z- == few chunks to delete / few segments to compact/remove.
              D-R- == many chunks to delete / many segments to compact/remove.

        Please note that there might be quite some variance in these measurements.
        Try multiple measurements and having a otherwise idle machine (and network, if you use it).
        """
        )
        subparser = ArgumentParser(
            parents=[common_parser], description=self.do_benchmark_crud.__doc__, epilog=bench_crud_epilog
        )
        benchmark_parsers.add_subcommand(
            "crud", subparser, help="benchmarks Borg CRUD (create, extract, update, delete)."
        )

        subparser.add_argument(
            "path", metavar="PATH", type=FilesystemDirSpec, help="path where to create benchmark input data"
        )
        subparser.add_argument("--json-lines", action="store_true", help="Format output as JSON Lines.")

        bench_cpu_epilog = process_epilog(
            """
        This command benchmarks miscellaneous CPU-bound Borg operations.

        It creates input data in memory, runs the operation and then displays throughput.
        To reduce outside influence on the timings, please make sure to run this with:

        - an otherwise as idle as possible machine
        - enough free memory so there will be no slow down due to paging activity

        By default all benchmarks run. Give one or more of --chunking, --hashing,
        --encryption, --compression, --msgpack to run only those.

        Some algorithms use multiple threads only above a size threshold, so the
        hashes and compressors are measured at several buffer sizes: 100kiB (below
        the threshold), 2MiB (a typical borg chunk) and, for hashes, 50MiB (a borg
        pack). Every row processes roughly the same total number of bytes, so the
        throughput column is comparable between them.
        """
        )
        subparser = ArgumentParser(
            parents=[common_parser], description=self.do_benchmark_cpu.__doc__, epilog=bench_cpu_epilog
        )
        benchmark_parsers.add_subcommand("cpu", subparser, help="benchmarks Borg CPU-bound operations.")
        subparser.add_argument("--json", action="store_true", help="format output as JSON")
        subparser.add_argument("--chunking", action="store_true", help="benchmark the chunkers")
        subparser.add_argument("--hashing", action="store_true", help="benchmark the hashes / MACs")
        subparser.add_argument("--encryption", action="store_true", help="benchmark the encryption modes")
        subparser.add_argument("--compression", action="store_true", help="benchmark the compressors")
        subparser.add_argument("--msgpack", action="store_true", help="benchmark msgpack item packing")

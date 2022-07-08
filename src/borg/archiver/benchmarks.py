import argparse
from contextlib import contextmanager
import functools
import os
import shutil
import time

from ..constants import *  # NOQA
from ..crypto.key import FlexiKey
from ..helpers import format_file_size
from ..helpers import msgpack
from ..item import Item
from ..platform import SyncFile


class BenchmarkMixIn:
    def do_benchmark_crud(self, args):
        """Benchmark Create, Read, Update, Delete for archives."""

        def measurement_run(repo, path):
            compression = "--compression=none"
            # measure create perf (without files cache to always have it chunking)
            t_start = time.monotonic()
            rc = self.do_create(
                self.parse_args(
                    [f"--repo={repo}", "create", compression, "--files-cache=disabled", "borg-benchmark-crud1", path]
                )
            )
            t_end = time.monotonic()
            dt_create = t_end - t_start
            assert rc == 0
            # now build files cache
            rc1 = self.do_create(
                self.parse_args([f"--repo={repo}", "create", compression, "borg-benchmark-crud2", path])
            )
            rc2 = self.do_delete(self.parse_args([f"--repo={repo}", "delete", "-a", "borg-benchmark-crud2"]))
            assert rc1 == rc2 == 0
            # measure a no-change update (archive1 is still present)
            t_start = time.monotonic()
            rc1 = self.do_create(
                self.parse_args([f"--repo={repo}", "create", compression, "borg-benchmark-crud3", path])
            )
            t_end = time.monotonic()
            dt_update = t_end - t_start
            rc2 = self.do_delete(self.parse_args([f"--repo={repo}", "delete", "-a", "borg-benchmark-crud3"]))
            assert rc1 == rc2 == 0
            # measure extraction (dry-run: without writing result to disk)
            t_start = time.monotonic()
            rc = self.do_extract(self.parse_args([f"--repo={repo}", "extract", "borg-benchmark-crud1", "--dry-run"]))
            t_end = time.monotonic()
            dt_extract = t_end - t_start
            assert rc == 0
            # measure archive deletion (of LAST present archive with the data)
            t_start = time.monotonic()
            rc = self.do_delete(self.parse_args([f"--repo={repo}", "delete", "-a", "borg-benchmark-crud1"]))
            t_end = time.monotonic()
            dt_delete = t_end - t_start
            assert rc == 0
            return dt_create, dt_update, dt_extract, dt_delete

        @contextmanager
        def test_files(path, count, size, random):
            try:
                path = os.path.join(path, "borg-test-data")
                os.makedirs(path)
                z_buff = None if random else memoryview(zeros)[:size] if size <= len(zeros) else b"\0" * size
                for i in range(count):
                    fname = os.path.join(path, "file_%d" % i)
                    data = z_buff if not random else os.urandom(size)
                    with SyncFile(fname, binary=True) as fd:  # used for posix_fadvise's sake
                        fd.write(data)
                yield path
            finally:
                shutil.rmtree(path)

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
            total_size_MB = count * size / 1e06
            file_size_formatted = format_file_size(size)
            content = "random" if random else "all-zero"
            fmt = "%s-%-10s %9.2f MB/s (%d * %s %s files: %.2fs)"
            print(fmt % ("C", msg, total_size_MB / dt_create, count, file_size_formatted, content, dt_create))
            print(fmt % ("R", msg, total_size_MB / dt_extract, count, file_size_formatted, content, dt_extract))
            print(fmt % ("U", msg, total_size_MB / dt_update, count, file_size_formatted, content, dt_update))
            print(fmt % ("D", msg, total_size_MB / dt_delete, count, file_size_formatted, content, dt_delete))

        return 0

    def do_benchmark_cpu(self, args):
        """Benchmark CPU bound operations."""
        from timeit import timeit

        random_10M = os.urandom(10 * 1000 * 1000)
        key_256 = os.urandom(32)
        key_128 = os.urandom(16)
        key_96 = os.urandom(12)

        import io
        from ..chunker import get_chunker

        print("Chunkers =======================================================")
        size = "1GB"

        def chunkit(chunker_name, *args, **kwargs):
            with io.BytesIO(random_10M) as data_file:
                ch = get_chunker(chunker_name, *args, **kwargs)
                for _ in ch.chunkify(fd=data_file):
                    pass

        for spec, func in [
            ("buzhash,19,23,21,4095", lambda: chunkit("buzhash", 19, 23, 21, 4095, seed=0)),
            ("fixed,1048576", lambda: chunkit("fixed", 1048576, sparse=False)),
        ]:
            print(f"{spec:<24} {size:<10} {timeit(func, number=100):.3f}s")

        from ..checksums import crc32, xxh64

        print("Non-cryptographic checksums / hashes ===========================")
        size = "1GB"
        tests = [("xxh64", lambda: xxh64(random_10M)), ("crc32 (zlib)", lambda: crc32(random_10M))]
        for spec, func in tests:
            print(f"{spec:<24} {size:<10} {timeit(func, number=100):.3f}s")

        from ..crypto.low_level import hmac_sha256, blake2b_256

        print("Cryptographic hashes / MACs ====================================")
        size = "1GB"
        for spec, func in [
            ("hmac-sha256", lambda: hmac_sha256(key_256, random_10M)),
            ("blake2b-256", lambda: blake2b_256(key_256, random_10M)),
        ]:
            print(f"{spec:<24} {size:<10} {timeit(func, number=100):.3f}s")

        from ..crypto.low_level import AES256_CTR_BLAKE2b, AES256_CTR_HMAC_SHA256
        from ..crypto.low_level import AES256_OCB, CHACHA20_POLY1305

        print("Encryption =====================================================")
        size = "1GB"

        tests = [
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
        ]
        for spec, func in tests:
            print(f"{spec:<24} {size:<10} {timeit(func, number=100):.3f}s")

        print("KDFs (slow is GOOD, use argon2!) ===============================")
        count = 5
        for spec, func in [
            ("pbkdf2", lambda: FlexiKey.pbkdf2("mypassphrase", b"salt" * 8, PBKDF2_ITERATIONS, 32)),
            ("argon2", lambda: FlexiKey.argon2("mypassphrase", 64, b"S" * ARGON2_SALT_BYTES, **ARGON2_ARGS)),
        ]:
            print(f"{spec:<24} {count:<10} {timeit(func, number=count):.3f}s")

        from ..compress import CompressionSpec

        print("Compression ====================================================")
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
            size = "0.1GB"
            print(f"{spec:<12} {size:<10} {timeit(lambda: compressor.compress(random_10M), number=10):.3f}s")

        print("msgpack ========================================================")
        item = Item(path="/foo/bar/baz", mode=660, mtime=1234567)
        items = [item.as_dict()] * 1000
        size = "100k Items"
        spec = "msgpack"
        print(f"{spec:<12} {size:<10} {timeit(lambda: msgpack.packb(items), number=100):.3f}s")

        return 0

    def build_parser_benchmarks(self, subparsers, common_parser, mid_common_parser):

        from .common import process_epilog

        benchmark_epilog = process_epilog("These commands do various benchmarks.")

        subparser = subparsers.add_parser(
            "benchmark",
            parents=[mid_common_parser],
            add_help=False,
            description="benchmark command",
            epilog=benchmark_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="benchmark command",
        )

        benchmark_parsers = subparser.add_subparsers(title="required arguments", metavar="<command>")
        subparser.set_defaults(fallback_func=functools.partial(self.do_subcommand_help, subparser))

        bench_crud_epilog = process_epilog(
            """
        This command benchmarks borg CRUD (create, read, update, delete) operations.

        It creates input data below the given PATH and backups this data into the given REPO.
        The REPO must already exist (it could be a fresh empty repo or an existing repo, the
        command will create / read / update / delete some archives named borg-benchmark-crud\\* there.

        Make sure you have free space there, you'll need about 1GB each (+ overhead).

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
        subparser = benchmark_parsers.add_parser(
            "crud",
            parents=[common_parser],
            add_help=False,
            description=self.do_benchmark_crud.__doc__,
            epilog=bench_crud_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="benchmarks borg CRUD (create, extract, update, delete).",
        )
        subparser.set_defaults(func=self.do_benchmark_crud)

        subparser.add_argument("path", metavar="PATH", help="path were to create benchmark input data")

        bench_cpu_epilog = process_epilog(
            """
        This command benchmarks misc. CPU bound borg operations.

        It creates input data in memory, runs the operation and then displays throughput.
        To reduce outside influence on the timings, please make sure to run this with:

        - an otherwise as idle as possible machine
        - enough free memory so there will be no slow down due to paging activity
        """
        )
        subparser = benchmark_parsers.add_parser(
            "cpu",
            parents=[common_parser],
            add_help=False,
            description=self.do_benchmark_cpu.__doc__,
            epilog=bench_cpu_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="benchmarks borg CPU bound operations.",
        )
        subparser.set_defaults(func=self.do_benchmark_cpu)

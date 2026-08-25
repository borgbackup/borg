#!/usr/bin/env python3
"""
Cross-architecture repository interoperability test.

borg's on-disk / on-the-wire format is architecture independent, but almost all
of our CI runs on little-endian machines only, so the big-endian code paths in
the native code (e.g. the __builtin_bswap64() in the chunker kernels) are never
executed.  This script drives a repository from two sides, so a repository that
was written on one architecture can be verified on the other one:

    # on machine/container A (e.g. big-endian):
    endian_interop_test.py testdata WORKDIR       # deterministic test data
    endian_interop_test.py write    WORKDIR be    # write archives "be-*"

    # on machine/container B (e.g. little-endian), same WORKDIR:
    endian_interop_test.py verify   WORKDIR be    # read what A wrote
    endian_interop_test.py write    WORKDIR le    # write archives "le-*"
    endian_interop_test.py compare  WORKDIR be le # same data, same chunks?

    # on machine/container A again:
    endian_interop_test.py verify   WORKDIR le    # read what B wrote

"verify" runs "borg check --verify-data", extracts the other side's archives and
compares the extracted files against the test data.  "compare" additionally
requires that both sides cut the data into exactly the same chunks with exactly
the same chunk IDs - if they did not, the archives would still be correct, but
deduplication between machines of different endianness would silently not work.

The labels are just names for the two sides, so the same script also drives the
32-bit interoperability test (.github/workflows/32bit.yml), where the two sides
are an emulated 32-bit machine and the 64-bit CI runner.

The environment (BORG_REPO, BORG_PASSPHRASE, cache and config dir) is set up by
this script; the borg to use can be given via the BORG environment variable.
"""

import argparse
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys

# fastcdc is borg's default chunker (and its kernel is one of the places with a
# byte-order dependent code path).  Much smaller chunks than the default: the
# test data then gets cut into thousands of chunks == thousands of chances to
# notice a byte-order dependent cut point.
#
# The second archive uses different chunker parameters on purpose: with the same
# parameters it would just deduplicate against the first one and its compression
# would never be exercised.  So both sides also have to agree about the chunk
# format of more than one compression method.
ARCHIVE_SPECS = [
    ("fastcdc-zstd", ["--chunker-params", "fastcdc,10,16,12,2", "--compression", "zstd,3"]),
    ("fastcdc-lz4", ["--chunker-params", "fastcdc,12,18,14,2", "--compression", "lz4"]),
]

PASSPHRASE = "borg-endian-interop-test"

# the test data lives in this subdirectory of the work directory
DATA = "data"


def borg(workdir, label, *args, cwd=None, capture=False):
    """run a borg command against the test repository"""
    env = os.environ.copy()
    env["BORG_REPO"] = os.path.join(workdir, "repo")
    env["BORG_PASSPHRASE"] = PASSPHRASE
    # the KDF does not need to be strong for a throwaway test repository and
    # argon2 is *slow* under emulation:
    env["BORG_TESTONLY_WEAKEN_KDF"] = "1"
    # keep the two sides (and the machine's own borg config) apart:
    env["BORG_BASE_DIR"] = os.path.join(workdir, "home-%s" % label)
    env["BORG_CACHE_DIR"] = os.path.join(workdir, "home-%s" % label, "cache")
    env["BORG_CONFIG_DIR"] = os.path.join(workdir, "home-%s" % label, "config")
    cmd = [os.environ.get("BORG", "borg")] + [str(a) for a in args]
    print("+ %s" % " ".join(cmd), flush=True)
    if capture:
        return subprocess.run(cmd, env=env, cwd=cwd, check=True, stdout=subprocess.PIPE).stdout
    subprocess.run(cmd, env=env, cwd=cwd, check=True)
    return None


def datadir(workdir):
    return os.path.join(workdir, DATA)


def cmd_testdata(args):
    """create deterministic test data - content must not depend on the machine"""
    path = datadir(args.workdir)
    if os.path.exists(path):
        shutil.rmtree(path)
    os.makedirs(os.path.join(path, "nested", "dir"))
    rnd = random.Random(20260814)

    # incompressible, gets cut into many chunks:
    with open(os.path.join(path, "random.bin"), "wb") as f:
        f.write(rnd.randbytes(8 * 1024 * 1024))
    # compressible, but not uniform - many different chunker cut points:
    with open(os.path.join(path, "text.bin"), "wb") as f:
        for i in range(64 * 1024):
            f.write(b"line %d: %s\n" % (i, b"borg" * (i % 17)))
    # all-zero data (the chunkers have a shortcut for this):
    with open(os.path.join(path, "zeros.bin"), "wb") as f:
        f.write(b"\0" * (2 * 1024 * 1024))
    # the same data as random.bin, but shifted by a few bytes: the rolling hash
    # has to find the same cut points again after the insertion.
    with open(os.path.join(path, "random.bin"), "rb") as f:
        data = f.read()
    with open(os.path.join(path, "nested", "shifted.bin"), "wb") as f:
        f.write(b"insertion" + data)
    with open(os.path.join(path, "nested", "dir", "small.txt"), "wb") as f:
        f.write(b"hello borg\n")
    with open(os.path.join(path, "nested", "empty"), "wb"):
        pass
    with open(os.path.join(path, "nested", "\u00fcmlaut-\u65e5\u672c\u8a9e.txt"), "wb") as f:
        f.write("non-ascii file name and content: \u00e4\u00f6\u00fc\n".encode())
    os.symlink("dir/small.txt", os.path.join(path, "nested", "symlink"))
    os.link(os.path.join(path, "nested", "dir", "small.txt"), os.path.join(path, "nested", "hardlink"))
    print("test data created in %s" % path)


def scan(path):
    """map relative path -> file content hash / symlink target, for comparing 2 trees"""
    result = {}
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames.sort()
        for name in sorted(dirnames + filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, path)
            if os.path.islink(full):
                result[rel] = "symlink:%s" % os.readlink(full)
            elif os.path.isdir(full):
                result[rel] = "dir"
            else:
                digest = hashlib.sha256()
                with open(full, "rb") as f:
                    for block in iter(lambda: f.read(1024 * 1024), b""):
                        digest.update(block)
                result[rel] = "file:%s" % digest.hexdigest()
    return result


def dump_path(workdir, archive, label):
    return os.path.join(workdir, "dumps", "%s.read-by-%s.json" % (archive, label))


def dump_archive(workdir, label, archive):
    """dump the archive metadata as read by *this* machine"""
    os.makedirs(os.path.join(workdir, "dumps"), exist_ok=True)
    borg(workdir, label, "debug", "dump-archive", archive, dump_path(workdir, archive, label))


def chunk_list(dump_file):
    """(path, size, chunks) of all items, everything that must not depend on the architecture"""
    with open(dump_file) as f:
        dump = json.load(f)
    items = []
    for item in dump["_items"]:
        items.append((item["path"], item.get("size"), item.get("target"), item.get("chunks")))
    return items


def cmd_write(args):
    workdir, label = args.workdir, args.label
    if not os.path.exists(os.path.join(workdir, "repo")):
        borg(workdir, label, "repo-create", "--encryption=aes256-ocb")
    for suffix, options in ARCHIVE_SPECS:
        archive = "%s-%s" % (label, suffix)
        # --files-cache=disabled: really chunk the files, do not trust any cache.
        # Archive the relative path "data" from within the work directory: the
        # two sides usually see the work directory at different absolute paths
        # (e.g. one of them inside a container), but the item paths in the
        # archives must be comparable.
        borg(workdir, label, "create", "--files-cache=disabled", *options, archive, DATA, cwd=workdir)
        dump_archive(workdir, label, archive)
    borg(workdir, label, "repo-list")


def cmd_verify(args):
    """check and extract the archives written by the *other* side"""
    workdir, other, label = args.workdir, args.label, args.as_label
    borg(workdir, label, "check", "--verify-data")
    expected = scan(datadir(workdir))
    assert expected, "no test data found in %s" % datadir(workdir)
    for suffix, _ in ARCHIVE_SPECS:
        archive = "%s-%s" % (other, suffix)
        extract_to = os.path.join(workdir, "extract-%s-by-%s" % (archive, label))
        if os.path.exists(extract_to):
            shutil.rmtree(extract_to)
        os.makedirs(extract_to)
        borg(workdir, label, "extract", archive, cwd=extract_to)
        got = scan(os.path.join(extract_to, DATA))
        if got != expected:
            for key in sorted(set(expected) | set(got)):
                if expected.get(key) != got.get(key):
                    print("MISMATCH %s: expected %r, got %r" % (key, expected.get(key), got.get(key)))
            raise SystemExit("archive %s does not extract to the original test data!" % archive)
        print("OK: %s extracted identically (%d entries)" % (archive, len(got)))
        # the same archive, but read (and its metadata decoded) on this machine:
        dump_archive(workdir, label, archive)
        written_by_other = chunk_list(dump_path(workdir, archive, other))
        read_by_us = chunk_list(dump_path(workdir, archive, label))
        if written_by_other != read_by_us:
            raise SystemExit("archive %s does not decode identically on both architectures!" % archive)
        print("OK: %s metadata (incl. chunk ids) decodes identically on both architectures" % archive)


def cmd_compare(args):
    """both sides archived the same data: they must have produced the same chunks"""
    workdir, a, b = args.workdir, args.label, args.other_label
    for suffix, _ in ARCHIVE_SPECS:
        archive_a, archive_b = "%s-%s" % (a, suffix), "%s-%s" % (b, suffix)
        items_a = chunk_list(dump_path(workdir, archive_a, a))
        items_b = chunk_list(dump_path(workdir, archive_b, b))
        if items_a != items_b:
            for item_a, item_b in zip(items_a, items_b):
                if item_a != item_b:
                    print("MISMATCH %s:\n  %s: %r\n  %s: %r" % (item_a[0], a, item_a[1:], b, item_b[1:]))
            raise SystemExit(
                "%s and %s chunked the same data differently - "
                "deduplication between these architectures would not work!" % (archive_a, archive_b)
            )
        chunks = sum(len(item[3] or []) for item in items_a)
        print("OK: %s and %s have identical items and chunk ids (%d chunks)" % (archive_a, archive_b, chunks))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)

    sub = commands.add_parser("testdata", help="create the deterministic test data")
    sub.add_argument("workdir")
    sub.set_defaults(func=cmd_testdata)

    sub = commands.add_parser("write", help="create the repository and this side's archives")
    sub.add_argument("workdir")
    sub.add_argument("label", help="label of this side, e.g. 'be'")
    sub.set_defaults(func=cmd_write)

    sub = commands.add_parser("verify", help="check/extract the archives the other side wrote")
    sub.add_argument("workdir")
    sub.add_argument("label", help="label of the *other* side, e.g. 'be'")
    sub.add_argument("--as", dest="as_label", required=True, help="label of this side, e.g. 'le'")
    sub.set_defaults(func=cmd_verify)

    sub = commands.add_parser("compare", help="compare the chunk ids both sides produced")
    sub.add_argument("workdir")
    sub.add_argument("label")
    sub.add_argument("other_label")
    sub.set_defaults(func=cmd_compare)

    args = parser.parse_args()
    os.makedirs(args.workdir, exist_ok=True)
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())

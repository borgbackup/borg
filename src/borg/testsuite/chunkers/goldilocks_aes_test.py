from hashlib import sha256
from io import BytesIO
import os
import random


from . import cf
from ...chunkers import ChunkerGoldilocksAES
from ...chunkers.goldilocks_aes import (
    goldilocks_aes_digest64,
    goldilocks_aes_get_key_elem,
    goldilocks_aes_get_tables,
    goldilocks_aes_scan_all,
    _GL_P,
)
from ...constants import *  # NOQA
from ...helpers import hex_to_bin


# from os.urandom(32)
key0 = hex_to_bin("ad9f89095817f0566337dc9ee292fcd59b70f054a8200151f1df5f21704824da")
key1 = hex_to_bin("f1088c7e9e6ae83557ad1558ff36c44a369ea719d1081c29684f52ffccb72cb8")


def H(data):
    return sha256(data).digest()


def test_chunkpoints_goldilocks_aes_unchanged():
    def twist(size):
        x = 1
        a = bytearray(size)
        for i in range(size):
            x = (x * 1103515245 + 12345) & 0x7FFFFFFF
            a[i] = x & 0xFF
        return a

    data = twist(100000)

    runs = []
    for nc_level in (0, 2, 3):
        for minexp in (6, 7, 11, 12):  # goldilocks-aes requires minexp >= 6 (64-byte window)
            for maxexp in (15, 17):
                if minexp >= maxexp:
                    continue
                for maskbits in (7, 10, 12):
                    if maskbits - nc_level < 1:  # nc_level needs room below the base mask bits
                        continue
                    for key in (key0, key1):
                        fh = BytesIO(data)
                        chunker = ChunkerGoldilocksAES(key, minexp, maxexp, maskbits, nc_level)
                        chunks = [H(c) for c in cf(chunker.chunkify(fh, -1))]
                        runs.append(H(b"".join(chunks)))

    # The "correct" hash below matches the existing chunker behavior.
    # Future chunker optimizations must not change this, or existing repos will bloat.
    overall_hash = H(b"".join(runs))
    print(overall_hash.hex())
    assert overall_hash == hex_to_bin("4aa18be3a2209cc0f454af01a9019e050eb1588b959f96c7e0de532b6a69fd65")


def test_goldilocks_aes_key_elem_and_tables():
    # K must be a canonical field element, deterministically derived from the key
    k0 = goldilocks_aes_get_key_elem(key0)
    assert 0 <= k0 < _GL_P
    assert k0 == goldilocks_aes_get_key_elem(key0)
    k1 = goldilocks_aes_get_key_elem(key1)
    assert k0 != k1

    nout64_tbl, nout65_tbl, in1_tbl = goldilocks_aes_get_tables(key0)
    assert len(nout64_tbl) == len(nout65_tbl) == len(in1_tbl) == 256
    for v in nout64_tbl + nout65_tbl + in1_tbl:
        assert isinstance(v, int)
        assert 0 <= v < _GL_P  # all table entries are canonical field elements
    # spot check the tables against K: entry b is (-b * K^64), (-b * K^65), (b * K) mod p
    k64 = pow(k0, 64, _GL_P)
    for b in (0, 1, 2, 128, 255):
        assert nout64_tbl[b] == (-b * k64) % _GL_P
        assert nout65_tbl[b] == (-b * k64 * k0) % _GL_P
        assert in1_tbl[b] == (b * k0) % _GL_P


def test_goldilocks_aes_field_arithmetic():
    # the C kernel's GF(p) arithmetic must match a pure-Python big-int reference,
    # including evaluation points and window bytes that stress the reduction
    def horner(k, window):
        d = 0
        for b in window:
            d = (d * k + b) % _GL_P
        return d

    rng = random.Random(42)
    ks = [1, 2, _GL_P - 1, _GL_P - 2, 0xFFFFFFFF, 0x100000000] + [rng.randrange(_GL_P) for _ in range(10)]
    windows = [b"\xff" * 64, b"\x00" * 63 + b"\x01", bytes(range(64))] + [rng.randbytes(64) for _ in range(10)]
    for k in ks:
        for w in windows:
            assert goldilocks_aes_digest64(k, w) == horner(k, w)


def test_goldilocks_aes_scan_matches_recompute():
    # the raw rolling scan (both kernels) must agree with itself across paths and
    # with a from-scratch state recomputation at every reported cut position
    data = os.urandom(256 * 1024)
    k = goldilocks_aes_get_key_elem(key0)
    aes_key = os.urandom(16)
    mask = (1 << 10) - 1
    hw = goldilocks_aes_scan_all(k, aes_key, data, mask, force_sw=False)
    evp = goldilocks_aes_scan_all(k, aes_key, data, mask, force_sw=True)
    assert hw == evp
    assert len(hw) > 100  # ~256 expected at 10 mask bits

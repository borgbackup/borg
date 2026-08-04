from hashlib import sha256
from io import BytesIO
import random


from . import cf
from ...chunkers import ChunkerToeplitzAES
from ...chunkers.rabin_aes import _is_irreducible
from ...chunkers.toeplitz_aes import toeplitz_aes_digest64, toeplitz_aes_get_table, toeplitz_aes_get_tables, _P
from ...constants import *  # NOQA
from ...helpers import hex_to_bin


# from os.urandom(32)
key0 = hex_to_bin("ad9f89095817f0566337dc9ee292fcd59b70f054a8200151f1df5f21704824da")
key1 = hex_to_bin("f1088c7e9e6ae83557ad1558ff36c44a369ea719d1081c29684f52ffccb72cb8")


def H(data):
    return sha256(data).digest()


def test_chunkpoints_toeplitz_aes_unchanged():
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
        for minexp in (6, 7, 11, 12):  # toeplitz-aes requires minexp >= 6 (64-byte window)
            for maxexp in (15, 17):
                if minexp >= maxexp:
                    continue
                for maskbits in (7, 10, 12):
                    if maskbits - nc_level < 1:  # nc_level needs room below the base mask bits
                        continue
                    for key in (key0, key1):
                        fh = BytesIO(data)
                        chunker = ChunkerToeplitzAES(key, minexp, maxexp, maskbits, nc_level)
                        chunks = [H(c) for c in cf(chunker.chunkify(fh, -1))]
                        runs.append(H(b"".join(chunks)))

    # The "correct" hash below matches the existing chunker behavior.
    # Future chunker optimizations must not change this, or existing repos will bloat.
    overall_hash = H(b"".join(runs))
    print(overall_hash.hex())
    assert overall_hash == hex_to_bin("d98a97b3eeb1122c602c4581f486bd356404447efe2bf550000e12d1f046b843")


def test_toeplitz_aes_polynomial_and_tables():
    # the fixed public polynomial must be irreducible of degree 64
    # (reuse the rabin-aes Rabin test, which handles degree 64)
    assert _P.bit_length() - 1 == 64
    assert _is_irreducible(_P)

    # T must be deterministically derived from the key
    t0 = toeplitz_aes_get_table(key0)
    assert len(t0) == 256
    assert all(0 <= v < 2**64 for v in t0)
    assert t0 == toeplitz_aes_get_table(key0)
    t1 = toeplitz_aes_get_table(key1)
    assert t0 != t1

    def pmod(v):
        while v.bit_length() - 1 >= 64:
            v ^= _P << (v.bit_length() - 1 - 64)
        return v

    in0_tbl, in1_tbl, out64_tbl, out65_tbl = toeplitz_aes_get_tables(key0)
    assert in0_tbl == t0
    assert len(in1_tbl) == len(out64_tbl) == len(out65_tbl) == 256
    # spot check the derived tables against T and P
    for b in (0, 1, 2, 128, 255):
        assert in1_tbl[b] == pmod(t0[b] << 1)
        assert out64_tbl[b] == pmod(t0[b] << 64)
        assert out65_tbl[b] == pmod(t0[b] << 65)


def test_toeplitz_aes_digest_reference():
    # the C kernel's digest must match a pure-Python big-int reference:
    # digest = sum_j x^(63-j) * T[b_j] mod P
    def pmod(v):
        while v.bit_length() - 1 >= 64:
            v ^= _P << (v.bit_length() - 1 - 64)
        return v

    rng = random.Random(42)
    for key in (key0, key1):
        t = toeplitz_aes_get_table(key)
        windows = [b"\x00" * 64, b"\xff" * 64, b"\x42" * 64, bytes(range(64))]
        windows += [rng.randbytes(64) for _ in range(10)]
        for w in windows:
            ref = 0
            for b in w:
                ref = pmod(ref << 1) ^ t[b]
            assert toeplitz_aes_digest64(key, w) == ref

from hashlib import sha256
from io import BytesIO


from . import cf
from ...chunkers import ChunkerRabinAES
from ...chunkers.rabin_aes import rabin_aes_get_polynomial, rabin_aes_get_tables, _is_irreducible
from ...constants import *  # NOQA
from ...helpers import hex_to_bin


# from os.urandom(32)
key0 = hex_to_bin("ad9f89095817f0566337dc9ee292fcd59b70f054a8200151f1df5f21704824da")
key1 = hex_to_bin("f1088c7e9e6ae83557ad1558ff36c44a369ea719d1081c29684f52ffccb72cb8")


def H(data):
    return sha256(data).digest()


def test_chunkpoints_rabin_aes_unchanged():
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
        for minexp in (6, 7, 11, 12):  # rabin-aes requires minexp >= 6 (64-byte window)
            for maxexp in (15, 17):
                if minexp >= maxexp:
                    continue
                for maskbits in (7, 10, 12):
                    if maskbits - nc_level < 1:  # nc_level needs room below the base mask bits
                        continue
                    for key in (key0, key1):
                        fh = BytesIO(data)
                        chunker = ChunkerRabinAES(key, minexp, maxexp, maskbits, nc_level)
                        chunks = [H(c) for c in cf(chunker.chunkify(fh, -1))]
                        runs.append(H(b"".join(chunks)))

    # The "correct" hash below matches the existing chunker behavior.
    # Future chunker optimizations must not change this, or existing repos will bloat.
    overall_hash = H(b"".join(runs))
    print(overall_hash.hex())
    assert overall_hash == hex_to_bin("f502d8da9dc338ff6949d89cdb545ff690bba8919263a17010c2a4995031d7ef")


def test_rabin_aes_polynomial():
    # P must be a degree-64 irreducible polynomial, deterministically derived from the key
    p0 = rabin_aes_get_polynomial(key0)
    assert p0.bit_length() - 1 == 64
    assert p0 & 1  # constant term set (otherwise divisible by x)
    assert _is_irreducible(p0)
    assert p0 == rabin_aes_get_polynomial(key0)
    p1 = rabin_aes_get_polynomial(key1)
    assert p0 != p1

    out_tbl, red_tbl = rabin_aes_get_tables(key0)
    assert len(out_tbl) == 256 and len(red_tbl) == 256
    for v in out_tbl + red_tbl:
        assert isinstance(v, int)
        assert 0 <= v < 2**64  # all table entries are mod-P remainders
    # spot check the tables against the polynomial: entry b is (b << shift) mod P
    for b in (0, 1, 2, 128, 255):
        v = b << 504
        while v.bit_length() - 1 >= 64:
            v ^= p0 << (v.bit_length() - 1 - 64)
        assert out_tbl[b] == v

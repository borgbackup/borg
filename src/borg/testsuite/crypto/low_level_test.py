"""Tests for borg.crypto.low_level: the AEAD ciphers' chunked OpenSSL calls and XXH64.

XXH64 only exists to support ``borg transfer`` from borg 1.x repos (see #9935), where it is
needed to verify the XXH64 integrity data that borg 1.x wrote for its repo index/hints files.

The reference vectors below are the official xxHash sanity-check vectors: the test buffer is
produced by the exact PRNG generator from the xxHash test suite
(https://github.com/Cyan4973/xxHash, tests/sanity_test.c) and the expected digests are the
canonical (big-endian) XXH64 results for that buffer, cross-checked against the reference
xxHash implementation.
"""

import os

import pytest

from ...crypto.low_level import AES256_OCB, CHACHA20_POLY1305, IntegrityError, XXH64, xxh64
from ...crypto.low_level import _set_cipher_update_chunk_size

# xxHash test-buffer generator, transcribed verbatim from tests/sanity_test.c:
#   XXH_U64 byteGen = PRIME32;
#   for each byte: buffer[i] = (U8)(byteGen >> 56); byteGen *= PRIME64;
_PRIME32 = 2654435761
_PRIME64 = 11400714785074694797
_MASK64 = (1 << 64) - 1
_SANITY_BUFFER_SIZE = 4096 + 64 + 1  # 4161


def _sanity_buffer(size):
    buf = bytearray(size)
    byte_gen = _PRIME32
    for i in range(size):
        buf[i] = (byte_gen >> 56) & 0xFF
        byte_gen = (byte_gen * _PRIME64) & _MASK64
    return bytes(buf)


SANITY_BUFFER = _sanity_buffer(_SANITY_BUFFER_SIZE)

# (length, seed, expected canonical hexdigest) for prefixes of SANITY_BUFFER.
# The lengths deliberately exercise all code paths: empty, the 1-byte tail loop, the 4-byte
# and 1-byte tails (<32 bytes -> seed+PRIME5 path), exactly one 32-byte stripe, multiple
# stripes plus tails, and the full multi-KiB buffer. Seeds are 0 and PRIME32 (0x9e3779b1).
XXH64_VECTORS = [
    (0, 0x00000000, "ef46db3751d8e999"),
    (1, 0x00000000, "e934a84adb052768"),
    (14, 0x00000000, "8282dcc4994e35c8"),
    (32, 0x00000000, "18b216492bb44b70"),
    (95, 0x00000000, "ff9f46bdcc644624"),
    (_SANITY_BUFFER_SIZE, 0x00000000, "cd3d6df2db509a75"),
    (0, 0x9E3779B1, "ac75fda2929b17ef"),
    (1, 0x9E3779B1, "5014607643a9b4c3"),
    (14, 0x9E3779B1, "c3bd6bf63deb6df0"),
    (32, 0x9E3779B1, "b3f33bdf93ade409"),
    (95, 0x9E3779B1, "72e75a560ef624a3"),
    (_SANITY_BUFFER_SIZE, 0x9E3779B1, "2394cb79e97368d1"),
]


@pytest.mark.parametrize("length, seed, expected", XXH64_VECTORS)
def test_official_vectors(length, seed, expected):
    data = SANITY_BUFFER[:length]
    # one-shot via the constructor and via the module-level helper
    assert XXH64(data, seed).hexdigest() == expected
    assert XXH64(data, seed).digest() == bytes.fromhex(expected)
    assert xxh64(data, seed) == bytes.fromhex(expected)


def test_empty():
    # the single most widely published XXH64 constant
    assert XXH64().hexdigest() == "ef46db3751d8e999"
    assert XXH64(b"").hexdigest() == "ef46db3751d8e999"


def test_default_seed_is_zero():
    assert XXH64(SANITY_BUFFER).hexdigest() == XXH64(SANITY_BUFFER, 0).hexdigest()


def test_digest_is_stable_and_bytes():
    h = XXH64(b"borg")
    d1 = h.digest()
    d2 = h.digest()
    assert isinstance(d1, bytes) and len(d1) == 8
    assert d1 == d2  # digest() can be called repeatedly without changing state
    assert h.hexdigest() == d1.hex()


@pytest.mark.parametrize("length, seed, expected", XXH64_VECTORS)
@pytest.mark.parametrize("chunk", [1, 3, 7, 8, 16, 31, 32, 33, 64])
def test_streaming_matches_oneshot(length, seed, expected, chunk):
    # feeding the data in arbitrary chunk sizes (crossing the internal 32-byte stripe
    # boundary in every possible alignment) must reproduce the one-shot digest.
    data = SANITY_BUFFER[:length]
    h = XXH64(seed=seed)
    for off in range(0, len(data), chunk):
        h.update(data[off : off + chunk])
    assert h.hexdigest() == expected


def test_accepts_buffer_protocol():
    data = SANITY_BUFFER[:100]
    expected = XXH64(data).hexdigest()
    assert XXH64(bytearray(data)).hexdigest() == expected
    assert XXH64(memoryview(data)).hexdigest() == expected
    h = XXH64()
    h.update(bytearray(data[:50]))
    h.update(memoryview(data[50:]))
    assert h.hexdigest() == expected


@pytest.fixture
def small_cipher_update_chunks():
    """Make the AEAD ciphers feed their input to OpenSSL in 7 byte chunks (see _cipher_update).

    7 is not a multiple of the 16 byte cipher block, so chunk boundaries fall inside blocks, which OCB
    buffers across calls.
    """
    previous = _set_cipher_update_chunk_size(7)
    yield
    _set_cipher_update_chunk_size(previous)


@pytest.mark.parametrize("cipher_cls", [AES256_OCB, CHACHA20_POLY1305])
def test_aead_cipher_update_in_chunks(cipher_cls, small_cipher_update_chunks):
    """Chunked processing gives the same envelope and plaintext as one call with all of the input."""
    key = b"k" * 32
    header = b"\x01\x02"
    aad = b"additional authenticated data " * 3  # longer than a chunk, so the AAD is chunked, too
    data = os.urandom(1000)
    previous = _set_cipher_update_chunk_size(1 << 30)  # reference: everything in one call
    envelope = cipher_cls(key, iv=42, header_len=len(header), aad_offset=1).encrypt(data, header=header, aad=aad)
    _set_cipher_update_chunk_size(previous)
    cipher = cipher_cls(key, iv=42, header_len=len(header), aad_offset=1)
    assert cipher.encrypt(data, header=header, aad=aad) == envelope
    assert cipher.decrypt(envelope, aad=aad) == data
    for size in (0, 1, 7, 16, 17):  # empty, less than a chunk, one chunk, one block, a block plus a byte
        cipher = cipher_cls(key, iv=size, header_len=len(header), aad_offset=1)
        assert cipher.decrypt(cipher.encrypt(data[:size], header=header, aad=aad), aad=aad) == data[:size]
    tampered = envelope[:-1] + bytes([envelope[-1] ^ 1])
    with pytest.raises(IntegrityError):
        cipher.decrypt(tampered, aad=aad)


@pytest.mark.skipif(
    not os.environ.get("BORG_TESTS_BIG_MEMORY"), reason="needs ~4 GiB of RAM, set BORG_TESTS_BIG_MEMORY=1 to run"
)
@pytest.mark.parametrize("cipher_cls", [AES256_OCB, CHACHA20_POLY1305])
def test_aead_message_longer_than_int_max(cipher_cls):
    """A message of more than 2^31 bytes exceeds the C int input length of one OpenSSL update call."""
    size = 2**31 + 1000
    data = bytes(size)  # all zero: cheap to allocate
    cipher = cipher_cls(b"k" * 32, iv=0)
    envelope = cipher.encrypt(data)
    assert len(envelope) == 16 + size
    del data
    plaintext = cipher.decrypt(envelope)
    assert len(plaintext) == size and plaintext.count(b"\0") == size

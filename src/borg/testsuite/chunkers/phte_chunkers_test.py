"""Behavior shared by all UHF-then-PRF chunkers (rabin-aes, goldilocks-aes, toeplitz-aes).

These chunkers differ only in their rolling universal hash; everything tested
here - kernel equivalence, chunk size distribution, shift resilience, param
parsing, fuzzing - must hold for all of them. Per-chunker specifics (frozen
golden chunk points, the hash arithmetic itself, key derivation) live in the
individual <chunker>_test.py modules.
"""

from hashlib import sha256
from io import BytesIO
import os
import random

import pytest

from . import cf, cf_expand
from ...chunkers import ChunkerRabinAES, ChunkerGoldilocksAES, ChunkerToeplitzAES, get_chunker
from ...constants import *  # NOQA
from ...helpers import hex_to_bin


# from os.urandom(32)
key0 = hex_to_bin("ad9f89095817f0566337dc9ee292fcd59b70f054a8200151f1df5f21704824da")

# (chunker class, algo name, default params constant, env var forcing the portable kernel)
CHUNKERS = [
    (ChunkerRabinAES, CH_RABIN_AES, RABIN_AES_PARAMS, "BORG_RABIN_AES_FORCE_EVP"),
    (ChunkerGoldilocksAES, CH_GOLDILOCKS_AES, GOLDILOCKS_AES_PARAMS, "BORG_GOLDILOCKS_AES_FORCE_EVP"),
    (ChunkerToeplitzAES, CH_TOEPLITZ_AES, TOEPLITZ_AES_PARAMS, "BORG_TOEPLITZ_AES_FORCE_EVP"),
]
IDS = [algo for _, algo, _, _ in CHUNKERS]


def H(data):
    return sha256(data).digest()


@pytest.fixture(params=CHUNKERS, ids=IDS)
def chunker_spec(request):
    return request.param


def test_kernels_identical(chunker_spec):
    # the OpenSSL EVP batch path and the AES hardware instruction path (if available
    # on this platform) must produce identical cut points.
    cls, algo, params, env_var = chunker_spec
    data = os.urandom(4 * 1024 * 1024)

    def sizes(chunker):
        return [c.meta["size"] for c in chunker.chunkify(BytesIO(data))]

    default = cls(key0, 10, 16, 14, 2)
    sizes_default = sizes(default)
    os.environ[env_var] = "1"
    try:
        forced = cls(key0, 10, 16, 14, 2)
        assert forced.kernel == "evp"
        sizes_evp = sizes(forced)
    finally:
        del os.environ[env_var]
    assert sizes_default == sizes_evp
    # whatever kernel was selected by default, it must be a known one
    assert default.kernel in ("aes-arm64", "vaes", "aes-ni", "evp")


def test_chunksize_distribution(chunker_spec):
    cls, algo, params, env_var = chunker_spec
    data = os.urandom(1048576)
    min_exp, max_exp, mask, nc_level = 10, 16, 14, 2  # chunk size target 16 KiB, clip at 1 KiB and 64 KiB
    chunker = cls(key0, min_exp, max_exp, mask, nc_level)
    f = BytesIO(data)
    chunks = cf(chunker.chunkify(f))
    del chunks[-1]  # get rid of the last chunk, it can be smaller than 2**min_exp
    chunk_sizes = [len(chunk) for chunk in chunks]
    chunks_count = len(chunks)
    min_chunksize_observed = min(chunk_sizes)
    max_chunksize_observed = max(chunk_sizes)
    min_count = sum(int(size == 2**min_exp) for size in chunk_sizes)
    max_count = sum(int(size == 2**max_exp) for size in chunk_sizes)
    print(
        f"count: {chunks_count} min: {min_chunksize_observed} max: {max_chunksize_observed} "
        f"min count: {min_count} max count: {max_count}"
    )
    # usually there will about 64 chunks
    assert 32 < chunks_count < 128
    # chunks always must be between min and max (clipping must work):
    assert min_chunksize_observed >= 2**min_exp
    assert max_chunksize_observed <= 2**max_exp
    # most chunks should be cut due to the hash triggering, not due to clipping at min/max size:
    assert min_count < 10
    assert max_count < 10


def test_shift_resilience(chunker_spec):
    # content-defined cuts must survive a prefix insertion (this also validates that the
    # rolling digest update and the per-chunk window warm-up agree with each other).
    cls, algo, params, env_var = chunker_spec
    data = os.urandom(4 * 1024 * 1024)

    def chunk_hashes(data):
        chunker = cls(key0, 10, 16, 14, 2)
        return [H(c) for c in cf_expand(chunker.chunkify(BytesIO(data)))]

    h1 = set(chunk_hashes(data))
    h2 = chunk_hashes(b"PREFIX_SHIFTS_EVERYTHING" + data)
    survived = sum(1 for h in h2 if h in h1)
    assert survived / len(h2) > 0.9


def test_get_chunker(chunker_spec):
    # without a key, get_chunker uses an all-zero key; chunking must still work and be deterministic
    cls, algo, params, env_var = chunker_spec
    data = os.urandom(2 * 1024 * 1024)
    a = cf_expand(get_chunker(*params, key=None).chunkify(BytesIO(data)))
    b = cf_expand(get_chunker(algo, 19, 23, 21, 2, key=None).chunkify(BytesIO(data)))
    assert a == b
    assert b"".join(a) == data


def test_params_parsing(chunker_spec):
    from argparse import ArgumentTypeError

    from ...helpers import ChunkerParams

    cls, algo, params, env_var = chunker_spec

    # <algo>, chunk_min, chunk_max, chunk_mask, nc_level (no window field)
    assert ChunkerParams(f"{algo},19,23,21,2") == (algo, 19, 23, 21, 2)
    assert ChunkerParams(f"{algo},10,23,16,0") == (algo, 10, 23, 16, 0)
    # a 6-field (buzhash64-style, with window) spec must be rejected
    with pytest.raises(ArgumentTypeError):
        ChunkerParams(f"{algo},19,23,21,4095,2")
    # a 4-field spec (missing nc_level) must be rejected, not fall into old-style compat mode
    with pytest.raises(ArgumentTypeError):
        ChunkerParams(f"{algo},19,23,21")
    # nc_level out of range (chunk_mask - nc_level < 1)
    with pytest.raises(ArgumentTypeError):
        ChunkerParams(f"{algo},19,23,21,21")
    # chunk_min <= chunk_mask <= chunk_max violated
    with pytest.raises(ArgumentTypeError):
        ChunkerParams(f"{algo},19,23,24,2")
    # chunk_min < 6 is not allowed (the 64-byte window needs 64 bytes of in-chunk history)
    with pytest.raises(ArgumentTypeError):
        ChunkerParams(f"{algo},5,23,21,2")


@pytest.mark.skipif("BORG_TESTS_SLOW" not in os.environ, reason="slow tests not enabled, use BORG_TESTS_SLOW=1")
@pytest.mark.parametrize("worker", range(os.cpu_count() or 1))
def test_fuzz(chunker_spec, worker):
    # Fuzz with random and uniform data of misc. sizes and misc keys.
    cls, algo, params, env_var = chunker_spec

    # decompose <ALGO>_PARAMS = (algo, min_exp, max_exp, mask_bits, nc_level)
    params_algo, min_exp, max_exp, mask_bits, nc_level = params
    assert params_algo == algo

    keys = [b"\0" * 32] + [os.urandom(32) for _ in range(10)]
    sizes = [random.randint(1, 4 * 1024 * 1024) for _ in range(50)]

    for key in keys:
        chunker = cls(key, min_exp, max_exp, mask_bits, nc_level)
        for size in sizes:
            # Random data
            data = os.urandom(size)
            with BytesIO(data) as bio:
                parts = cf_expand(chunker.chunkify(bio))
            assert b"".join(parts) == data

            # All-same data (non-zero)
            data = b"\x42" * size
            with BytesIO(data) as bio:
                parts = cf_expand(chunker.chunkify(bio))
            assert b"".join(parts) == data

            # All-zero data
            data = b"\x00" * size
            with BytesIO(data) as bio:
                parts = cf_expand(chunker.chunkify(bio))
            assert b"".join(parts) == data

from .buzhash import Chunker
from .buzhash64 import ChunkerBuzHash64
from .fastcdc import ChunkerFastCDC
from .rabin_aes import ChunkerRabinAES
from .goldilocks_aes import ChunkerGoldilocksAES
from .toeplitz_aes import ChunkerToeplitzAES
from .failing import ChunkerFailing
from .fixed import ChunkerFixed
from .reader import *  # noqa

from .. import logger as _logger

logger = _logger.create_logger()


def _made(algo, chunker):
    """Log which chunker was constructed and which scan kernel it ended up with.

    The kernel is worth seeing because it is not implied by the platform: it
    defaults to the simplest implementation and is only changed by the
    BORG_*_KERNEL env vars (see kernel_env.py).

    Chunkers that have nothing to select - buzhash and fixed have exactly one
    implementation each - say so rather than omitting the field, so that a
    missing kernel cannot be mistaken for a reporting bug.

    Chunkers can be built before setup_logging() has run (tests do it, and so
    does anything using borg as a library), and create_logger() raises rather
    than log at that point - so say nothing when there is nowhere to say it.
    """
    if _logger.configured:
        kernel = getattr(chunker, "kernel", None) or "n/a (single implementation)"
        logger.debug("chunker: %s, scan kernel: %s", algo, kernel)
    return chunker


def get_chunker(algo, *params, **kw):
    key = kw.get("key", None)
    sparse = kw.get("sparse", False)
    # key.chunk_seed only has 32 bits
    seed = key.chunk_seed if key is not None else 0
    if algo == "buzhash":
        return _made(algo, Chunker(seed, *params, sparse=sparse))
    if algo == "buzhash64":
        # for buzhash64, we want a much longer key, so we derive it from the id key.
        # params is (chunk_min_exp, chunk_max_exp, hash_mask_bits, hash_window_size, nc_level);
        # nc_level is passed positionally. normal_size is an optional tuning knob (0 = auto).
        bh64_key = (
            key.derive_key(salt=b"", domain=b"buzhash64", size=32, from_id_key=True) if key is not None else b"\0" * 32
        )
        return _made(algo, ChunkerBuzHash64(bh64_key, *params, normal_size=kw.get("normal_size", 0), sparse=sparse))
    if algo == "fastcdc":
        # keyed gear table, derived from the id key (own domain). params is
        # (chunk_min_exp, chunk_max_exp, hash_mask_bits, nc_level) - no window (Gear is window-less).
        fc_key = (
            key.derive_key(salt=b"", domain=b"fastcdc", size=32, from_id_key=True) if key is not None else b"\0" * 32
        )
        return _made(algo, ChunkerFastCDC(fc_key, *params, normal_size=kw.get("normal_size", 0), sparse=sparse))
    if algo == "rabin-aes":
        # UHF-then-PRF chunker (secret Rabin polynomial + AES-128), derived from
        # the id key (own domain). params is (chunk_min_exp, chunk_max_exp,
        # hash_mask_bits, nc_level) - no window param (fixed 64-byte window).
        ra_key = (
            key.derive_key(salt=b"", domain=b"rabin-aes", size=32, from_id_key=True) if key is not None else b"\0" * 32
        )
        return _made(algo, ChunkerRabinAES(ra_key, *params, normal_size=kw.get("normal_size", 0), sparse=sparse))
    if algo == "goldilocks-aes":
        # like rabin-aes, but with the Goldilocks prime-field polynomial hash as
        # the UHF (the reference construction of eprint 2025/558). Same param
        # shape: (chunk_min_exp, chunk_max_exp, hash_mask_bits, nc_level).
        gl_key = (
            key.derive_key(salt=b"", domain=b"goldilocks-aes", size=32, from_id_key=True)
            if key is not None
            else b"\0" * 32
        )
        return _made(algo, ChunkerGoldilocksAES(gl_key, *params, normal_size=kw.get("normal_size", 0), sparse=sparse))
    if algo == "toeplitz-aes":
        # like rabin-aes, but with a tabulated LFSR/Toeplitz hash as the UHF
        # (secret 2 KiB table, fixed public polynomial). Same param shape:
        # (chunk_min_exp, chunk_max_exp, hash_mask_bits, nc_level).
        tp_key = (
            key.derive_key(salt=b"", domain=b"toeplitz-aes", size=32, from_id_key=True)
            if key is not None
            else b"\0" * 32
        )
        return _made(algo, ChunkerToeplitzAES(tp_key, *params, normal_size=kw.get("normal_size", 0), sparse=sparse))
    if algo == "fixed":
        return _made(algo, ChunkerFixed(*params, sparse=sparse))
    if algo == "fail":
        return _made(algo, ChunkerFailing(*params))
    raise TypeError("unsupported chunker algo %r" % algo)

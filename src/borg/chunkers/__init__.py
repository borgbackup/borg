from .buzhash import Chunker
from .buzhash64 import ChunkerBuzHash64
from .fastcdc import ChunkerFastCDC
from .rabin_aes import ChunkerRabinAES
from .goldilocks_aes import ChunkerGoldilocksAES
from .failing import ChunkerFailing
from .fixed import ChunkerFixed
from .reader import *  # noqa


def get_chunker(algo, *params, **kw):
    key = kw.get("key", None)
    sparse = kw.get("sparse", False)
    # key.chunk_seed only has 32 bits
    seed = key.chunk_seed if key is not None else 0
    if algo == "buzhash":
        return Chunker(seed, *params, sparse=sparse)
    if algo == "buzhash64":
        # for buzhash64, we want a much longer key, so we derive it from the id key.
        # params is (chunk_min_exp, chunk_max_exp, hash_mask_bits, hash_window_size, nc_level);
        # nc_level is passed positionally. normal_size is an optional tuning knob (0 = auto).
        bh64_key = (
            key.derive_key(salt=b"", domain=b"buzhash64", size=32, from_id_key=True) if key is not None else b"\0" * 32
        )
        return ChunkerBuzHash64(bh64_key, *params, normal_size=kw.get("normal_size", 0), sparse=sparse)
    if algo == "fastcdc":
        # keyed gear table, derived from the id key (own domain). params is
        # (chunk_min_exp, chunk_max_exp, hash_mask_bits, nc_level) - no window (Gear is window-less).
        fc_key = (
            key.derive_key(salt=b"", domain=b"fastcdc", size=32, from_id_key=True) if key is not None else b"\0" * 32
        )
        return ChunkerFastCDC(fc_key, *params, normal_size=kw.get("normal_size", 0), sparse=sparse)
    if algo == "rabin-aes":
        # UHF-then-PRF chunker (secret Rabin polynomial + AES-128), derived from
        # the id key (own domain). params is (chunk_min_exp, chunk_max_exp,
        # hash_mask_bits, nc_level) - no window param (fixed 64-byte window).
        ra_key = (
            key.derive_key(salt=b"", domain=b"rabin-aes", size=32, from_id_key=True) if key is not None else b"\0" * 32
        )
        return ChunkerRabinAES(ra_key, *params, normal_size=kw.get("normal_size", 0), sparse=sparse)
    if algo == "goldilocks-aes":
        # like rabin-aes, but with the Goldilocks prime-field polynomial hash as
        # the UHF (the reference construction of eprint 2025/558). Same param
        # shape: (chunk_min_exp, chunk_max_exp, hash_mask_bits, nc_level).
        gl_key = (
            key.derive_key(salt=b"", domain=b"goldilocks-aes", size=32, from_id_key=True)
            if key is not None
            else b"\0" * 32
        )
        return ChunkerGoldilocksAES(gl_key, *params, normal_size=kw.get("normal_size", 0), sparse=sparse)
    if algo == "fixed":
        return ChunkerFixed(*params, sparse=sparse)
    if algo == "fail":
        return ChunkerFailing(*params)
    raise TypeError("unsupported chunker algo %r" % algo)

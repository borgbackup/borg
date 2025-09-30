from .buzhash import Chunker
from .buzhash64 import ChunkerBuzHash64
from .failing import ChunkerFailing
from .fixed import ChunkerFixed
from .reader import *  # noqa

API_VERSION = "1.2_01"


def get_chunker(algo, *params, **kw):
    key = kw.get("key", None)
    sparse = kw.get("sparse", False)
    do_encrypt = kw.get("do_encrypt", 0)  # 0 is much faster, 1 is more secure
    # key.chunk_seed only has 32 bits
    seed = key.chunk_seed if key is not None else 0
    # for buzhash64, we want a much longer key, so we derive it from the id key
    bh64_key = (
        key.derive_key(salt=b"", domain=b"buzhash64", size=32, from_id_key=True) if key is not None else b"\0" * 32
    )
    if algo == "buzhash":
        return Chunker(seed, *params, sparse=sparse)
    if algo == "buzhash64":
        return ChunkerBuzHash64(bh64_key, *params, sparse=sparse, do_encrypt=do_encrypt)
    if algo == "fixed":
        return ChunkerFixed(*params, sparse=sparse)
    if algo == "fail":
        return ChunkerFailing(*params)
    raise TypeError("unsupported chunker algo %r" % algo)

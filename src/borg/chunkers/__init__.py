from .buzhash import Chunker
from .buzhash64 import ChunkerBuzHash64
from .failing import ChunkerFailing
from .fixed import ChunkerFixed
from .reader import *  # noqa
from ..crypto.key import PlaintextKey

API_VERSION = "1.2_01"


def get_chunker(algo, *params, **kw):
    key = kw.get("key", None)
    sparse = kw.get("sparse", False)
    # key.chunk_seed only has 32bits
    seed = key.chunk_seed if key is not None else 0
    # we want 64bits for buzhash64, get them from crypt_key
    if key is None or isinstance(key, PlaintextKey):
        seed64 = 0
    else:
        seed64 = int.from_bytes(key.crypt_key[:8], byteorder="little")
    if algo == "buzhash":
        return Chunker(seed, *params, sparse=sparse)
    if algo == "buzhash64":
        return ChunkerBuzHash64(seed64, *params, sparse=sparse)
    if algo == "fixed":
        return ChunkerFixed(*params, sparse=sparse)
    if algo == "fail":
        return ChunkerFailing(*params)
    raise TypeError("unsupported chunker algo %r" % algo)

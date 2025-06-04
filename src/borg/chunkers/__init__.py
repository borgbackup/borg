from .buzhash import Chunker
from .failing import ChunkerFailing
from .fixed import ChunkerFixed
from .reader import *  # noqa

API_VERSION = "1.2_01"


def get_chunker(algo, *params, **kw):
    if algo == "buzhash":
        seed = kw["seed"]
        sparse = kw["sparse"]
        return Chunker(seed, *params, sparse=sparse)
    if algo == "fixed":
        sparse = kw["sparse"]
        return ChunkerFixed(*params, sparse=sparse)
    if algo == "fail":
        return ChunkerFailing(*params)
    raise TypeError("unsupported chunker algo %r" % algo)

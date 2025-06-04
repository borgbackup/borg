from .chunker import *  # noqa
from .reader import *  # noqa


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

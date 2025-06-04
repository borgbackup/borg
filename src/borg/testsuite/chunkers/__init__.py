from borg.constants import *  # noqa


def cf(chunks):
    """chunk filter"""

    # this is to simplify testing: either return the data piece (bytes) or the hole length (int).
    def _cf(chunk):
        if chunk.meta["allocation"] == CH_DATA:
            assert len(chunk.data) == chunk.meta["size"]
            return bytes(chunk.data)  # make sure we have bytes, not memoryview
        if chunk.meta["allocation"] in (CH_HOLE, CH_ALLOC):
            assert chunk.data is None
            return chunk.meta["size"]
        assert False, "unexpected allocation value"

    return [_cf(chunk) for chunk in chunks]

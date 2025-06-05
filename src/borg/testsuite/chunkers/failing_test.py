from io import BytesIO

import pytest

from ...chunkers import ChunkerFailing
from ...constants import *  # NOQA


def test_chunker_failing():
    SIZE = 4096
    data = bytes(2 * SIZE + 1000)
    chunker = ChunkerFailing(SIZE, "rEErrr")  # cut <SIZE> chunks, start failing at block 1, fail 2 times
    with BytesIO(data) as fd:
        ch = chunker.chunkify(fd)
        c1 = next(ch)  # block 0: ok
        assert c1.meta["allocation"] == CH_DATA
        assert c1.data == data[:SIZE]
        with pytest.raises(OSError):  # block 1: failure 1
            next(ch)
    with BytesIO(data) as fd:
        ch = chunker.chunkify(fd)
        with pytest.raises(OSError):  # block 2: failure 2
            next(ch)
    with BytesIO(data) as fd:
        ch = chunker.chunkify(fd)
        c1 = next(ch)  # block 3: success!
        c2 = next(ch)  # block 4: success!
        c3 = next(ch)  # block 5: success!
        assert c1.meta["allocation"] == c2.meta["allocation"] == c3.meta["allocation"] == CH_DATA
        assert c1.data == data[:SIZE]
        assert c2.data == data[SIZE : 2 * SIZE]
        assert c3.data == data[2 * SIZE :]

from argparse import ArgumentTypeError

import pytest

from ..constants import *  # NOQA
from ..helpers import ChunkerParams


@pytest.mark.parametrize(
    "chunker_params, expected_return",
    [
        ("default", ("buzhash", 19, 23, 21, 4095)),
        ("19,23,21,4095", ("buzhash", 19, 23, 21, 4095)),
        ("buzhash,19,23,21,4095", ("buzhash", 19, 23, 21, 4095)),
        ("10,23,16,4095", ("buzhash", 10, 23, 16, 4095)),
        ("fixed,4096", ("fixed", 4096, 0)),
        ("fixed,4096,200", ("fixed", 4096, 200)),
    ],
)
def test_valid_chunkerparams(chunker_params, expected_return):
    assert ChunkerParams(chunker_params) == expected_return


@pytest.mark.parametrize(
    "invalid_chunker_params",
    [
        "crap,1,2,3,4",  # invalid algo
        "buzhash,5,7,6,4095",  # too small min. size
        "buzhash,19,24,21,4095",  # too big max. size
        "buzhash,23,19,21,4095",  # violates min <= mask <= max
        "fixed,63",  # too small block size
        "fixed,%d,%d" % (MAX_DATA_SIZE + 1, 4096),  # too big block size
        "fixed,%d,%d" % (4096, MAX_DATA_SIZE + 1),  # too big header size
    ],
)
def test_invalid_chunkerparams(invalid_chunker_params):
    with pytest.raises(ArgumentTypeError):
        ChunkerParams(invalid_chunker_params)

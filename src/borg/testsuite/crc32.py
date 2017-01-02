import os
import zlib

import pytest

from .. import crc32

crc32_implementations = [crc32.crc32_slice_by_8]
if crc32.have_clmul:
    crc32_implementations.append(crc32.crc32_clmul)


@pytest.mark.parametrize('implementation', crc32_implementations)
def test_crc32(implementation):
    # This includes many critical values, like zero length, 3/4/5, 6/7/8 and so on which are near and on
    # alignment boundaries. This is of course just a sanity check ie. "did it compile all right?".
    data = os.urandom(256)
    initial_crc = 0x12345678
    for i in range(0, 256):
        d = data[:i]
        assert zlib.crc32(d, initial_crc) == implementation(d, initial_crc)

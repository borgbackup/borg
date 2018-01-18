import os
import zlib
from binascii import unhexlify

import pytest

from ..algorithms import checksums
from ..helpers import bin_to_hex

crc32_implementations = [checksums.crc32_slice_by_8]
if checksums.have_clmul:
    crc32_implementations.append(checksums.crc32_clmul)


@pytest.mark.parametrize('implementation', crc32_implementations)
def test_crc32(implementation):
    # This includes many critical values, like misc. length and misc. aligned start addresses.
    data = os.urandom(300)
    mv = memoryview(data)
    initial_crc = 0x12345678
    for start in range(0, 4):  # 4B / int32 alignment, head processing
        for length in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                       31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
                       63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73,
                       127, 128, 129, 130, 131, 132, 133, 134, 135,
                       255, 256, 257, ]:
            d = mv[start:start+length]
            assert zlib.crc32(d, initial_crc) == implementation(d, initial_crc)


def test_xxh64():
    assert bin_to_hex(checksums.xxh64(b'test', 123)) == '2b81b9401bef86cf'
    assert bin_to_hex(checksums.xxh64(b'test')) == '4fdcca5ddb678139'
    assert bin_to_hex(checksums.xxh64(unhexlify(
        '6f663f01c118abdea553373d5eae44e7dac3b6829b46b9bbeff202b6c592c22d724'
        'fb3d25a347cca6c5b8f20d567e4bb04b9cfa85d17f691590f9a9d32e8ccc9102e9d'
        'cf8a7e6716280cd642ce48d03fdf114c9f57c20d9472bb0f81c147645e6fa3d331'))) == '35d5d2f545d9511a'


def test_streaming_xxh64():
    hasher = checksums.StreamingXXH64(123)
    hasher.update(b'te')
    hasher.update(b'st')
    assert bin_to_hex(hasher.digest()) == hasher.hexdigest() == '2b81b9401bef86cf'

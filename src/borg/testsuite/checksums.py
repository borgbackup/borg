from binascii import unhexlify

from .. import checksums
from ..helpers import bin_to_hex


def test_xxh64():
    assert bin_to_hex(checksums.xxh64(b"test", 123)) == "2b81b9401bef86cf"
    assert bin_to_hex(checksums.xxh64(b"test")) == "4fdcca5ddb678139"
    assert (
        bin_to_hex(
            checksums.xxh64(
                unhexlify(
                    "6f663f01c118abdea553373d5eae44e7dac3b6829b46b9bbeff202b6c592c22d724"
                    "fb3d25a347cca6c5b8f20d567e4bb04b9cfa85d17f691590f9a9d32e8ccc9102e9d"
                    "cf8a7e6716280cd642ce48d03fdf114c9f57c20d9472bb0f81c147645e6fa3d331"
                )
            )
        )
        == "35d5d2f545d9511a"
    )


def test_streaming_xxh64():
    hasher = checksums.StreamingXXH64(123)
    hasher.update(b"te")
    hasher.update(b"st")
    assert bin_to_hex(hasher.digest()) == hasher.hexdigest() == "2b81b9401bef86cf"

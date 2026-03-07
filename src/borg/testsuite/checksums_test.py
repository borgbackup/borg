from xxhash import xxh64

from ..helpers import hex_to_bin


def test_xxh64():
    assert xxh64(b"test", 123).hexdigest() == "2b81b9401bef86cf"
    assert xxh64(b"test").hexdigest() == "4fdcca5ddb678139"
    assert (
        xxh64(
            hex_to_bin(
                "6f663f01c118abdea553373d5eae44e7dac3b6829b46b9bbeff202b6c592c22d724"
                "fb3d25a347cca6c5b8f20d567e4bb04b9cfa85d17f691590f9a9d32e8ccc9102e9d"
                "cf8a7e6716280cd642ce48d03fdf114c9f57c20d9472bb0f81c147645e6fa3d331"
            )
        ).hexdigest()
        == "35d5d2f545d9511a"
    )

    hasher = xxh64(seed=123)
    hasher.update(b"te")
    hasher.update(b"st")
    assert hasher.hexdigest() == "2b81b9401bef86cf"

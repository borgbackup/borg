import pytest

import msgpack

from ..msg_pack import packb, unpackb, is_slow


def test_is_slow():
    saved_packer = msgpack.Packer
    try:
        msgpack.Packer = msgpack.fallback.Packer
        assert is_slow()
    finally:
        msgpack.Packer = saved_packer
    # this assumes that we have fast msgpack on test platform:
    assert not is_slow()


def test_msg_pack_roundtrip():
    # this is how the new code works, easily roundtripping bytes and str
    data = b'bytes-ascii\x00'
    assert data == unpackb(packb(data))
    data = b'bytes-arbitrary-\xe4\xf6\xfc\x00'
    assert data == unpackb(packb(data))
    data = 'text-ascii\u0000'
    assert data == unpackb(packb(data))
    data = 'text-unicode-äöü\u0000'
    assert data == unpackb(packb(data))


def test_msgpack_roundtrip():
    # this is how the old code works (directly using msgpack)
    # str needs addtl. decode to round-trip
    data = 'text-unicode-äöü\u0000'
    assert msgpack.unpackb(msgpack.packb(data)).decode('utf-8') == data
    # bytes do roundtrip without addtl. effort
    data = b'bytes-arbitrary-\xe4\xf6\xfc\x00'
    assert msgpack.unpackb(msgpack.packb(data)) == data


def test_compat_keys():
    key_old = b'keyname'  # old code item dict key
    key_new = 'keyname'  # new code item dict key
    # old code with old key produces same output as new code with new key
    assert msgpack.packb(key_old) == packb(key_new)


def test_compat_values_str():
    # old and new code produce same output for str
    value = 'str-ascii'
    assert msgpack.packb(value) == packb(value)
    value = 'str-unicode-äöü\u0000'
    assert msgpack.packb(value) == packb(value)


@pytest.mark.xfail(reason="impossible, bytes must serialize differently now from str to have clean roundtrip")
def test_compat_values_bytes():
    # old and new code do NOT produce same output for bytes
    value = b'bytes-ascii'
    assert msgpack.packb(value) == packb(value)
    value = b'bytes-arbitrary-\xe4\xf6\xfc\x00'
    assert msgpack.packb(value) == packb(value)

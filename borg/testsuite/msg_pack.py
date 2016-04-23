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
    data = b'bytes-ascii\x00'
    assert data == unpackb(packb(data))
    data = b'bytes-arbitrary-\xe4\xf6\xfc\x00'
    assert data == unpackb(packb(data))
    data = 'text-ascii\u0000'
    assert data == unpackb(packb(data))
    data = 'text-unicode-äöü\u0000'
    assert data == unpackb(packb(data))

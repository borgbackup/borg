import zlib
try:
    import lzma
except ImportError:
    lzma = None

import pytest

from ..compress import get_compressor, Compressor, CNULL, ZLIB, LZ4


buffer = bytes(2**16)
data = b'fooooooooobaaaaaaaar' * 10
params = dict(name='zlib', level=6, buffer=buffer)


def test_get_compressor():
    c = get_compressor(name='null')
    assert isinstance(c, CNULL)
    c = get_compressor(name='lz4', buffer=buffer)
    assert isinstance(c, LZ4)
    c = get_compressor(name='zlib')
    assert isinstance(c, ZLIB)
    with pytest.raises(KeyError):
        get_compressor(name='foobar')


def test_cnull():
    c = get_compressor(name='null')
    cdata = c.compress(data)
    assert len(cdata) > len(data)
    assert data in cdata  # it's not compressed and just in there 1:1
    assert data == c.decompress(cdata)
    assert data == Compressor(**params).decompress(cdata)  # autodetect


def test_lz4():
    c = get_compressor(name='lz4', buffer=buffer)
    cdata = c.compress(data)
    assert len(cdata) < len(data)
    assert data == c.decompress(cdata)
    assert data == Compressor(**params).decompress(cdata)  # autodetect


def test_zlib():
    c = get_compressor(name='zlib')
    cdata = c.compress(data)
    assert len(cdata) < len(data)
    assert data == c.decompress(cdata)
    assert data == Compressor(**params).decompress(cdata)  # autodetect


def test_lzma():
    if lzma is None:
        pytest.skip("No lzma support found.")
    c = get_compressor(name='lzma')
    cdata = c.compress(data)
    assert len(cdata) < len(data)
    assert data == c.decompress(cdata)
    assert data == Compressor(**params).decompress(cdata)  # autodetect


def test_autodetect_invalid():
    with pytest.raises(ValueError):
        Compressor(**params).decompress(b'\xff\xfftotalcrap')
    with pytest.raises(ValueError):
        Compressor(**params).decompress(b'\x08\x00notreallyzlib')


def test_zlib_compat():
    # for compatibility reasons, we do not add an extra header for zlib,
    # nor do we expect one when decompressing / autodetecting
    for level in range(10):
        c = get_compressor(name='zlib', level=level)
        cdata1 = c.compress(data)
        cdata2 = zlib.compress(data, level)
        assert cdata1 == cdata2
        data2 = c.decompress(cdata2)
        assert data == data2
        data2 = Compressor(**params).decompress(cdata2)
        assert data == data2


def test_compressor():
    params_list = [
        dict(name='null', buffer=buffer),
        dict(name='lz4', buffer=buffer),
        dict(name='zlib', level=0, buffer=buffer),
        dict(name='zlib', level=6, buffer=buffer),
        dict(name='zlib', level=9, buffer=buffer),
    ]
    if lzma:
        params_list += [
            dict(name='lzma', level=0, buffer=buffer),
            dict(name='lzma', level=6, buffer=buffer),
            dict(name='lzma', level=9, buffer=buffer),
        ]
    for params in params_list:
        c = Compressor(**params)
        assert data == c.decompress(c.compress(data))



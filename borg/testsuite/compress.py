import os
import zlib
try:
    import lzma
except ImportError:
    lzma = None

import pytest

from ..compress import get_compressor, Compressor, CNONE, ZLIB, LZ4


buffer = bytes(2**16)
data = b'fooooooooobaaaaaaaar' * 10
params = dict(name='zlib', level=6)


def test_get_compressor():
    c = get_compressor(name='none')
    assert isinstance(c, CNONE)
    c = get_compressor(name='lz4')
    assert isinstance(c, LZ4)
    c = get_compressor(name='zlib')
    assert isinstance(c, ZLIB)
    with pytest.raises(KeyError):
        get_compressor(name='foobar')


def test_cnull():
    c = get_compressor(name='none')
    cdata = c.compress(data)
    assert len(cdata) > len(data)
    assert data in cdata  # it's not compressed and just in there 1:1
    assert data == c.decompress(cdata)
    assert data == Compressor(**params).decompress(cdata)  # autodetect


def test_lz4():
    c = get_compressor(name='lz4')
    cdata = c.compress(data)
    assert len(cdata) < len(data)
    assert data == c.decompress(cdata)
    assert data == Compressor(**params).decompress(cdata)  # autodetect


def test_lz4_buffer_allocation():
    # test with a rather huge data object to see if buffer allocation / resizing works
    data = os.urandom(50 * 2**20)  # 50MiB incompressible data
    c = get_compressor(name='lz4')
    cdata = c.compress(data)
    assert data == c.decompress(cdata)


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
        dict(name='none'),
        dict(name='lz4'),
        dict(name='zlib', level=0),
        dict(name='zlib', level=6),
        dict(name='zlib', level=9),
    ]
    if lzma:
        params_list += [
            dict(name='lzma', level=0),
            dict(name='lzma', level=6),
            # we do not test lzma on level 9 because of the huge memory needs
        ]
    for params in params_list:
        c = Compressor(**params)
        assert data == c.decompress(c.compress(data))

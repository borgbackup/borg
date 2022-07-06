import os
import zlib

try:
    import lzma
except ImportError:
    lzma = None

import pytest

from ..compress import get_compressor, Compressor, CompressionSpec, CNONE, ZLIB, LZ4, LZMA, ZSTD, Auto


buffer = bytes(2**16)
data = b"fooooooooobaaaaaaaar" * 10
params = dict(name="zlib", level=6)


def test_get_compressor():
    c = get_compressor(name="none")
    assert isinstance(c, CNONE)
    c = get_compressor(name="lz4")
    assert isinstance(c, LZ4)
    c = get_compressor(name="zlib")
    assert isinstance(c, ZLIB)
    with pytest.raises(KeyError):
        get_compressor(name="foobar")


def test_cnull():
    c = get_compressor(name="none")
    cdata = c.compress(data)
    assert len(cdata) > len(data)
    assert data in cdata  # it's not compressed and just in there 1:1
    assert data == c.decompress(cdata)
    assert data == Compressor(**params).decompress(cdata)  # autodetect


def test_lz4():
    c = get_compressor(name="lz4")
    cdata = c.compress(data)
    assert len(cdata) < len(data)
    assert data == c.decompress(cdata)
    assert data == Compressor(**params).decompress(cdata)  # autodetect


def test_lz4_buffer_allocation(monkeypatch):
    # disable fallback to no compression on incompressible data
    monkeypatch.setattr(LZ4, "decide", lambda always_compress: LZ4)
    # test with a rather huge data object to see if buffer allocation / resizing works
    data = os.urandom(5 * 2**20) * 10  # 50MiB badly compressible data
    assert len(data) == 50 * 2**20
    c = Compressor("lz4")
    cdata = c.compress(data)
    assert len(cdata) > len(data)
    assert data == c.decompress(cdata)


def test_zlib():
    c = get_compressor(name="zlib")
    cdata = c.compress(data)
    assert len(cdata) < len(data)
    assert data == c.decompress(cdata)
    assert data == Compressor(**params).decompress(cdata)  # autodetect


def test_lzma():
    if lzma is None:
        pytest.skip("No lzma support found.")
    c = get_compressor(name="lzma")
    cdata = c.compress(data)
    assert len(cdata) < len(data)
    assert data == c.decompress(cdata)
    assert data == Compressor(**params).decompress(cdata)  # autodetect


def test_zstd():
    c = get_compressor(name="zstd")
    cdata = c.compress(data)
    assert len(cdata) < len(data)
    assert data == c.decompress(cdata)
    assert data == Compressor(**params).decompress(cdata)  # autodetect


def test_autodetect_invalid():
    with pytest.raises(ValueError):
        Compressor(**params).decompress(b"\xff\xfftotalcrap")
    with pytest.raises(ValueError):
        Compressor(**params).decompress(b"\x08\x00notreallyzlib")


def test_zlib_legacy_compat():
    # for compatibility reasons, we do not add an extra header for zlib,
    # nor do we expect one when decompressing / autodetecting
    for level in range(10):
        c = get_compressor(name="zlib_legacy", level=level)
        cdata1 = c.compress(data)
        cdata2 = zlib.compress(data, level)
        assert cdata1 == cdata2
        data2 = c.decompress(cdata2)
        assert data == data2
        data2 = Compressor(**params).decompress(cdata2)
        assert data == data2


def test_compressor():
    params_list = [
        dict(name="none"),
        dict(name="lz4"),
        dict(name="zstd", level=1),
        dict(name="zstd", level=3),
        # avoiding high zstd levels, memory needs unclear
        dict(name="zlib", level=0),
        dict(name="zlib", level=6),
        dict(name="zlib", level=9),
    ]
    if lzma:
        params_list += [
            dict(name="lzma", level=0),
            dict(name="lzma", level=6),
            # we do not test lzma on level 9 because of the huge memory needs
        ]
    for params in params_list:
        c = Compressor(**params)
        assert data == c.decompress(c.compress(data))


def test_auto():
    compressor_auto_zlib = CompressionSpec("auto,zlib,9").compressor
    compressor_lz4 = CompressionSpec("lz4").compressor
    compressor_zlib = CompressionSpec("zlib,9").compressor
    data = bytes(500)
    compressed_auto_zlib = compressor_auto_zlib.compress(data)
    compressed_lz4 = compressor_lz4.compress(data)
    compressed_zlib = compressor_zlib.compress(data)
    ratio = len(compressed_zlib) / len(compressed_lz4)
    assert Compressor.detect(compressed_auto_zlib)[0] == ZLIB if ratio < 0.99 else LZ4

    data = b"\x00\xb8\xa3\xa2-O\xe1i\xb6\x12\x03\xc21\xf3\x8a\xf78\\\x01\xa5b\x07\x95\xbeE\xf8\xa3\x9ahm\xb1~"
    compressed = compressor_auto_zlib.compress(data)
    assert Compressor.detect(compressed)[0] == CNONE


def test_obfuscate():
    compressor = CompressionSpec("obfuscate,1,none").compressor
    data = bytes(10000)
    compressed = compressor.compress(data)
    # 2 id bytes compression, 2 id bytes obfuscator. 4 length bytes
    assert len(data) + 8 <= len(compressed) <= len(data) * 101 + 8
    # compressing 100 times the same data should give at least 50 different result sizes
    assert len({len(compressor.compress(data)) for i in range(100)}) > 50

    cs = CompressionSpec("obfuscate,2,lz4")
    assert isinstance(cs.inner.compressor, LZ4)
    compressor = cs.compressor
    data = bytes(10000)
    compressed = compressor.compress(data)
    # 2 id bytes compression, 2 id bytes obfuscator. 4 length bytes
    min_compress, max_compress = 0.2, 0.001  # estimate compression factor outer boundaries
    assert max_compress * len(data) + 8 <= len(compressed) <= min_compress * len(data) * 1001 + 8
    # compressing 100 times the same data should give multiple different result sizes
    assert len({len(compressor.compress(data)) for i in range(100)}) > 10

    cs = CompressionSpec("obfuscate,6,zstd,3")
    assert isinstance(cs.inner.compressor, ZSTD)
    compressor = cs.compressor
    data = bytes(10000)
    compressed = compressor.compress(data)
    # 2 id bytes compression, 2 id bytes obfuscator. 4 length bytes
    min_compress, max_compress = 0.2, 0.001  # estimate compression factor outer boundaries
    assert max_compress * len(data) + 8 <= len(compressed) <= min_compress * len(data) * 10000001 + 8
    # compressing 100 times the same data should give multiple different result sizes
    assert len({len(compressor.compress(data)) for i in range(100)}) > 90

    cs = CompressionSpec("obfuscate,2,auto,zstd,10")
    assert isinstance(cs.inner.compressor, Auto)
    compressor = cs.compressor
    data = bytes(10000)
    compressed = compressor.compress(data)
    # 2 id bytes compression, 2 id bytes obfuscator. 4 length bytes
    min_compress, max_compress = 0.2, 0.001  # estimate compression factor outer boundaries
    assert max_compress * len(data) + 8 <= len(compressed) <= min_compress * len(data) * 1001 + 8
    # compressing 100 times the same data should give multiple different result sizes
    assert len({len(compressor.compress(data)) for i in range(100)}) > 10

    cs = CompressionSpec("obfuscate,110,none")
    assert isinstance(cs.inner.compressor, CNONE)
    compressor = cs.compressor
    data = bytes(1000)
    compressed = compressor.compress(data)
    # N blocks + 2 id bytes obfuscator. 4 length bytes
    # The 'none' compressor also adds 2 id bytes
    assert 6 + 2 + 1000 <= len(compressed) <= 6 + 2 + 1000 + 1024
    data = bytes(1100)
    compressed = compressor.compress(data)
    # N blocks + 2 id bytes obfuscator. 4 length bytes
    # The 'none' compressor also adds 2 id bytes
    assert 6 + 2 + 1100 <= len(compressed) <= 6 + 2 + 1100 + 1024


def test_compression_specs():
    with pytest.raises(ValueError):
        CompressionSpec("")

    assert isinstance(CompressionSpec("none").compressor, CNONE)
    assert isinstance(CompressionSpec("lz4").compressor, LZ4)

    zlib = CompressionSpec("zlib").compressor
    assert isinstance(zlib, ZLIB)
    assert zlib.level == 6
    zlib = CompressionSpec("zlib,0").compressor
    assert isinstance(zlib, ZLIB)
    assert zlib.level == 0
    zlib = CompressionSpec("zlib,9").compressor
    assert isinstance(zlib, ZLIB)
    assert zlib.level == 9
    with pytest.raises(ValueError):
        CompressionSpec("zlib,9,invalid")

    lzma = CompressionSpec("lzma").compressor
    assert isinstance(lzma, LZMA)
    assert lzma.level == 6
    lzma = CompressionSpec("lzma,0").compressor
    assert isinstance(lzma, LZMA)
    assert lzma.level == 0
    lzma = CompressionSpec("lzma,9").compressor
    assert isinstance(lzma, LZMA)
    assert lzma.level == 9

    zstd = CompressionSpec("zstd").compressor
    assert isinstance(zstd, ZSTD)
    assert zstd.level == 3
    zstd = CompressionSpec("zstd,1").compressor
    assert isinstance(zstd, ZSTD)
    assert zstd.level == 1
    zstd = CompressionSpec("zstd,22").compressor
    assert isinstance(zstd, ZSTD)
    assert zstd.level == 22

    with pytest.raises(ValueError):
        CompressionSpec("lzma,9,invalid")
    with pytest.raises(ValueError):
        CompressionSpec("invalid")

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
    meta, cdata = c.compress({}, data)
    assert len(cdata) >= len(data)
    assert data in cdata  # it's not compressed and just in there 1:1
    assert data == c.decompress(meta, cdata)[1]
    assert data == Compressor(**params).decompress(meta, cdata)[1]  # autodetect


def test_lz4():
    c = get_compressor(name="lz4")
    meta, cdata = c.compress({}, data)
    assert len(cdata) < len(data)
    assert data == c.decompress(meta, cdata)[1]
    assert data == Compressor(**params).decompress(meta, cdata)[1]  # autodetect


def test_lz4_buffer_allocation(monkeypatch):
    # disable fallback to no compression on incompressible data
    monkeypatch.setattr(LZ4, "decide", lambda always_compress: LZ4)
    # test with a rather huge data object to see if buffer allocation / resizing works
    data = os.urandom(5 * 2**20) * 10  # 50MiB badly compressible data
    assert len(data) == 50 * 2**20
    c = Compressor("lz4")
    meta, cdata = c.compress({}, data)
    assert len(cdata) >= len(data)
    assert data == c.decompress(meta, cdata)[1]


def test_zlib():
    c = get_compressor(name="zlib")
    meta, cdata = c.compress({}, data)
    assert len(cdata) < len(data)
    assert data == c.decompress(meta, cdata)[1]
    assert data == Compressor(**params).decompress(meta, cdata)[1]  # autodetect


def test_lzma():
    if lzma is None:
        pytest.skip("No lzma support found.")
    c = get_compressor(name="lzma")
    meta, cdata = c.compress({}, data)
    assert len(cdata) < len(data)
    assert data == c.decompress(meta, cdata)[1]
    assert data == Compressor(**params).decompress(meta, cdata)[1]  # autodetect


def test_zstd():
    c = get_compressor(name="zstd")
    meta, cdata = c.compress({}, data)
    assert len(cdata) < len(data)
    assert data == c.decompress(meta, cdata)[1]
    assert data == Compressor(**params).decompress(meta, cdata)[1]  # autodetect


def test_autodetect_invalid():
    with pytest.raises(ValueError):
        Compressor(**params, legacy_mode=True).decompress({}, b"\xff\xfftotalcrap")
    with pytest.raises(ValueError):
        Compressor(**params, legacy_mode=True).decompress({}, b"\x08\x00notreallyzlib")


def test_zlib_legacy_compat():
    # for compatibility reasons, we do not add an extra header for zlib,
    # nor do we expect one when decompressing / autodetecting
    for level in range(10):
        c = get_compressor(name="zlib_legacy", level=level, legacy_mode=True)
        meta1, cdata1 = c.compress({}, data)
        cdata2 = zlib.compress(data, level)
        assert cdata1 == cdata2
        meta2, data2 = c.decompress({}, cdata2)
        assert data == data2
        # _, data2 = Compressor(**params).decompress({}, cdata2)
        # assert data == data2


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
        meta_c, data_compressed = c.compress({}, data)
        assert "ctype" in meta_c
        assert "clevel" in meta_c
        assert meta_c["csize"] == len(data_compressed)
        assert meta_c["size"] == len(data)
        meta_d, data_decompressed = c.decompress(meta_c, data_compressed)
        assert data == data_decompressed
        assert "ctype" in meta_d
        assert "clevel" in meta_d
        assert meta_d["csize"] == len(data_compressed)
        assert meta_d["size"] == len(data)


def test_auto():
    compressor_auto_zlib = CompressionSpec("auto,zlib,9").compressor
    compressor_lz4 = CompressionSpec("lz4").compressor
    compressor_zlib = CompressionSpec("zlib,9").compressor
    data = bytes(500)
    meta, compressed_auto_zlib = compressor_auto_zlib.compress({}, data)
    _, compressed_lz4 = compressor_lz4.compress({}, data)
    _, compressed_zlib = compressor_zlib.compress({}, data)
    ratio = len(compressed_zlib) / len(compressed_lz4)
    assert meta["ctype"] == ZLIB.ID if ratio < 0.99 else LZ4.ID
    assert meta["clevel"] == 9 if ratio < 0.99 else 255
    assert meta["csize"] == len(compressed_auto_zlib)

    data = b"\x00\xb8\xa3\xa2-O\xe1i\xb6\x12\x03\xc21\xf3\x8a\xf78\\\x01\xa5b\x07\x95\xbeE\xf8\xa3\x9ahm\xb1~"
    meta, compressed = compressor_auto_zlib.compress(dict(meta), data)
    assert meta["ctype"] == CNONE.ID
    assert meta["clevel"] == 255
    assert meta["csize"] == len(compressed)


def test_obfuscate():
    compressor = CompressionSpec("obfuscate,1,none").compressor
    data = bytes(10000)
    _, compressed = compressor.compress({}, data)
    assert len(data) <= len(compressed) <= len(data) * 101
    # compressing 100 times the same data should give at least 50 different result sizes
    assert len({len(compressor.compress({}, data)[1]) for i in range(100)}) > 50

    cs = CompressionSpec("obfuscate,2,lz4")
    assert isinstance(cs.inner.compressor, LZ4)
    compressor = cs.compressor
    data = bytes(10000)
    _, compressed = compressor.compress({}, data)
    min_compress, max_compress = 0.2, 0.001  # estimate compression factor outer boundaries
    assert max_compress * len(data) <= len(compressed) <= min_compress * len(data) * 1001
    # compressing 100 times the same data should give multiple different result sizes
    assert len({len(compressor.compress({}, data)[1]) for i in range(100)}) > 10

    cs = CompressionSpec("obfuscate,6,zstd,3")
    assert isinstance(cs.inner.compressor, ZSTD)
    compressor = cs.compressor
    data = bytes(10000)
    _, compressed = compressor.compress({}, data)
    min_compress, max_compress = 0.2, 0.001  # estimate compression factor outer boundaries
    assert max_compress * len(data) <= len(compressed) <= min_compress * len(data) * 10000001
    # compressing 100 times the same data should give multiple different result sizes
    assert len({len(compressor.compress({}, data)[1]) for i in range(100)}) > 90

    cs = CompressionSpec("obfuscate,2,auto,zstd,10")
    assert isinstance(cs.inner.compressor, Auto)
    compressor = cs.compressor
    data = bytes(10000)
    _, compressed = compressor.compress({}, data)
    min_compress, max_compress = 0.2, 0.001  # estimate compression factor outer boundaries
    assert max_compress * len(data) <= len(compressed) <= min_compress * len(data) * 1001
    # compressing 100 times the same data should give multiple different result sizes
    assert len({len(compressor.compress({}, data)[1]) for i in range(100)}) > 10

    cs = CompressionSpec("obfuscate,110,none")
    assert isinstance(cs.inner.compressor, CNONE)
    compressor = cs.compressor
    data = bytes(1000)
    _, compressed = compressor.compress({}, data)
    assert 1000 <= len(compressed) <= 1000 + 1024
    data = bytes(1100)
    _, compressed = compressor.compress({}, data)
    assert 1100 <= len(compressed) <= 1100 + 1024


def test_obfuscate_meta():
    compressor = CompressionSpec("obfuscate,3,lz4").compressor
    meta_in = {}
    data = bytes(10000)
    meta_out, compressed = compressor.compress(meta_in, data)
    assert "ctype" not in meta_in  # do not modify dict of caller
    assert "ctype" in meta_out
    assert meta_out["ctype"] == LZ4.ID
    assert "clevel" in meta_out
    assert meta_out["clevel"] == 0xFF
    assert "csize" in meta_out
    csize = meta_out["csize"]
    assert csize == len(compressed)  # this is the overall size
    assert "psize" in meta_out
    psize = meta_out["psize"]
    assert 0 < psize < 100
    assert csize - psize >= 0  # there is a obfuscation trailer
    trailer = compressed[psize:]
    assert not trailer or set(trailer) == {0}  # trailer is all-zero-bytes


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

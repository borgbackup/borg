import argparse
import os
import zlib

import pytest

from ..compress import get_compressor, Compressor, CompressionSpec, CNONE, ZLIB, LZ4, LZMA, ZSTD, Auto

DATA = b"fooooooooobaaaaaaaar" * 10
params = dict(name="zlib", level=6)


@pytest.mark.parametrize(
    "c_type, expected_compressor",
    [("none", CNONE), ("lz4", LZ4), ("zlib", ZLIB), ("lzma", LZMA), ("zstd", ZSTD), ("foobar", None)],
)
def test_get_compressor(c_type, expected_compressor):
    if expected_compressor is not None:
        compressor = get_compressor(name=c_type)
        assert isinstance(compressor, expected_compressor)
    else:
        with pytest.raises(KeyError):
            get_compressor(name=c_type)


@pytest.mark.parametrize("c_type", ["none", "lz4", "zlib", "zstd", "lzma"])
def test_compression_types(c_type):
    c = get_compressor(name=c_type)
    meta, cdata = c.compress({}, DATA)
    if c_type == "none":
        assert len(cdata) >= len(DATA)  # it's not compressed and just in there 1:1
    else:
        assert len(cdata) < len(DATA)
    assert DATA == c.decompress(meta, cdata)[1]
    assert DATA == Compressor(**params).decompress(meta, cdata)[1]  # autodetect


def test_lz4_buffer_allocation(monkeypatch):
    # disable fallback to no compression on incompressible data
    monkeypatch.setattr(LZ4, "decide", lambda always_compress: LZ4)
    # test with a rather huge data object to see if buffer allocation / resizing works
    incompressible_data = os.urandom(5 * 2**20) * 10  # 50MiB badly compressible data
    c = Compressor("lz4")
    meta, cdata = c.compress({}, incompressible_data)
    assert len(incompressible_data) == 50 * 2**20
    assert len(cdata) >= len(incompressible_data)
    assert incompressible_data == c.decompress(meta, cdata)[1]


@pytest.mark.parametrize("invalid_cdata", [b"\xff\xfftotalcrap", b"\x08\x00notreallyzlib"])
def test_autodetect_invalid(invalid_cdata):
    with pytest.raises(ValueError):
        Compressor(**params, legacy_mode=True).decompress(None, invalid_cdata)


def test_zlib_legacy_compat():
    # for compatibility reasons, we do not add an extra header for zlib,
    # nor do we expect one when decompressing / auto-detecting
    for level in range(10):
        c = get_compressor(name="zlib_legacy", level=level, legacy_mode=True)
        meta1, cdata1 = c.compress({}, DATA)
        cdata2 = zlib.compress(DATA, level)
        assert cdata1 == cdata2
        meta2, data2 = c.decompress(None, cdata2)
        assert DATA == data2


@pytest.mark.parametrize(
    "c_params",
    [
        dict(name="none"),
        dict(name="lz4"),
        dict(name="zstd", level=1),
        dict(name="zstd", level=3),  # avoiding high zstd levels, memory needs unclear
        dict(name="zlib", level=0),
        dict(name="zlib", level=6),
        dict(name="zlib", level=9),
        dict(name="lzma", level=0),
        dict(name="lzma", level=6),  # we do not test lzma on level 9 because of the huge memory needs
    ],
)
def test_compressor(c_params):
    c = Compressor(**c_params)
    meta_c, data_compressed = c.compress({}, DATA)
    assert "ctype" in meta_c
    assert "clevel" in meta_c
    assert meta_c["csize"] == len(data_compressed)
    assert meta_c["size"] == len(DATA)
    meta_d, data_decompressed = c.decompress(meta_c, data_compressed)
    assert DATA == data_decompressed
    assert "ctype" in meta_d
    assert "clevel" in meta_d
    assert meta_d["csize"] == len(data_compressed)
    assert meta_d["size"] == len(DATA)


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
    smallest_csize = min(len(compressed_zlib), len(compressed_lz4))
    assert meta["csize"] == len(compressed_auto_zlib) == smallest_csize

    data = b"\x00\xb8\xa3\xa2-O\xe1i\xb6\x12\x03\xc21\xf3\x8a\xf78\\\x01\xa5b\x07\x95\xbeE\xf8\xa3\x9ahm\xb1~"
    meta, compressed = compressor_auto_zlib.compress(dict(meta), data)
    assert meta["ctype"] == CNONE.ID
    assert meta["clevel"] == 255
    assert meta["csize"] == len(compressed)


@pytest.mark.parametrize(
    "specs, c_type, result_range, obfuscation_factor",
    [
        ("obfuscate,1,none", CNONE, 50, 10**1),
        ("obfuscate,2,lz4", LZ4, 10, 10**2),
        ("obfuscate,6,zstd,3", ZSTD, 90, 10**6),
        ("obfuscate,2,auto,zstd,10", Auto, 10, 10**2),
    ],
)
def test_factor_obfuscation(specs, c_type, result_range, obfuscation_factor: int):
    # Testing relative random reciprocal size variation, obfuscation spec 1 to 6 inclusive
    # obfuscate_factor = 10**(obfuscation spec)
    cs = CompressionSpec(specs)
    assert isinstance(cs.inner.compressor, c_type)
    compressor = cs.compressor
    data = bytes(10000)
    _, compressed = compressor.compress({}, data)
    if c_type is CNONE:  # no compression
        assert len(data) <= len(compressed) <= len(data) * (10 * obfuscation_factor) + 1
    else:  # with compression
        min_compress, max_compress = 0.2, 0.001  # estimate compression factor outer boundaries
        assert max_compress * len(data) <= len(compressed) <= min_compress * len(data) * (10 * obfuscation_factor) + 1
    assert len({len(compressor.compress({}, data)[1]) for i in range(100)}) > result_range
    # compressing 100 times the same data should give multiple different result sizes


@pytest.mark.parametrize(
    "specs, c_type, obfuscation_padding",
    [
        ("obfuscate,110,none", CNONE, 2**10),  # up to 1KiB padding
        ("obfuscate,120,lz4", LZ4, 2**20),  # up to 1MiB padding
        ("obfuscate,123,zstd,3", ZSTD, 2**23),  # max, up to 8MiB padding
    ],
)
def test_additive_obfuscation(specs, c_type, obfuscation_padding: int):
    # Testing randomly sized padding, obfuscation spec 110 to 123 inclusive
    # obfuscate_padding = 2 ** (obfuscation spec - 100)
    cs = CompressionSpec(specs)
    assert isinstance(cs.inner.compressor, c_type)
    compressor = cs.compressor
    data_list = (bytes(1000), bytes(1100))
    for data in data_list:
        _, compressed = compressor.compress({}, data)
        if c_type is CNONE:  # no compression
            assert len(data) <= len(compressed) <= len(data) + obfuscation_padding
        else:  # with compression
            min_compress, max_compress = 0.2, 0.001  # estimate compression factor outer boundaries
            assert max_compress * len(data) <= len(compressed) <= min_compress * len(data) * obfuscation_padding


def test_obfuscate_meta():
    compressor = CompressionSpec("obfuscate,3,lz4").compressor
    data = bytes(10000)
    meta, compressed = compressor.compress({}, data)
    assert "ctype" in meta
    assert meta["ctype"] == LZ4.ID
    assert "clevel" in meta
    assert meta["clevel"] == 0xFF
    assert "csize" in meta
    csize = meta["csize"]
    assert csize == len(compressed)  # this is the overall size
    assert "psize" in meta
    psize = meta["psize"]
    assert 0 < psize < 100
    assert csize - psize >= 0  # there is an obfuscation trailer
    trailer = compressed[psize:]
    assert not trailer or set(trailer) == {0}  # trailer is all-zero-bytes


@pytest.mark.parametrize(
    "c_type, c_name", [(CNONE, "none"), (LZ4, "lz4"), (ZLIB, "zlib"), (LZMA, "lzma"), (ZSTD, "zstd")]
)
def test_default_compression_level(c_type, c_name):
    cs = CompressionSpec(c_name).compressor
    assert isinstance(cs, c_type)
    if c_type in (ZLIB, LZMA):
        assert cs.level == 6
    elif c_type is ZSTD:
        assert cs.level == 3


@pytest.mark.parametrize(
    "c_type, c_name, c_levels", [(ZLIB, "zlib", [0, 9]), (LZMA, "lzma", [0, 9]), (ZSTD, "zstd", [1, 22])]
)
def test_specified_compression_level(c_type, c_name, c_levels):
    for level in c_levels:
        cs = CompressionSpec(f"{c_name},{level}").compressor
        assert isinstance(cs, c_type)
        assert cs.level == level


@pytest.mark.parametrize("invalid_spec", ["", "lzma,9,invalid", "invalid"])
def test_invalid_compression_level(invalid_spec):
    with pytest.raises(argparse.ArgumentTypeError):
        CompressionSpec(invalid_spec)


@pytest.mark.parametrize(
    "data_length, expected_padding",
    [
        (0, 0),
        (1, 0),
        (10, 0),
        (100, 4),
        (1000, 24),
        (10000, 240),
        (20000, 480),
        (50000, 1200),
        (100000, 352),
        (1000000, 15808),
        (5000000, 111808),
        (10000000, 223616),
        (20000000, 447232),
    ],
)
def test_padme_obfuscation(data_length, expected_padding):
    compressor = Compressor(name="obfuscate", level=250, compressor=Compressor("none"))
    data = b"x" * data_length
    meta, compressed = compressor.compress({}, data)

    expected_padded_size = data_length + expected_padding

    assert (
        len(compressed) == expected_padded_size
    ), f"For {data_length}, expected {expected_padded_size}, got {len(compressed)}"

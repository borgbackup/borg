import os
import random
import zlib
from concurrent.futures import ThreadPoolExecutor

import pytest

from ..compress import get_compressor, Compressor, CNONE, ZLIB, LZ4, LZMA, ZSTD, Auto
from ..compress import get_zstd_mt_workers, get_zstd_compressor, forget_zstd_compressors
from ..compress import ZSTD_JOB_SIZE_MIN, ZSTD_MT_MIN_SIZE
from ..helpers import Error
from ..helpers import CompressionSpec
from ..constants import ROBJ_FILE_STREAM, ROBJ_ARCHIVE_META
from ..helpers.argparsing import ArgumentTypeError

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


def test_lz4_threaded():
    # LZ4 must not share one scratch buffer between threads, see issue #10032.
    # Without a per-thread buffer, concurrent (de)compression silently produces wrong
    # output: the threads write their results into the same bytearray.
    threads = 8
    rounds = 50

    def make_data(seed):
        # compressible (so that lz4 does not bail out to "no compression"), but distinct
        # per thread, so that output of one thread showing up in another one is detected.
        rnd = random.Random(seed)
        words = [bytes([rnd.randrange(256)]) * 64 for _ in range(16)]
        data = bytearray()
        while len(data) < 2**20:
            data += rnd.choice(words)
        return bytes(data)

    def roundtrip(seed):
        c = Compressor("lz4")
        data = make_data(seed)
        for _ in range(rounds):
            meta, cdata = c.compress({}, data)
            assert c.decompress(meta, cdata)[1] == data

    with ThreadPoolExecutor(max_workers=threads) as executor:
        # list() so that exceptions raised in the worker threads are re-raised here
        list(executor.map(roundtrip, range(threads)))


@pytest.mark.parametrize("invalid_cdata", [b"\xff\xfftotalcrap", b"\x08\x00notreallyzlib"])
def test_autodetect_invalid(invalid_cdata):
    with pytest.raises(ValueError):
        Compressor(**params, legacy_mode=True).decompress(None, invalid_cdata)


def test_zlib_legacy_compat():
    # For compatibility reasons, we do not add an extra header for zlib,
    # nor do we expect one when decompressing / auto-detecting.
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
    _, compressed = compressor.compress(dict(type=ROBJ_FILE_STREAM), data)
    if c_type is CNONE:  # no compression
        assert len(data) <= len(compressed) <= len(data) * (10 * obfuscation_factor) + 1
    else:  # with compression
        min_compress, max_compress = 0.2, 0.001  # estimate compression factor outer boundaries
        assert max_compress * len(data) <= len(compressed) <= min_compress * len(data) * (10 * obfuscation_factor) + 1
    assert len({len(compressor.compress(dict(type=ROBJ_FILE_STREAM), data)[1]) for i in range(100)}) > result_range
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
        _, compressed = compressor.compress(dict(type=ROBJ_FILE_STREAM), data)
        if c_type is CNONE:  # no compression
            assert len(data) <= len(compressed) <= len(data) + obfuscation_padding
        else:  # with compression
            min_compress, max_compress = 0.2, 0.001  # estimate compression factor outer boundaries
            assert max_compress * len(data) <= len(compressed) <= min_compress * len(data) * obfuscation_padding


def test_obfuscate_meta():
    compressor = CompressionSpec("obfuscate,3,lz4").compressor
    data = bytes(10000)
    meta, compressed = compressor.compress(dict(type=ROBJ_FILE_STREAM), data)
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
    "c_type, c_name, c_levels",
    [(ZLIB, "zlib", [0, 9]), (LZMA, "lzma", [0, 9]), (ZSTD, "zstd", [-128, -22, -4, -1, 1, 22])],
)
def test_specified_compression_level(c_type, c_name, c_levels):
    for level in c_levels:
        cs = CompressionSpec(f"{c_name},{level}").compressor
        assert isinstance(cs, c_type)
        assert cs.level == level


@pytest.mark.parametrize("invalid_spec", ["", "lzma,9,invalid", "invalid", "zstd,-129", "zstd,23"])
def test_invalid_compression_level(invalid_spec):
    with pytest.raises(ArgumentTypeError):
        CompressionSpec(invalid_spec)


@pytest.mark.parametrize("level, clevel", [(22, 22), (3, 3), (1, 1), (-1, 255), (-4, 252), (-22, 234), (-128, 128)])
def test_zstd_level_encoding(level, clevel):
    """The clevel byte is an int8_t for zstd, and levels 1..22 keep the byte they always had."""
    assert ZSTD.encode_level(level) == clevel
    assert ZSTD.decode_level(clevel) == level
    # the autodetection has to hand back the decoded (possibly negative) level
    assert Compressor.detect(bytes((ZSTD.ID, clevel))) == (ZSTD, level)


@pytest.mark.parametrize("level", [-128, -22, -4, -1, 1, 3, 22])
def test_zstd_level_roundtrip(level):
    data = bytes(bytearray(range(256))) * 400
    compressor = CompressionSpec(f"zstd,{level}").compressor
    meta, compressed = compressor.compress({}, data)
    assert meta["clevel"] == ZSTD.encode_level(level)
    # decompress via the autodetecting Compressor, i.e. the way a repo object is read back
    meta, decompressed = Compressor("zstd").decompress(dict(meta), compressed)
    assert decompressed == data


@pytest.mark.parametrize("level", [-128, -4, -1, 3])
def test_zstd_level_roundtrip_legacy_mode(level):
    data = bytes(bytearray(range(256))) * 400
    compressor = ZSTD(level=level, legacy_mode=True)
    # legacy mode returns meta None, but compress() still needs a dict to put "size" into
    meta, compressed = compressor.compress({}, data)
    assert compressed[:2] == bytes((ZSTD.ID, ZSTD.encode_level(level)))
    meta, decompressed = Compressor("zstd", legacy_mode=True).decompress(None, compressed)
    assert decompressed == data


def test_other_compressors_keep_their_level_byte():
    """Only zstd reinterprets the byte - everything else must store exactly what it did before."""
    for cls in (CNONE, LZ4, ZLIB, LZMA):
        assert cls.encode_level(255) == 255
        assert cls.decode_level(255) == 255
        for level in (0, 6, 9):
            assert cls.encode_level(level) == level
            assert cls.decode_level(level) == level


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
    compressor = CompressionSpec("obfuscate,250,none").compressor
    data = b"x" * data_length
    meta, compressed = compressor.compress(dict(type=ROBJ_FILE_STREAM), data)

    expected_padded_size = data_length + expected_padding

    assert (
        len(compressed) == expected_padded_size
    ), f"For {data_length}, expected {expected_padded_size}, got {len(compressed)}"


@pytest.mark.parametrize(
    "data_length, expected_padding, robj_type",
    [
        (1000000, 15808, ROBJ_FILE_STREAM),  # we want to obfuscate file content chunk sizes
        (1000000, 0, ROBJ_ARCHIVE_META),  # we do not want to obfuscate metadata chunk sizes
    ],
)
def test_robj_specific_obfuscation(data_length, expected_padding, robj_type):
    compressor = CompressionSpec("obfuscate,250,none").compressor
    data = b"x" * data_length
    meta, compressed = compressor.compress(dict(type=robj_type), data)

    expected_padded_size = data_length + expected_padding

    assert (
        len(compressed) == expected_padded_size
    ), f"For {data_length}, expected {expected_padded_size}, got {len(compressed)}"


def test_zstd_mt_workers_from_env(monkeypatch):
    def workers_for(env_value, stream=False):
        monkeypatch.setattr("borg.compress._zstd_mt_workers", None)  # drop the cache
        if env_value is None:
            monkeypatch.delenv("BORG_ZSTD_MT_WORKERS", raising=False)
        else:
            monkeypatch.setenv("BORG_ZSTD_MT_WORKERS", env_value)
        return get_zstd_mt_workers(stream=stream)

    cpus = os.cpu_count() or 1
    assert workers_for(None) == min(cpus, 4)  # per-chunk default is capped
    assert workers_for(None, stream=True) == cpus  # stream default is not
    for empty in ["", " "]:  # an empty value is treated like an unset one
        assert workers_for(empty) == min(cpus, 4)
        assert workers_for(empty, stream=True) == cpus
    for value, expected in [("0", 0), ("1", 1), ("4", 4), ("12", 12)]:
        assert workers_for(value) == expected  # the env var is not capped
        assert workers_for(value, stream=True) == expected
    for invalid in ["yes", "4x", "1.5", "-1"]:
        with pytest.raises(Error):
            workers_for(invalid)


@pytest.fixture
def zstd_mt(monkeypatch):
    """Force the multithreaded zstd path on, whatever the machine's cpu count is."""
    monkeypatch.setattr("borg.compress._zstd_mt_workers", (4, 4))
    forget_zstd_compressors()  # do not inherit compressors cached by another test
    yield 4
    forget_zstd_compressors()


def mt_data(size=ZSTD_MT_MIN_SIZE):
    """Compressible data, big enough for the MT path to engage."""
    rnd = random.Random(0)
    words = [b"borg", b"backup", b"chunk", b"compress", b"zstd"]
    out = bytearray()
    while len(out) < size:
        out += rnd.choice(words)
    return bytes(out[:size])


def test_zstd_compressor_is_cached_per_thread_and_level(zstd_mt):
    workers = zstd_mt
    compressor = get_zstd_compressor(3, workers)
    assert get_zstd_compressor(3, workers) is compressor  # reused, that is the point
    assert get_zstd_compressor(-4, workers) is not compressor  # but not across levels
    assert get_zstd_compressor(3, workers + 1) is not compressor  # nor across worker counts
    assert get_zstd_compressor(3, 0) is get_zstd_compressor(3, 1)  # 0 workers == 1 == no pool

    forget_zstd_compressors()
    assert get_zstd_compressor(3, workers) is not compressor  # dropped, so rebuilt

    in_thread = ThreadPoolExecutor(max_workers=1).submit(get_zstd_compressor, 3, workers).result()
    assert in_thread is not get_zstd_compressor(3, workers)  # each thread has its own


def test_zstd_mt_reused_compressor_output(zstd_mt):
    """Reusing the compressor must give the same bytes as a fresh one-shot compression."""
    from borg.compress import zstd  # the stdlib module or its backport, whichever is in use

    data = mt_data()
    params = zstd.CompressionParameter
    expected = zstd.compress(
        data, options={params.compression_level: 3, params.nb_workers: zstd_mt, params.job_size: ZSTD_JOB_SIZE_MIN}
    )
    compressor = get_compressor(name="zstd", level=3)
    meta, first = compressor.compress({}, data)
    meta, second = compressor.compress({}, data)  # same compressor object, second frame
    assert first == expected
    assert second == expected  # no state carried over from the previous chunk


def test_zstd_mt_roundtrip_concurrent(zstd_mt):
    """Several threads compressing at once must not share a compressor (or corrupt each other)."""
    chunks = [mt_data() + bytes([i]) * 1024 for i in range(8)]
    compressor = get_compressor(name="zstd", level=3)  # one instance, shared by all threads

    def roundtrip(data):
        meta, cdata = compressor.compress({}, data)
        meta, plain = compressor.decompress(dict(meta), cdata)
        return plain

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(roundtrip, chunks)) == chunks


def test_zstd_below_threshold_is_single_threaded(zstd_mt):
    """Small chunks are compressed single-threaded, by a compressor cached for one worker."""
    from borg.compress import zstd, _thread_local

    data = mt_data(ZSTD_MT_MIN_SIZE - 1)
    compressor = get_compressor(name="zstd", level=3)
    meta, cdata = compressor.compress({}, data)
    assert cdata == zstd.compress(data, 3)  # same bytes as the one-shot single-threaded API
    cached = _thread_local.zstd_compressors
    assert list(cached) == [(3, 1)]  # one worker: no thread pool was set up for this chunk
    assert cached[(3, 1)] is get_zstd_compressor(3, 1)


def test_zstd_single_threaded_reused_compressor_output(zstd_mt):
    """Reuse must not change the single-threaded output either, chunk after chunk."""
    from borg.compress import zstd

    data = mt_data(ZSTD_MT_MIN_SIZE - 1)
    expected = zstd.compress(data, 3)
    compressor = get_compressor(name="zstd", level=3)
    assert compressor.compress({}, data)[1] == expected
    assert compressor.compress({}, data)[1] == expected

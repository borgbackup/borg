import pytest

from ..constants import ROBJ_FILE_STREAM, ROBJ_MANIFEST, ROBJ_ARCHIVE_META
from ..crypto.key import PlaintextKey
from ..helpers.errors import IntegrityError
from ..repository import Repository
from ..repoobj import RepoObj, RepoObj1
from ..compress import LZ4


@pytest.fixture
def repository(tmpdir):
    return Repository(tmpdir, create=True)


@pytest.fixture
def key(repository):
    return PlaintextKey(repository)


def test_format_parse_roundtrip(key):
    repo_objs = RepoObj(key)
    data = b"foobar" * 10
    id = repo_objs.id_hash(data)
    meta = {"custom": "something"}  # size and csize are computed automatically
    cdata = repo_objs.format(id, meta, data, ro_type=ROBJ_FILE_STREAM)

    got_meta = repo_objs.parse_meta(id, cdata, ro_type=ROBJ_FILE_STREAM)
    assert got_meta["size"] == len(data)
    assert got_meta["csize"] < len(data)
    assert got_meta["custom"] == "something"

    got_meta, got_data = repo_objs.parse(id, cdata, ro_type=ROBJ_FILE_STREAM)
    assert got_meta["size"] == len(data)
    assert got_meta["csize"] < len(data)
    assert got_meta["custom"] == "something"
    assert data == got_data

    edata = repo_objs.extract_crypted_data(cdata)
    key = repo_objs.key
    assert edata.startswith(bytes((key.TYPE,)))


def test_format_parse_roundtrip_borg1(key):  # legacy
    repo_objs = RepoObj1(key)
    data = b"foobar" * 10
    id = repo_objs.id_hash(data)
    meta = {}  # borg1 does not support this kind of metadata
    cdata = repo_objs.format(id, meta, data, ro_type=ROBJ_FILE_STREAM)

    # borg1 does not support separate metadata and borg2 does not invoke parse_meta for borg1 repos

    got_meta, got_data = repo_objs.parse(id, cdata, ro_type=ROBJ_FILE_STREAM)
    assert got_meta["size"] == len(data)
    assert got_meta["csize"] < len(data)
    assert data == got_data

    edata = repo_objs.extract_crypted_data(cdata)
    compressor = repo_objs.compressor
    key = repo_objs.key
    assert edata.startswith(bytes((key.TYPE, compressor.ID, compressor.level)))


def test_borg1_borg2_transition(key):
    # borg transfer reads borg 1.x repo objects (without decompressing them),
    # writes borg 2 repo objects (giving already compressed data to avoid compression).
    meta = {}  # borg1 does not support this kind of metadata
    data = b"foobar" * 10
    len_data = len(data)
    repo_objs1 = RepoObj1(key)
    id = repo_objs1.id_hash(data)
    borg1_cdata = repo_objs1.format(id, meta, data, ro_type=ROBJ_FILE_STREAM)
    meta1, compr_data1 = repo_objs1.parse(
        id, borg1_cdata, decompress=True, want_compressed=True, ro_type=ROBJ_FILE_STREAM
    )  # avoid re-compression
    # in borg 1, we can only get this metadata after decrypting the whole chunk (and we do not have "size" here):
    assert meta1["ctype"] == LZ4.ID  # default compression
    assert meta1["clevel"] == 0xFF  # lz4 does not know levels (yet?)
    assert meta1["csize"] < len_data  # lz4 should make it smaller

    repo_objs2 = RepoObj(key)
    # note: as we did not decompress, we do not have "size" and we need to get it from somewhere else.
    # here, we just use len_data. for borg transfer, we also know the size from another metadata source.
    borg2_cdata = repo_objs2.format(
        id,
        dict(meta1),
        compr_data1[2:],
        compress=False,
        size=len_data,
        ctype=meta1["ctype"],
        clevel=meta1["clevel"],
        ro_type=ROBJ_FILE_STREAM,
    )
    meta2, data2 = repo_objs2.parse(id, borg2_cdata, ro_type=ROBJ_FILE_STREAM)
    assert data2 == data
    assert meta2["ctype"] == LZ4.ID
    assert meta2["clevel"] == 0xFF
    assert meta2["csize"] == meta1["csize"] - 2  # borg2 does not store the type/level bytes there
    assert meta2["size"] == len_data

    meta2 = repo_objs2.parse_meta(id, borg2_cdata, ro_type=ROBJ_FILE_STREAM)
    # now, in borg 2, we have nice and separately decrypted metadata (no need to decrypt the whole chunk):
    assert meta2["ctype"] == LZ4.ID
    assert meta2["clevel"] == 0xFF
    assert meta2["csize"] == meta1["csize"] - 2  # borg2 does not store the type/level bytes there
    assert meta2["size"] == len_data


def test_spoof_manifest(key):
    repo_objs = RepoObj(key)
    data = b"fake or malicious manifest data"  # file content could be provided by attacker.
    id = repo_objs.id_hash(data)
    # create a repo object containing user data (file content data).
    cdata = repo_objs.format(id, {}, data, ro_type=ROBJ_FILE_STREAM)
    # let's assume an attacker somehow managed to replace the manifest with that repo object.
    # as borg always give the ro_type it wants to read, this should fail:
    with pytest.raises(IntegrityError):
        repo_objs.parse(id, cdata, ro_type=ROBJ_MANIFEST)


def test_spoof_archive(key):
    repo_objs = RepoObj(key)
    data = b"fake or malicious archive data"  # file content could be provided by attacker.
    id = repo_objs.id_hash(data)
    # create a repo object containing user data (file content data).
    cdata = repo_objs.format(id, {}, data, ro_type=ROBJ_FILE_STREAM)
    # let's assume an attacker somehow managed to replace an archive with that repo object.
    # as borg always give the ro_type it wants to read, this should fail:
    with pytest.raises(IntegrityError):
        repo_objs.parse(id, cdata, ro_type=ROBJ_ARCHIVE_META)

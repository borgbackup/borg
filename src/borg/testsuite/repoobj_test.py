import pytest

from ..constants import ROBJ_FILE_STREAM, ROBJ_MANIFEST, ROBJ_ARCHIVE_META
from ..crypto.key import PlaintextKey, CHPOKey
from ..helpers import msgpack
from ..helpers.errors import IntegrityError
from ..repository import Repository
from ..repoobj import RepoObj
from ..legacy.repoobj import RepoObj1
from ..compress import LZ4


@pytest.fixture
def repository(tmpdir):
    return Repository(tmpdir, create=True)


@pytest.fixture
def key(repository):
    return PlaintextKey(repository)


@pytest.fixture
def aead_key(repository):
    # AEAD key, needed to test header_aad authentication; PlaintextKey is unauthenticated.
    key = CHPOKey(repository)
    key.init_from_random_data()
    key.init_ciphers()
    return key


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

    # Borg 1 does not support separate metadata, and Borg 2 does not invoke parse_meta for Borg 1 repositories.

    got_meta, got_data = repo_objs.parse(id, cdata, ro_type=ROBJ_FILE_STREAM)
    assert got_meta["size"] == len(data)
    assert got_meta["csize"] < len(data)
    assert data == got_data

    edata = repo_objs.extract_crypted_data(cdata)
    compressor = repo_objs.compressor
    key = repo_objs.key
    assert edata.startswith(bytes((key.TYPE, compressor.ID, compressor.level)))


def test_borg1_borg2_transition(key):
    # Borg transfer reads Borg 1.x repository objects (without decompressing them),
    # and writes Borg 2 repository objects (providing already-compressed data to avoid recompression).
    meta = {}  # borg1 does not support this kind of metadata
    data = b"foobar" * 10
    len_data = len(data)
    repo_objs1 = RepoObj1(key)
    id = repo_objs1.id_hash(data)
    borg1_cdata = repo_objs1.format(id, meta, data, ro_type=ROBJ_FILE_STREAM)
    meta1, compr_data1 = repo_objs1.parse(
        id, borg1_cdata, decompress=True, want_compressed=True, ro_type=ROBJ_FILE_STREAM
    )  # avoid re-compression
    # In Borg 1, we can only get this metadata after decrypting the whole chunk (and we do not have "size" here):
    assert meta1["ctype"] == LZ4.ID  # Default compression.
    assert meta1["clevel"] == 0xFF  # LZ4 does not support levels (yet?).
    assert meta1["csize"] < len_data  # LZ4 should make it smaller.

    repo_objs2 = RepoObj(key)
    # Note: As we did not decompress, we do not have "size" and need to get it from somewhere else.
    # Here, we just use len_data. For Borg transfer, we also know the size from another metadata source.
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
    assert meta2["csize"] == meta1["csize"] - 2  # Borg 2 does not store the type/level bytes there.
    assert meta2["size"] == len_data

    meta2 = repo_objs2.parse_meta(id, borg2_cdata, ro_type=ROBJ_FILE_STREAM)
    # Now, in Borg 2, we have nice and separately decrypted metadata (no need to decrypt the whole chunk).
    assert meta2["ctype"] == LZ4.ID
    assert meta2["clevel"] == 0xFF
    assert meta2["csize"] == meta1["csize"] - 2  # Borg 2 does not store the type/level bytes there.
    assert meta2["size"] == len_data


def test_malformed_object_too_short(key):
    # a malformed / truncated object (e.g. from a corrupted or malicious repo) must be
    # rejected with a clean IntegrityError, not an uncaught struct.error / IndexError.
    repo_objs = RepoObj(key)
    id = repo_objs.id_hash(b"x")
    hdr_size = RepoObj.obj_header.size
    for blob in [b"", b"BORG_OBJ", b"\x00" * (hdr_size - 1)]:
        with pytest.raises(IntegrityError):
            RepoObj.extract_crypted_data(blob)
        with pytest.raises(IntegrityError):
            repo_objs.parse_meta(id, blob, ro_type=ROBJ_FILE_STREAM)
        with pytest.raises(IntegrityError):
            repo_objs.parse(id, blob, ro_type=ROBJ_FILE_STREAM)


def test_malformed_object_inconsistent_sizes(key):
    # a valid-looking header that claims more meta/data than the object actually contains
    # must be rejected cleanly with IntegrityError.
    from ..repoobj import OBJ_MAGIC, OBJ_VERSION

    repo_objs = RepoObj(key)
    id = repo_objs.id_hash(b"x")
    # huge meta_size, but no actual meta/data bytes follow the header
    hdr = RepoObj.obj_header.pack(OBJ_MAGIC, OBJ_VERSION, id, 0xFFFFFFFF, 0)
    with pytest.raises(IntegrityError):
        RepoObj.extract_crypted_data(hdr)
    with pytest.raises(IntegrityError):
        repo_objs.parse_meta(id, hdr, ro_type=ROBJ_FILE_STREAM)
    with pytest.raises(IntegrityError):
        repo_objs.parse(id, hdr, ro_type=ROBJ_FILE_STREAM)


def test_spoof_manifest(key):
    repo_objs = RepoObj(key)
    data = b"fake or malicious manifest data"  # File content could be provided by an attacker.
    id = repo_objs.id_hash(data)
    # Create a repository object containing user data (file content data).
    cdata = repo_objs.format(id, {}, data, ro_type=ROBJ_FILE_STREAM)
    # Let's assume an attacker managed to replace the manifest with that repository object.
    # As Borg always gives the ro_type it intends to read, this should fail:
    with pytest.raises(IntegrityError):
        repo_objs.parse(id, cdata, ro_type=ROBJ_MANIFEST)


def test_spoof_archive(key):
    repo_objs = RepoObj(key)
    data = b"fake or malicious archive data"  # File content could be provided by an attacker.
    id = repo_objs.id_hash(data)
    # Create a repository object containing user data (file content data).
    cdata = repo_objs.format(id, {}, data, ro_type=ROBJ_FILE_STREAM)
    # Let's assume an attacker managed to replace an archive with that repository object.
    # As Borg always gives the ro_type it intends to read, this should fail:
    with pytest.raises(IntegrityError):
        repo_objs.parse(id, cdata, ro_type=ROBJ_ARCHIVE_META)


def _tamper(cdata, offset):
    # flip one bit at the given byte offset of an otherwise-valid formatted object.
    tampered = bytearray(cdata)
    tampered[offset] ^= 0x01
    return bytes(tampered)


def test_tampered_header_chunk_id_detected(aead_key):
    # chunk_id is part of header_aad, so tampering with it fails AEAD authentication in
    # parse()/parse_meta().
    repo_objs = RepoObj(aead_key)
    data = b"foobar" * 10
    id = repo_objs.id_hash(data)
    cdata = repo_objs.format(id, {"custom": "something"}, data, ro_type=ROBJ_FILE_STREAM)

    # chunk_id is at header offset 9..41 (after 8-byte magic + 1-byte version). It has no structural
    # check, so tampering is detected only through AEAD authentication.
    tampered = _tamper(cdata, offset=9)
    with pytest.raises(IntegrityError):
        repo_objs.parse_meta(id, tampered, ro_type=ROBJ_FILE_STREAM)
    with pytest.raises(IntegrityError):
        repo_objs.parse(id, tampered, ro_type=ROBJ_FILE_STREAM)


def test_tampered_header_magic_detected(aead_key):
    # A tampered magic byte is rejected by the structural check (`hdr.magic != OBJ_MAGIC`) before
    # key.decrypt() runs, so this does not test AEAD authentication of header_aad - see
    # test_header_aad_tamper_detected_at_key_layer for that.
    repo_objs = RepoObj(aead_key)
    data = b"foobar" * 10
    id = repo_objs.id_hash(data)
    cdata = repo_objs.format(id, {"custom": "something"}, data, ro_type=ROBJ_FILE_STREAM)

    # OBJ_MAGIC lives at header offset 0..8.
    tampered = _tamper(cdata, offset=0)
    with pytest.raises(IntegrityError):
        repo_objs.parse_meta(id, tampered, ro_type=ROBJ_FILE_STREAM)
    with pytest.raises(IntegrityError):
        repo_objs.parse(id, tampered, ro_type=ROBJ_FILE_STREAM)


def test_header_aad_tamper_detected_at_key_layer(aead_key):
    # Calls key.encrypt()/key.decrypt() directly with header_aad, to check that every byte of
    # header_aad (magic, version, chunk_id) is authenticated, not just chunk_id.
    from ..repoobj import OBJ_MAGIC, OBJ_VERSION

    data = b"foobar" * 10
    id = aead_key.id_hash(data)
    header_aad = OBJ_MAGIC + bytes([OBJ_VERSION]) + id
    encrypted = aead_key.encrypt(id, data, header=header_aad)

    assert aead_key.decrypt(id, encrypted, header=header_aad) == data

    # tamper the magic byte (offset 0) after encryption; decrypt gets a different header_aad than encrypt did.
    tampered_header_aad = bytearray(header_aad)
    tampered_header_aad[0] ^= 0x01
    with pytest.raises(IntegrityError):
        aead_key.decrypt(id, encrypted, header=bytes(tampered_header_aad))

    # tamper the version byte (offset 8) after encryption.
    tampered_header_aad = bytearray(header_aad)
    tampered_header_aad[8] ^= 0x01
    with pytest.raises(IntegrityError):
        aead_key.decrypt(id, encrypted, header=bytes(tampered_header_aad))


def test_untampered_roundtrip_with_aead_key(aead_key):
    repo_objs = RepoObj(aead_key)
    data = b"foobar" * 10
    id = repo_objs.id_hash(data)
    cdata = repo_objs.format(id, {"custom": "something"}, data, ro_type=ROBJ_FILE_STREAM)

    got_meta, got_data = repo_objs.parse(id, cdata, ro_type=ROBJ_FILE_STREAM)
    assert got_data == data
    assert got_meta["custom"] == "something"


def test_version1_object_without_header_aad_still_readable(aead_key):
    # Builds an OBJ_VERSION_NO_HEADER_AAD object by hand (format() only writes OBJ_VERSION_HEADER_AAD)
    # and checks that parse()/parse_meta() still decrypt it.
    from ..repoobj import OBJ_MAGIC, OBJ_VERSION_NO_HEADER_AAD, REPOOBJ_HEADER_SIZE

    repo_objs = RepoObj(aead_key)
    data = b"foobar" * 10
    id = repo_objs.id_hash(data)
    meta = {"type": ROBJ_FILE_STREAM}
    meta, data_compressed = repo_objs.compressor.compress(meta, data)

    # OBJ_VERSION_NO_HEADER_AAD encoding: header=b"", aad=chunk_id only.
    data_encrypted = aead_key.encrypt(id, data_compressed, header=b"")
    meta_packed = msgpack.packb(meta)
    meta_encrypted = aead_key.encrypt(id, meta_packed, header=b"")
    hdr = RepoObj.ObjHeader(OBJ_MAGIC, OBJ_VERSION_NO_HEADER_AAD, id, len(meta_encrypted), len(data_encrypted))
    cdata = RepoObj.obj_header.pack(*hdr) + meta_encrypted + data_encrypted
    assert len(RepoObj.obj_header.pack(*hdr)) == REPOOBJ_HEADER_SIZE

    got_meta = repo_objs.parse_meta(id, cdata, ro_type=ROBJ_FILE_STREAM)
    assert got_meta["type"] == ROBJ_FILE_STREAM
    got_meta, got_data = repo_objs.parse(id, cdata, ro_type=ROBJ_FILE_STREAM)
    assert got_data == data

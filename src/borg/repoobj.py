from collections import namedtuple
from struct import Struct

from .constants import *  # NOQA
from .helpers import msgpack, workarounds
from .helpers.errors import IntegrityError
from .compress import Compressor, LZ4_COMPRESSOR

# Workaround for lost passphrase or key in "authenticated" or "authenticated-blake2" mode
AUTHENTICATED_NO_KEY = "authenticated_no_key" in workarounds


OBJ_MAGIC = b"BORG_OBJ"

# meta_encrypted/data_encrypted are AEAD-authenticated with aad=chunk_id. The header (magic, version,
# chunk_id) is not authenticated.
OBJ_VERSION_NO_HEADER_AAD = 0x01
# meta_encrypted/data_encrypted are AEAD-authenticated with aad=header_aad+chunk_id, where header_aad
# is the header prefix (magic, version, chunk_id, see REPOOBJ_HEADER_AAD_SIZE). format() writes this
# version.
OBJ_VERSION_HEADER_AAD = 0x02
OBJ_VERSION = OBJ_VERSION_HEADER_AAD
# Versions accepted by parse() and parse_meta().
SUPPORTED_OBJ_VERSIONS = (OBJ_VERSION_NO_HEADER_AAD, OBJ_VERSION_HEADER_AAD)

# Fixed header size per blob: OBJ_MAGIC(8) + version(1) + chunk_id(32) + meta_size(4) + data_size(4)
REPOOBJ_HEADER_SIZE = 49

# Size of the header prefix used as AEAD additional authenticated data (AAD, data that is authenticated
# but not encrypted) for OBJ_VERSION_HEADER_AAD objects: OBJ_MAGIC(8) + version(1) + chunk_id(32).
# meta_size and data_size are excluded, since they are only known after encryption; tampering with them
# still fails authentication, because it changes the length of the ciphertext slice being decrypted.
REPOOBJ_HEADER_AAD_SIZE = 41


class RepoObj:
    # Object header: magic (8b), format version (1b), chunk_id (32b), meta size (4b), data size (4b).
    obj_header = Struct("<8sB32sII")
    ObjHeader = namedtuple("ObjHeader", "magic version chunk_id meta_size data_size")

    @classmethod
    def extract_crypted_data(cls, data: bytes) -> bytes:
        # used for crypto type detection
        hdr_size = cls.obj_header.size
        if len(data) < hdr_size:
            raise IntegrityError(f"object too small: expected at least {hdr_size} header bytes, got {len(data)}")
        hdr = cls.ObjHeader(*cls.obj_header.unpack(data[:hdr_size]))
        if hdr.magic != OBJ_MAGIC:
            raise IntegrityError("invalid object magic")
        if hdr.version not in SUPPORTED_OBJ_VERSIONS:
            raise IntegrityError(f"unsupported object version: {hdr.version}")
        overall_expected_size = hdr_size + hdr.meta_size + hdr.data_size
        if overall_expected_size != len(data):
            raise IntegrityError(f"object size inconsistent: expected {overall_expected_size} bytes, got {len(data)}")
        return data[hdr_size + hdr.meta_size :]  # crypted data

    def __init__(self, key):
        self.key = key
        # Some commands write new chunks (e.g. rename) but don't take a --compression argument. This duplicates
        # the default used by those commands who do take a --compression argument.
        self.compressor = LZ4_COMPRESSOR

    def id_hash(self, data: bytes) -> bytes:
        return self.key.id_hash(data)

    def format(
        self,
        id: bytes,
        meta: dict,
        data: bytes,
        compress: bool = True,
        size: int = None,
        ctype: int = None,
        clevel: int = None,
        ro_type: str = None,
    ) -> bytes:
        assert isinstance(ro_type, str)
        assert ro_type != ROBJ_DONTCARE
        meta["type"] = ro_type
        assert isinstance(id, bytes)
        assert isinstance(meta, dict)
        assert isinstance(data, (bytes, memoryview))
        assert compress or size is not None and ctype is not None and clevel is not None
        if compress:
            assert size is None or size == len(data)
            meta, data_compressed = self.compressor.compress(meta, data)
        else:
            assert isinstance(size, int)
            meta["size"] = size
            assert isinstance(ctype, int)
            meta["ctype"] = ctype
            assert isinstance(clevel, int)
            meta["clevel"] = clevel
            data_compressed = data  # is already compressed, is NOT prefixed by type/level bytes
            meta["csize"] = len(data_compressed)
        # header_aad is the header prefix (magic, version, chunk_id), used as AEAD AAD for both meta and data.
        header_aad = OBJ_MAGIC + bytes([OBJ_VERSION]) + id
        data_encrypted = self.key.encrypt(id, data_compressed, header=header_aad)
        meta_packed = msgpack.packb(meta)
        meta_encrypted = self.key.encrypt(id, meta_packed, header=header_aad)
        hdr = self.ObjHeader(OBJ_MAGIC, OBJ_VERSION, id, len(meta_encrypted), len(data_encrypted))
        hdr_packed = self.obj_header.pack(*hdr)
        return hdr_packed + meta_encrypted + data_encrypted

    def parse_meta(self, id: bytes, cdata: bytes, ro_type: str) -> dict:
        # when calling parse_meta, enough cdata needs to be supplied to contain completely the
        # meta_len_hdr and the encrypted, packed metadata. it is allowed to provide more cdata.
        assert isinstance(id, bytes)
        assert isinstance(cdata, bytes)
        assert isinstance(ro_type, str)
        obj = memoryview(cdata)
        hdr_size = self.obj_header.size
        if len(obj) < hdr_size:
            raise IntegrityError(f"object too small: expected at least {hdr_size} header bytes, got {len(obj)}")
        hdr = self.ObjHeader(*self.obj_header.unpack(obj[:hdr_size]))
        if hdr.magic != OBJ_MAGIC:
            raise IntegrityError("invalid object magic")
        if hdr.version not in SUPPORTED_OBJ_VERSIONS:
            raise IntegrityError(f"unsupported object version: {hdr.version}")
        if hdr_size + hdr.meta_size > len(obj):
            raise IntegrityError(
                f"object too small: expected at least {hdr_size + hdr.meta_size} bytes, got {len(obj)}"
            )
        # header_aad is read from the on-disk header bytes, so any change to magic/version/chunk_id changes
        # header_aad and breaks decryption below. OBJ_VERSION_NO_HEADER_AAD objects have no header_aad.
        header_aad = bytes(obj[:REPOOBJ_HEADER_AAD_SIZE]) if hdr.version == OBJ_VERSION_HEADER_AAD else b""
        meta_encrypted = obj[hdr_size : hdr_size + hdr.meta_size]
        meta_packed = self.key.decrypt(id, meta_encrypted, header=header_aad)
        meta = msgpack.unpackb(meta_packed)
        if ro_type != ROBJ_DONTCARE and meta["type"] != ro_type:
            raise IntegrityError(f"ro_type expected: {ro_type} got: {meta['type']}")
        return meta

    def parse(
        self, id: bytes, cdata: bytes, decompress: bool = True, want_compressed: bool = False, ro_type: str = None
    ) -> tuple[dict, bytes]:
        """
        Parse a repo object into metadata and data (decrypt it, maybe decompress, maybe verify if the chunk plaintext
        corresponds to the chunk id via assert_id()).

        Tweaking options (default is usually fine):
        - decompress=True, want_compressed=False: slow, verifying. returns decompressed data (default).
        - decompress=True, want_compressed=True: slow, verifying. returns compressed data (caller wants to reuse it).
        - decompress=False, want_compressed=True: quick, not verifying. returns compressed data (caller wants to reuse).
        - decompress=False, want_compressed=False: invalid
        """
        assert isinstance(ro_type, str)
        assert not (not decompress and not want_compressed), "invalid parameter combination!"
        assert isinstance(id, bytes)
        assert isinstance(cdata, bytes)
        obj = memoryview(cdata)
        hdr_size = self.obj_header.size
        if len(obj) < hdr_size:
            raise IntegrityError(f"object too small: expected at least {hdr_size} header bytes, got {len(obj)}")
        hdr = self.ObjHeader(*self.obj_header.unpack(obj[:hdr_size]))
        if hdr.magic != OBJ_MAGIC:
            raise IntegrityError("invalid object magic")
        if hdr.version not in SUPPORTED_OBJ_VERSIONS:
            raise IntegrityError(f"unsupported object version: {hdr.version}")
        overall_expected_size = hdr_size + hdr.meta_size + hdr.data_size
        if overall_expected_size != len(obj):
            raise IntegrityError(f"object size inconsistent: expected {overall_expected_size} bytes, got {len(obj)}")
        # header_aad: see parse_meta().
        header_aad = bytes(obj[:REPOOBJ_HEADER_AAD_SIZE]) if hdr.version == OBJ_VERSION_HEADER_AAD else b""
        meta_encrypted = obj[hdr_size : hdr_size + hdr.meta_size]
        meta_packed = self.key.decrypt(id, meta_encrypted, header=header_aad)
        meta_compressed = msgpack.unpackb(meta_packed)  # means: before adding more metadata in decompress block
        if ro_type != ROBJ_DONTCARE and meta_compressed["type"] != ro_type:
            raise IntegrityError(f"ro_type expected: {ro_type} got: {meta_compressed['type']}")
        data_encrypted = obj[hdr_size + hdr.meta_size : hdr_size + hdr.meta_size + hdr.data_size]
        data_compressed = self.key.decrypt(id, data_encrypted, header=header_aad)  # does not include type/level
        if decompress:
            ctype = meta_compressed["ctype"]
            clevel = meta_compressed["clevel"]
            csize = meta_compressed["csize"]  # always the overall size
            assert csize == len(data_compressed)
            psize = meta_compressed.get(
                "psize", csize
            )  # obfuscation: psize (payload size) is potentially less than csize.
            assert psize <= csize
            compr_hdr = bytes((ctype, clevel))
            compressor_cls, compression_level = Compressor.detect(compr_hdr)
            compressor = compressor_cls(level=compression_level)
            meta, data = compressor.decompress(dict(meta_compressed), data_compressed[:psize])
            if not AUTHENTICATED_NO_KEY:
                self.key.assert_id(id, data)
        else:
            meta, data = None, None
        return meta_compressed if want_compressed else meta, data_compressed if want_compressed else data


# Backward compatibility: RepoObj1 has moved to borg.legacy.repoobj
from .legacy.repoobj import RepoObj1  # noqa: F401

from collections import namedtuple
from struct import Struct

from .constants import *  # NOQA
from .checksums import xxh64
from .helpers import msgpack, workarounds
from .helpers.errors import IntegrityError
from .compress import Compressor, LZ4_COMPRESSOR, get_compressor

# workaround for lost passphrase or key in "authenticated" or "authenticated-blake2" mode
AUTHENTICATED_NO_KEY = "authenticated_no_key" in workarounds


class RepoObj:
    # Object header format includes size infos for parsing the object into meta and data,
    # as well as hashes to enable checking consistency without having the borg key.
    obj_header = Struct("<II8s8s")  # meta size (32b), data size (32b), meta hash (64b), data hash (64b)
    ObjHeader = namedtuple("ObjHeader", "meta_size data_size meta_hash data_hash")

    @classmethod
    def extract_crypted_data(cls, data: bytes) -> bytes:
        # used for crypto type detection
        hdr_size = cls.obj_header.size
        hdr = cls.ObjHeader(*cls.obj_header.unpack(data[:hdr_size]))
        return data[hdr_size + hdr.meta_size :]

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
        data_encrypted = self.key.encrypt(id, data_compressed)
        meta_packed = msgpack.packb(meta)
        meta_encrypted = self.key.encrypt(id, meta_packed)
        hdr = self.ObjHeader(len(meta_encrypted), len(data_encrypted), xxh64(meta_encrypted), xxh64(data_encrypted))
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
        hdr = self.ObjHeader(*self.obj_header.unpack(obj[:hdr_size]))
        assert hdr_size + hdr.meta_size <= len(obj)
        meta_encrypted = obj[hdr_size : hdr_size + hdr.meta_size]
        meta_packed = self.key.decrypt(id, meta_encrypted)
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
        hdr = self.ObjHeader(*self.obj_header.unpack(obj[:hdr_size]))
        assert hdr_size + hdr.meta_size <= len(obj)
        meta_encrypted = obj[hdr_size : hdr_size + hdr.meta_size]
        meta_packed = self.key.decrypt(id, meta_encrypted)
        meta_compressed = msgpack.unpackb(meta_packed)  # means: before adding more metadata in decompress block
        if ro_type != ROBJ_DONTCARE and meta_compressed["type"] != ro_type:
            raise IntegrityError(f"ro_type expected: {ro_type} got: {meta_compressed['type']}")
        assert hdr_size + hdr.meta_size + hdr.data_size <= len(obj)
        data_encrypted = obj[hdr_size + hdr.meta_size : hdr_size + hdr.meta_size + hdr.data_size]
        data_compressed = self.key.decrypt(id, data_encrypted)  # does not include the type/level bytes
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


class RepoObj1:  # legacy
    @classmethod
    def extract_crypted_data(cls, data: bytes) -> bytes:
        # used for crypto type detection
        return data

    def __init__(self, key):
        self.key = key
        self.compressor = get_compressor("lz4", legacy_mode=True)

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
        assert isinstance(id, bytes)
        assert meta == {}
        assert isinstance(data, (bytes, memoryview))
        assert ro_type is not None
        assert compress or size is not None and ctype is not None and clevel is not None
        if compress:
            assert size is None or size == len(data)
            meta, data_compressed = self.compressor.compress(meta, data)
        else:
            assert isinstance(size, int)
            data_compressed = data  # is already compressed, must include type/level bytes
        data_encrypted = self.key.encrypt(id, data_compressed)
        return data_encrypted

    def parse_meta(self, id: bytes, cdata: bytes) -> dict:
        raise NotImplementedError("parse_meta is not available for RepoObj1")

    def parse(
        self, id: bytes, cdata: bytes, decompress: bool = True, want_compressed: bool = False, ro_type: str = None
    ) -> tuple[dict, bytes]:
        assert not (not decompress and not want_compressed), "invalid parameter combination!"
        assert isinstance(id, bytes)
        assert isinstance(cdata, bytes)
        assert ro_type is not None
        data_compressed = self.key.decrypt(id, cdata)
        compressor_cls, compression_level = Compressor.detect(data_compressed[:2])
        compressor = compressor_cls(level=compression_level, legacy_mode=True)
        meta_compressed = {}
        meta_compressed["ctype"] = compressor.ID
        meta_compressed["clevel"] = compressor.level
        meta_compressed["csize"] = len(data_compressed)
        if decompress:
            meta, data = compressor.decompress(None, data_compressed)
            if not AUTHENTICATED_NO_KEY:
                self.key.assert_id(id, data)
        else:
            meta, data = None, None
        return meta_compressed if want_compressed else meta, data_compressed if want_compressed else data

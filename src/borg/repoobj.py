from struct import Struct

from .helpers import msgpack
from .compress import Compressor, LZ4_COMPRESSOR, get_compressor


class RepoObj:
    meta_len_hdr = Struct("<H")  # 16bit unsigned int

    @classmethod
    def extract_crypted_data(cls, data: bytes) -> bytes:
        # used for crypto type detection
        offs = cls.meta_len_hdr.size
        meta_len = cls.meta_len_hdr.unpack(data[:offs])[0]
        return data[offs + meta_len :]

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
    ) -> bytes:
        assert isinstance(id, bytes)
        assert isinstance(meta, dict)
        meta = dict(meta)  # make a copy, so call arg is not modified
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
        hdr = self.meta_len_hdr.pack(len(meta_encrypted))
        return hdr + meta_encrypted + data_encrypted

    def parse_meta(self, id: bytes, cdata: bytes) -> dict:
        # when calling parse_meta, enough cdata needs to be supplied to completely contain the
        # meta_len_hdr and the encrypted, packed metadata. it is allowed to provide more cdata.
        assert isinstance(id, bytes)
        assert isinstance(cdata, bytes)
        obj = memoryview(cdata)
        offs = self.meta_len_hdr.size
        hdr = obj[:offs]
        len_meta_encrypted = self.meta_len_hdr.unpack(hdr)[0]
        assert offs + len_meta_encrypted <= len(obj)
        meta_encrypted = obj[offs : offs + len_meta_encrypted]
        meta_packed = self.key.decrypt(id, meta_encrypted)
        meta = msgpack.unpackb(meta_packed)
        return meta

    def parse(self, id: bytes, cdata: bytes, decompress: bool = True) -> tuple[dict, bytes]:
        assert isinstance(id, bytes)
        assert isinstance(cdata, bytes)
        obj = memoryview(cdata)
        offs = self.meta_len_hdr.size
        hdr = obj[:offs]
        len_meta_encrypted = self.meta_len_hdr.unpack(hdr)[0]
        assert offs + len_meta_encrypted <= len(obj)
        meta_encrypted = obj[offs : offs + len_meta_encrypted]
        offs += len_meta_encrypted
        meta_packed = self.key.decrypt(id, meta_encrypted)
        meta = msgpack.unpackb(meta_packed)
        data_encrypted = obj[offs:]
        data_compressed = self.key.decrypt(id, data_encrypted)
        if decompress:
            ctype = meta["ctype"]
            clevel = meta["clevel"]
            csize = meta["csize"]  # always the overall size
            assert csize == len(data_compressed)
            psize = meta.get("psize", csize)  # obfuscation: psize (payload size) is potentially less than csize.
            assert psize <= csize
            compr_hdr = bytes((ctype, clevel))
            compressor_cls, compression_level = Compressor.detect(compr_hdr)
            compressor = compressor_cls(level=compression_level)
            meta, data = compressor.decompress(meta, data_compressed[:psize])
            self.key.assert_id(id, data)
        else:
            data = data_compressed  # does not include the type/level bytes
        return meta, data


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

    def format(self, id: bytes, meta: dict, data: bytes, compress: bool = True, size: int = None) -> bytes:
        assert isinstance(id, bytes)
        assert meta == {}
        assert isinstance(data, (bytes, memoryview))
        assert compress or size is not None
        assert compress or size is not None
        if compress:
            assert size is None
            meta, data_compressed = self.compressor.compress(meta, data)
        else:
            assert isinstance(size, int)
            data_compressed = data  # is already compressed, must include type/level bytes
        data_encrypted = self.key.encrypt(id, data_compressed)
        return data_encrypted

    def parse(self, id: bytes, cdata: bytes, decompress: bool = True) -> tuple[dict, bytes]:
        assert isinstance(id, bytes)
        assert isinstance(cdata, bytes)
        data_compressed = self.key.decrypt(id, cdata)
        compressor_cls, compression_level = Compressor.detect(data_compressed[:2])
        compressor = compressor_cls(level=compression_level, legacy_mode=True)
        if decompress:
            meta, data = compressor.decompress(None, data_compressed)
            self.key.assert_id(id, data)
        else:
            meta = {}
            meta["ctype"] = compressor.ID
            meta["clevel"] = compressor.level
            data = data_compressed
        meta["csize"] = len(data_compressed)
        return meta, data

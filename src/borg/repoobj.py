from struct import Struct

from .helpers import msgpack
from .compress import Compressor, LZ4_COMPRESSOR


class RepoObj:
    meta_len_hdr = Struct("<I")

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
            size = len(data) if size is None else size
            data_compressed = self.compressor.compress(data)  # TODO: compressor also adds compressor type/level bytes
            ctype = data_compressed[0]
            clevel = data_compressed[1]
            data_compressed = data_compressed[2:]  # strip the type/level bytes
        else:
            assert isinstance(size, int)
            assert isinstance(ctype, int)
            assert isinstance(clevel, int)
            data_compressed = data  # is already compressed, is NOT prefixed by type/level bytes
        meta["size"] = size
        meta["csize"] = len(data_compressed)
        meta["ctype"] = ctype
        meta["clevel"] = clevel
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
            compr_hdr = bytes((ctype, clevel))
            compressor_cls, compression_level = Compressor.detect(compr_hdr)
            compressor = compressor_cls(level=compression_level)
            data = compressor.decompress(compr_hdr + data_compressed)  # TODO: decompressor still needs type/level bytes
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
        self.compressor = LZ4_COMPRESSOR

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
            data_compressed = self.compressor.compress(data)  # TODO: compressor also adds compressor type/level bytes
        else:
            assert isinstance(size, int)
            data_compressed = data  # is already compressed, must include type/level bytes
        data_encrypted = self.key.encrypt(id, data_compressed)
        return data_encrypted

    def parse(self, id: bytes, cdata: bytes, decompress: bool = True) -> tuple[dict, bytes]:
        assert isinstance(id, bytes)
        assert isinstance(cdata, bytes)
        meta = {}
        data_compressed = self.key.decrypt(id, cdata)
        meta["csize"] = len(data_compressed)
        compressor_cls, compression_level = Compressor.detect(data_compressed[:2])
        compressor = compressor_cls(level=compression_level)
        meta["ctype"] = compressor.ID[0]
        meta["clevel"] = compressor.level
        if decompress:
            data = compressor.decompress(data_compressed)  # TODO: decompressor still needs type/level bytes
            self.key.assert_id(id, data)
            meta["size"] = len(data)
        else:
            data = data_compressed
        return meta, data

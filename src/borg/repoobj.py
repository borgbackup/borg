from struct import Struct

from borg.helpers import msgpack
from borg.compress import Compressor, LZ4_COMPRESSOR


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
        self.decompress = Compressor("lz4").decompress

    def id_hash(self, data: bytes) -> bytes:
        return self.key.id_hash(data)

    def format(self, id: bytes, meta: dict, data: bytes, compress: bool = True, size: int = None) -> bytes:
        assert isinstance(id, bytes)
        assert isinstance(meta, dict)
        assert isinstance(data, (bytes, memoryview))
        assert compress or size is not None
        if compress:
            assert size is None or size == len(data)
            size = len(data) if size is None else size
            data_compressed = self.compressor.compress(data)  # TODO: compressor also adds compressor type/level bytes
        else:
            assert isinstance(size, int)
            data_compressed = data  # is already compressed
        meta = dict(meta)  # make a copy, so call arg is not modified
        meta["size"] = size
        meta["csize"] = len(data_compressed)
        # meta["ctype"] = ...
        # meta["clevel"] = ...
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
            data = self.decompress(data_compressed)  # TODO: decompressor still needs type/level bytes
            self.key.assert_id(id, data)
        else:
            data = data_compressed
        return meta, data


class RepoObj1:  # legacy
    @classmethod
    def extract_crypted_data(cls, data: bytes) -> bytes:
        # used for crypto type detection
        return data

    def __init__(self, key):
        self.key = key
        self.compressor = LZ4_COMPRESSOR
        self.decompress = Compressor("lz4").decompress

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
            size = len(data)
            data_compressed = self.compressor.compress(data)  # TODO: compressor also adds compressor type/level bytes
        else:
            assert isinstance(size, int)
            data_compressed = data  # is already compressed
        data_encrypted = self.key.encrypt(id, data_compressed)
        return data_encrypted

    def parse(self, id: bytes, cdata: bytes, decompress: bool = True) -> tuple[dict, bytes]:
        assert isinstance(id, bytes)
        assert isinstance(cdata, bytes)
        meta = {}
        data_compressed = self.key.decrypt(id, cdata)
        meta["csize"] = len(data_compressed)
        if decompress:
            data = self.decompress(data_compressed)  # TODO: decompressor still needs type/level bytes
            self.key.assert_id(id, data)
            meta["size"] = len(data)
        else:
            data = data_compressed
        return meta, data

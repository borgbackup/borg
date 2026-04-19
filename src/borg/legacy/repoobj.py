"""Legacy RepoObj1 — Borg 1.x repository object format.

Moved from borg.repoobj as part of the legacy code separation.
"""

from ..constants import *  # NOQA
from ..helpers import workarounds
from ..compress import Compressor, get_compressor

# Workaround for lost passphrase or key in "authenticated" or "authenticated-blake2" mode
AUTHENTICATED_NO_KEY = "authenticated_no_key" in workarounds


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

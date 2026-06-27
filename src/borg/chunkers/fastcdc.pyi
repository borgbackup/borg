from collections.abc import Iterator
from typing import BinaryIO

from .reader import fmap_entry

def fastcdc_get_gear_table(key: bytes) -> list[int]: ...

class ChunkerFastCDC:
    def __init__(
        self,
        key: bytes,
        chunk_min_exp: int,
        chunk_max_exp: int,
        hash_mask_bits: int,
        nc_level: int = 0,
        normal_size: int = 0,
        sparse: bool = False,
    ) -> None: ...
    def chunkify(self, fd: BinaryIO = None, fh: int = -1, fmap: list[fmap_entry] = None) -> Iterator: ...

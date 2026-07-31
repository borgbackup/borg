from collections.abc import Iterator
from typing import BinaryIO

from .reader import fmap_entry

_P: int

def toeplitz_aes_get_table(key: bytes) -> list[int]: ...
def toeplitz_aes_get_tables(key: bytes) -> tuple[list[int], list[int], list[int], list[int]]: ...
def toeplitz_aes_digest64(key: bytes, window: bytes) -> int: ...

class ChunkerToeplitzAES:
    kernel: str
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

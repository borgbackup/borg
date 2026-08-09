import os
from collections.abc import Iterator
from typing import BinaryIO

from .reader import fmap_entry

_GL_P: int

def goldilocks_aes_get_key_elem(key: bytes) -> int: ...
def goldilocks_aes_get_tables(key: bytes) -> tuple[list[int], list[int], list[int]]: ...
def goldilocks_aes_digest64(k: int, window: bytes) -> int: ...
def goldilocks_aes_scan_all(k: int, aes_key: bytes, data: bytes, mask: int, force_sw: bool = False) -> list[int]: ...

class ChunkerGoldilocksAES:
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
    def chunkify(
        self, fd: BinaryIO = None, fh: int = -1, fmap: list[fmap_entry] = None, st: os.stat_result = None
    ) -> Iterator: ...

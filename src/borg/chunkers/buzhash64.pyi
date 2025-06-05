from typing import List, Iterator, BinaryIO

from .reader import fmap_entry

API_VERSION: str

def buzhash(data: bytes, seed: int) -> int: ...
def buzhash_update(sum: int, remove: int, add: int, len: int, seed: int) -> int: ...

class Chunker:
    def __init__(
        self,
        seed: int,
        chunk_min_exp: int,
        chunk_max_exp: int,
        hash_mask_bits: int,
        hash_window_size: int,
        sparse: bool = False,
    ) -> None: ...
    def chunkify(self, fd: BinaryIO = None, fh: int = -1, fmap: List[fmap_entry] = None) -> Iterator: ...

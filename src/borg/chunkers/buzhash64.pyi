from typing import List, Iterator, BinaryIO

from .reader import fmap_entry

API_VERSION: str

def buzhash64(data: bytes, key: bytes) -> int: ...
def buzhash64_update(sum: int, remove: int, add: int, len: int, key: bytes) -> int: ...
def buzhash64_get_table(key: bytes) -> List[int]: ...

class ChunkerBuzHash64:
    def __init__(
        self,
        key: bytes,
        chunk_min_exp: int,
        chunk_max_exp: int,
        hash_mask_bits: int,
        hash_window_size: int,
        sparse: bool = False,
    ) -> None: ...
    def chunkify(self, fd: BinaryIO = None, fh: int = -1, fmap: List[fmap_entry] = None) -> Iterator: ...

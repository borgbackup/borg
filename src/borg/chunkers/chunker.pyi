from typing import List, Iterator, BinaryIO

from .reader import fmap_entry

API_VERSION: str

class ChunkerFixed:
    def __init__(self, block_size: int, header_size: int = 0, sparse: bool = False) -> None: ...
    def chunkify(self, fd: BinaryIO = None, fh: int = -1, fmap: List[fmap_entry] = None) -> Iterator: ...

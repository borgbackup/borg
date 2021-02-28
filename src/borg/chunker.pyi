from typing import NamedTuple, Tuple, List, Dict, Any, Type, Iterator, BinaryIO

API_VERSION: str

has_seek_hole: bool

class _Chunk(NamedTuple):
    data: bytes
    meta: Dict[str, Any]

def Chunk(data: bytes, **meta) -> Type[_Chunk]: ...

def buzhash(data: bytes, seed: int) -> int: ...
def buzhash_update(sum: int, remove: int, add: int, len: int, seed: int) -> int: ...

def get_chunker(algo: str, *params, **kw) -> Any: ...

fmap_entry = Tuple[int, int, bool]

def sparsemap(fd: BinaryIO = None, fh: int = -1) -> List[fmap_entry]: ...


class ChunkerFixed:
    def __init__(self, block_size: int, header_size: int = 0, sparse: bool = False) -> None: ...
    def chunkify(self, fd: BinaryIO = None, fh: int = -1, fmap: List[fmap_entry] = None) -> Iterator: ...


class Chunker:
    def __init__(self, seed: int, chunk_min_exp: int, chunk_max_exp: int, hash_mask_bits: int,
                 hash_window_size: int) -> None: ...
    def chunkify(self, fd: BinaryIO = None, fh: int = -1) -> Iterator: ...

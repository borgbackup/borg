from typing import NamedTuple, Tuple, Dict, List, Any, Type, BinaryIO, Iterator

API_VERSION: str

has_seek_hole: bool

class _Chunk(NamedTuple):
    data: bytes
    meta: Dict[str, Any]

def Chunk(data: bytes, **meta) -> Type[_Chunk]: ...

fmap_entry = Tuple[int, int, bool]

def sparsemap(fd: BinaryIO = None, fh: int = -1) -> List[fmap_entry]: ...

class FileFMAPReader:
    def __init__(
        self,
        *,
        fd: BinaryIO = None,
        fh: int = -1,
        read_size: int = 0,
        sparse: bool = False,
        fmap: List[fmap_entry] = None,
    ) -> None: ...
    def _build_fmap(self) -> List[fmap_entry]: ...
    def blockify(self) -> Iterator: ...

class FileReader:
    def __init__(
        self,
        *,
        fd: BinaryIO = None,
        fh: int = -1,
        read_size: int = 0,
        sparse: bool = False,
        fmap: List[fmap_entry] = None,
    ) -> None: ...
    def _fill_buffer(self) -> bool: ...
    def read(self, size: int) -> Type[_Chunk]: ...

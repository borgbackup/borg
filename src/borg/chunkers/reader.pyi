from collections.abc import Iterator
from typing import Any, BinaryIO, NamedTuple

has_seek_hole: bool

class _Chunk(NamedTuple):
    data: bytes | None
    meta: dict[str, Any]

def Chunk(data: bytes | None, **meta) -> type[_Chunk]: ...

fmap_entry = tuple[int, int, bool]

def sparsemap(fd: BinaryIO = None, fh: int = -1) -> list[fmap_entry]: ...

class FileFMAPReader:
    def __init__(
        self,
        *,
        fd: BinaryIO = None,
        fh: int = -1,
        read_size: int = 0,
        sparse: bool = False,
        fmap: list[fmap_entry] = None,
    ) -> None: ...
    def _build_fmap(self) -> list[fmap_entry]: ...
    def blockify(self) -> Iterator: ...

class FileReader:
    def __init__(
        self,
        *,
        fd: BinaryIO = None,
        fh: int = -1,
        read_size: int = 0,
        sparse: bool = False,
        fmap: list[fmap_entry] = None,
    ) -> None: ...
    def _fill_buffer(self) -> bool: ...
    def read(self, size: int) -> type[_Chunk]: ...

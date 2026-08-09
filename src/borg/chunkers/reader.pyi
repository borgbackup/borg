import os
from collections.abc import Iterator
from typing import Any, BinaryIO, NamedTuple

has_seek_hole: bool

class _Chunk(NamedTuple):
    data: bytes | memoryview | None
    meta: dict[str, Any]

def Chunk(data: bytes | memoryview | None, **meta) -> type[_Chunk]: ...
def release_chunk_data(data: bytes | memoryview | None) -> None: ...

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
        st: os.stat_result = None,
    ) -> None: ...
    def _fill_buffer(self) -> bool: ...
    def _readinto_direct(self, tv: memoryview, size: int) -> int: ...
    def read(self, size: int) -> type[_Chunk]: ...
    def readinto(self, target: bytearray | memoryview, size: int) -> int: ...

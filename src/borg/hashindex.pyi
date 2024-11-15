from typing import NamedTuple, Tuple, Type, Union, IO, Iterator, Any

API_VERSION: str

PATH_OR_FILE = Union[str, IO]

class ChunkIndexEntry(NamedTuple):
    flags: int
    size: int

CIE = Union[Tuple[int, int], Type[ChunkIndexEntry]]

class ChunkIndex:
    F_NONE: int
    F_USED: int
    F_COMPRESS: int
    F_NEW: int
    M_USER: int
    M_SYSTEM: int
    def add(self, key: bytes, size: int) -> None: ...
    def iteritems(self, *, only_new: bool = ...) -> Iterator: ...
    def clear_new(self) -> None: ...
    def __contains__(self, key: bytes) -> bool: ...
    def __getitem__(self, key: bytes) -> Type[ChunkIndexEntry]: ...
    def __setitem__(self, key: bytes, value: CIE) -> None: ...

class NSIndex1Entry(NamedTuple):
    segment: int
    offset: int

class NSIndex1:  # legacy
    def iteritems(self, *args, **kwargs) -> Iterator: ...
    def __contains__(self, key: bytes) -> bool: ...
    def __getitem__(self, key: bytes) -> Any: ...
    def __setitem__(self, key: bytes, value: Any) -> None: ...

class FuseVersionsIndexEntry(NamedTuple):
    version: int
    hash: bytes

class FuseVersionsIndex:
    def __contains__(self, key: bytes) -> bool: ...
    def __getitem__(self, key: bytes) -> Any: ...
    def __setitem__(self, key: bytes, value: Any) -> None: ...

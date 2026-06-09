from typing import NamedTuple, Tuple, Type, IO, Iterator, Any, MutableMapping

PATH_OR_FILE = str | IO

class HTProxyMixin(MutableMapping): ...

class ChunkIndexEntry(NamedTuple):
    flags: int
    size: int  # plaintext chunk size
    pack_id: bytes
    obj_offset: int
    obj_size: int

CIE = Tuple[int, int, bytes, int, int] | Type[ChunkIndexEntry]

class ChunkIndex:
    F_NONE: int
    F_USED: int
    F_COMPRESS: int
    F_NEW: int
    M_USER: int
    M_SYSTEM: int
    def add(self, key: bytes, size: int) -> None: ...
    def update_pack_info(self, pack_results: list | None) -> None: ...
    def iteritems(self, *, only_new: bool = ...) -> Iterator: ...
    def clear_new(self) -> None: ...
    def __contains__(self, key: bytes) -> bool: ...
    def __getitem__(self, key: bytes) -> Type[ChunkIndexEntry]: ...
    def __setitem__(self, key: bytes, value: CIE) -> None: ...

class FuseVersionsIndexEntry(NamedTuple):
    version: int
    hash: bytes

class FuseVersionsIndex:
    def __contains__(self, key: bytes) -> bool: ...
    def __getitem__(self, key: bytes) -> Any: ...
    def __setitem__(self, key: bytes, value: Any) -> None: ...

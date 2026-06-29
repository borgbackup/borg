from collections.abc import MutableMapping
from collections import namedtuple
import os
import struct

from borghash import HashTableNT

from ..hashindex import HTProxyMixin


NSIndex1Entry = namedtuple("NSIndex1Entry", "segment offset")
NSIndex1EntryFormatT = namedtuple("NSIndex1EntryFormatT", "segment offset")
NSIndex1EntryFormat = NSIndex1EntryFormatT(segment="I", offset="I")


class NSIndex1(HTProxyMixin, MutableMapping):
    """
    Mapping from key256 to (segment32, offset32), as used by the legacy repository index of Borg 1.x.
    """

    MAX_VALUE = 2**32 - 1  # borghash has the full uint32_t range
    MAGIC = b"BORG_IDX"  # borg 1.x
    HEADER_FMT = "<8sIIBB"  # magic, entries, buckets, ksize, vsize
    KEY_SIZE = 32
    VALUE_SIZE = 8

    def __init__(self, capacity=1000, path=None, usable=None):
        if usable is not None:
            capacity = usable * 2  # load factor 0.5
        self.ht = HashTableNT(
            key_size=self.KEY_SIZE, value_type=NSIndex1Entry, value_format=NSIndex1EntryFormat, capacity=capacity
        )
        if path:
            self._read(path)

    def iteritems(self, marker=None):
        do_yield = marker is None
        for key, value in self.ht.items():
            if do_yield:
                yield key, value
            else:
                do_yield = key == marker

    @classmethod
    def read(cls, path):
        return cls(path=path)

    def size(self):
        return self.ht.size()  # not quite correct as this is not the on-disk read-only format.

    def write(self, path):
        if isinstance(path, str):
            with open(path, "wb") as fd:
                self._write_fd(fd)
        else:
            self._write_fd(path)

    def _read(self, path):
        if isinstance(path, str):
            with open(path, "rb") as fd:
                self._read_fd(fd)
        else:
            self._read_fd(path)

    def _write_fd(self, fd):
        used = len(self.ht)
        header_bytes = struct.pack(self.HEADER_FMT, self.MAGIC, used, used, self.KEY_SIZE, self.VALUE_SIZE)
        fd.write(header_bytes)
        hash_part = getattr(fd, "hash_part", None)
        if hash_part:
            hash_part("HashHeader")
        count = 0
        for key, _ in self.ht.items():
            value = self.ht._get_raw(key)
            fd.write(key)
            fd.write(value)
            count += 1
        assert count == used

    def _read_fd(self, fd):
        header_size = struct.calcsize(self.HEADER_FMT)
        header_bytes = fd.read(header_size)
        if len(header_bytes) < header_size:
            raise ValueError("Invalid file: file is too short (header).")
        hash_part = getattr(fd, "hash_part", None)
        if hash_part:
            hash_part("HashHeader")
        magic, entries, buckets, ksize, vsize = struct.unpack(self.HEADER_FMT, header_bytes)
        if magic != self.MAGIC:
            raise ValueError(f"Invalid file: magic {self.MAGIC.decode()} not found.")
        if ksize != self.KEY_SIZE:
            raise ValueError("Invalid key size")
        if vsize != self.VALUE_SIZE:
            raise ValueError("Invalid value size")
        buckets_size = buckets * (ksize + vsize)
        current_pos = fd.tell()
        end_of_file = fd.seek(0, os.SEEK_END)
        if current_pos + buckets_size != end_of_file:
            raise ValueError("Invalid file: file size does not match (buckets).")
        fd.seek(current_pos)
        for i in range(buckets):
            key = fd.read(ksize)
            value = fd.read(vsize)
            if value.startswith(b"\xff\xff\xff\xff"):  # LE for 0xffffffff (empty/unused bucket)
                continue
            if value.startswith(b"\xfe\xff\xff\xff"):  # LE for 0xfffffffe (deleted/tombstone bucket)
                continue
            self.ht._set_raw(key, value)
        pos = fd.tell()
        if pos != end_of_file:
            raise ValueError(f"Expected pos ({pos}) to be at end_of_file ({end_of_file})")

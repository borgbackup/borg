API_VERSION = "1.2_01"

import os
import errno
from typing import BinaryIO, Iterator

from ..constants import CH_DATA
from .reader import Chunk


class ChunkerFailing:
    """
    This is a very simple chunker for testing purposes.

    Reads block_size chunks, starts failing at block <fail_start>, <fail_count> failures, then succeeds.
    """

    def __init__(self, block_size: int, map: str) -> None:
        self.block_size = block_size
        # one char per block: r/R = successful read, e/E = I/O Error, e.g.: "rrrrErrrEEr"
        # blocks beyond the map will have same behaviour as the last map char indicates.
        map = map.upper()
        if not set(map).issubset({"R", "E"}):
            raise ValueError("unsupported map character")
        self.map = map
        self.count = 0
        self.chunking_time = 0.0  # not updated, just provided so that caller does not crash

    def chunkify(self, fd: BinaryIO = None, fh: int = -1) -> Iterator:
        """
        Cut a file into chunks.

        :param fd: Python file object
        :param fh: OS-level file handle (if available),
                   defaults to -1 which means not to use OS-level fd.
        """
        use_fh = fh >= 0
        wanted = self.block_size
        while True:
            data = os.read(fh, wanted) if use_fh else fd.read(wanted)
            got = len(data)
            if got > 0:
                idx = self.count if self.count < len(self.map) else -1
                behaviour = self.map[idx]
                if behaviour == "E":
                    self.count += 1
                    fname = None if use_fh else getattr(fd, "name", None)
                    raise OSError(errno.EIO, "simulated I/O error", fname)
                elif behaviour == "R":
                    self.count += 1
                    yield Chunk(data, size=got, allocation=CH_DATA)
                else:
                    raise ValueError("unsupported map character")
            if got < wanted:
                # we did not get enough data, looks like EOF.
                return

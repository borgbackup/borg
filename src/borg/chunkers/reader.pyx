# cython: language_level=3

API_VERSION = '1.2_01'

import os
import errno
import time
from collections import namedtuple

from ..platform import safe_fadvise
from ..constants import CH_DATA, CH_ALLOC, CH_HOLE, zeros

# this will be True if Python's seek implementation supports data/holes seeking.
# this does not imply that it will actually work on the filesystem,
# because the FS also needs to support this.
has_seek_hole = hasattr(os, 'SEEK_DATA') and hasattr(os, 'SEEK_HOLE')

_Chunk = namedtuple('_Chunk', 'meta data')
_Chunk.__doc__ = """\
    Chunk namedtuple

    meta is always a dictionary, data depends on allocation.

    data chunk read from a DATA range of a file (not from a sparse hole):
        meta = {'allocation' = CH_DATA, 'size' = size_of_chunk }
        data = read_data [bytes or memoryview]

    all-zero chunk read from a DATA range of a file (not from a sparse hole, but detected to be all-zero):
        meta = {'allocation' = CH_ALLOC, 'size' = size_of_chunk }
        data = None

    all-zero chunk from a HOLE range of a file (from a sparse hole):
        meta = {'allocation' = CH_HOLE, 'size' = size_of_chunk }
        data = None
"""

def Chunk(data, **meta):
    return _Chunk(meta, data)


def dread(offset, size, fd=None, fh=-1):
    use_fh = fh >= 0
    if use_fh:
        data = os.read(fh, size)
        safe_fadvise(fh, offset, len(data), "DONTNEED")
        return data
    else:
        return fd.read(size)


def dseek(amount, whence, fd=None, fh=-1):
    use_fh = fh >= 0
    if use_fh:
        return os.lseek(fh, amount, whence)
    else:
        return fd.seek(amount, whence)


def dpos_curr_end(fd=None, fh=-1):
    """
    determine current position, file end position (== file length)
    """
    curr = dseek(0, os.SEEK_CUR, fd, fh)
    end = dseek(0, os.SEEK_END, fd, fh)
    dseek(curr, os.SEEK_SET, fd, fh)
    return curr, end


def sparsemap(fd=None, fh=-1):
    """
    generator yielding a (start, length, is_data) tuple for each range.
    is_data is indicating data ranges (True) or hole ranges (False).

    note:
    the map is generated starting from the current seek position (it
    is not required to be 0 / to be at the start of the file) and
    work from there up to the end of the file.
    when the generator is finished, the file pointer position will be
    reset to where it was before calling this function.
    """
    curr, file_len = dpos_curr_end(fd, fh)
    start = curr
    try:
        whence = os.SEEK_HOLE
        while True:
            is_data = whence == os.SEEK_HOLE  # True: range with data, False: range is a hole
            try:
                end = dseek(start, whence, fd, fh)
            except OSError as e:
                if e.errno == errno.ENXIO:
                    if not is_data and start < file_len:
                        # if there is a hole at the end of a file, we can not find the file end by SEEK_DATA
                        # (because we run into ENXIO), thus we must manually deal with this case:
                        end = file_len
                        yield (start, end - start, is_data)
                    break
                else:
                    raise
            # we do not want to yield zero-length ranges with start == end:
            if end > start:
                yield (start, end - start, is_data)
            start = end
            whence = os.SEEK_DATA if is_data else os.SEEK_HOLE
    finally:
        # seek to same position as before calling this function
        dseek(curr, os.SEEK_SET, fd, fh)


class FileFMAPReader:
    """
    This is for reading blocks from a file.

    It optionally supports:

    - using a sparsemap to read only data ranges and seek over hole ranges
      for sparse files.
    - using an externally given filemap to read only specific ranges from
      a file.

    Note: the last block of a data or hole range may be less than the read_size,
          this is supported and not considered to be an error.
    """
    def __init__(self, *, fd=None, fh=-1, read_size=0, sparse=False, fmap=None):
        assert fd is not None or fh >= 0
        self.fd = fd
        self.fh = fh
        assert 0 < read_size <= len(zeros)
        self.read_size = read_size  # how much data we want to read at once
        self.reading_time = 0.0  # time spent in reading/seeking
        # should borg try to do sparse input processing?
        # whether it actually can be done depends on the input file being seekable.
        self.try_sparse = sparse and has_seek_hole
        self.fmap = fmap

    def _build_fmap(self):
        started_fmap = time.monotonic()
        fmap = None
        if self.try_sparse:
            try:
                fmap = list(sparsemap(self.fd, self.fh))
            except OSError as err:
                # seeking did not work
                pass

        if fmap is None:
            # either sparse processing (building the fmap) was not tried or it failed.
            # in these cases, we just build a "fake fmap" that considers the whole file
            # as range(s) of data (no holes), so we can use the same code.
            fmap = [(0, 2 ** 62, True), ]
        self.reading_time += time.monotonic() - started_fmap
        return fmap

    def blockify(self):
        """
        Read <read_size> sized blocks from a file.
        """
        if self.fmap is None:
            self.fmap = self._build_fmap()

        offset = 0
        for range_start, range_size, is_data in self.fmap:
            if range_start != offset:
                # this is for the case when the fmap does not cover the file completely,
                # e.g. it could be without the ranges of holes or of unchanged data.
                offset = range_start
                dseek(offset, os.SEEK_SET, self.fd, self.fh)
            while range_size:
                started_reading = time.monotonic()
                wanted = min(range_size, self.read_size)
                if is_data:
                    # read block from the range
                    data = dread(offset, wanted, self.fd, self.fh)
                    got = len(data)
                    if zeros.startswith(data):
                        data = None
                        allocation = CH_ALLOC
                    else:
                        allocation = CH_DATA
                else:  # hole
                    # seek over block from the range
                    pos = dseek(wanted, os.SEEK_CUR, self.fd, self.fh)
                    got = pos - offset
                    data = None
                    allocation = CH_HOLE
                self.reading_time += time.monotonic() - started_reading
                if got > 0:
                    offset += got
                    range_size -= got
                    yield Chunk(data, size=got, allocation=allocation)
                if got < wanted:
                    # we did not get enough data, looks like EOF.
                    return


class FileReader:
    """
    This is a buffered reader for file data.

    It maintains a buffer that is filled with Chunks from the FileFMAPReader.blockify generator.
    The data in that buffer is consumed by clients calling FileReader.read, which returns a Chunk.

    Most complexity in here comes from the desired size when a user calls FileReader.read does
    not need to match the Chunk sizes we got from the FileFMAPReader.
    """
    def __init__(self, *, fd=None, fh=-1, read_size=0, sparse=False, fmap=None):
        assert read_size > 0
        self.reader = FileFMAPReader(fd=fd, fh=fh, read_size=read_size, sparse=sparse, fmap=fmap)
        self.buffer = []  # list of Chunk objects
        self.offset = 0  # offset into the first buffer object's data
        self.remaining_bytes = 0  # total bytes available in buffer
        self.blockify_gen = None  # generator from FileFMAPReader.blockify
        self.fd = fd
        self.fh = fh
        self.fmap = fmap

    def _fill_buffer(self):
        """
        Fill the buffer with more data from the blockify generator.
        Returns True if more data was added, False if EOF.
        """
        if self.blockify_gen is None:
            return False

        try:
            chunk = next(self.blockify_gen)
            # Store the Chunk object directly in the buffer
            self.buffer.append(chunk)
            self.remaining_bytes += chunk.meta["size"]
            return True
        except StopIteration:
            self.blockify_gen = None
            return False

    def read(self, size):
        """
        Read a Chunk of up to 'size' bytes from the file.

        This method tries to yield a Chunk of the requested size, if possible, by considering
        multiple chunks from the buffer.

        The allocation type of the resulting chunk depends on the allocation types of the contributing chunks:
        - If one of the chunks is CH_DATA, it will create all-zero bytes for other chunks that are not CH_DATA
        - If all contributing chunks are CH_HOLE, the resulting chunk will also be CH_HOLE
        - If the contributing chunks are a mix of CH_HOLE and CH_ALLOC, the resulting chunk will be CH_HOLE

        :param size: Number of bytes to read
        :return: Chunk object containing the read data.
                 If no data is available, returns Chunk(None, size=0, allocation=CH_ALLOC).
                 If less than requested bytes were available (at EOF), the returned chunk might be smaller
                 than requested.
        """
        # Initialize if not already done
        if self.blockify_gen is None:
            self.buffer = []
            self.offset = 0
            self.remaining_bytes = 0
            self.blockify_gen = self.reader.blockify()

        # If we don't have enough data in the buffer, try to fill it
        while self.remaining_bytes < size:
            if not self._fill_buffer():
                # No more data available, return what we have
                break

        # If we have no data at all, return an empty Chunk
        if not self.buffer:
            return Chunk(b"", size=0, allocation=CH_DATA)

        # Prepare to collect the requested data
        result = bytearray()
        bytes_to_read = min(size, self.remaining_bytes)
        bytes_read = 0

        # Track if we've seen different allocation types
        has_data = False
        has_hole = False
        has_alloc = False

        # Read data from the buffer, combining chunks as needed
        while bytes_read < bytes_to_read and self.buffer:
            chunk = self.buffer[0]
            chunk_size = chunk.meta["size"]
            allocation = chunk.meta["allocation"]
            data = chunk.data

            # Track allocation types
            if allocation == CH_DATA:
                has_data = True
            elif allocation == CH_HOLE:
                has_hole = True
            elif allocation == CH_ALLOC:
                has_alloc = True
            else:
                raise ValueError(f"Invalid allocation type: {allocation}")

            # Calculate how much we can read from this chunk
            available = chunk_size - self.offset
            to_read = min(available, bytes_to_read - bytes_read)

            # Process the chunk based on its allocation type
            if allocation == CH_DATA:
                assert data is not None
                # For data chunks, add the actual data
                result.extend(data[self.offset:self.offset + to_read])
            else:
                # For non-data chunks, add zeros if we've seen a data chunk
                if has_data:
                    result.extend(b'\0' * to_read)
                # Otherwise, we'll just track the size without adding data

            bytes_read += to_read

            # Update offset or remove chunk if fully consumed
            if to_read < available:
                self.offset += to_read
            else:
                self.offset = 0
                self.buffer.pop(0)

            self.remaining_bytes -= to_read

        # Determine the allocation type of the resulting chunk
        if has_data:
            # If any chunk was CH_DATA, the result is CH_DATA
            return Chunk(bytes(result), size=bytes_read, allocation=CH_DATA)
        elif has_hole:
            # If any chunk was CH_HOLE (and none were CH_DATA), the result is CH_HOLE
            return Chunk(None, size=bytes_read, allocation=CH_HOLE)
        else:
            # Otherwise, all chunks were CH_ALLOC
            return Chunk(None, size=bytes_read, allocation=CH_ALLOC)



# cython: language_level=3



import os
import errno
import stat
import time
from collections import namedtuple

from ..platform import safe_fadvise
from ..constants import CH_DATA, CH_ALLOC, CH_HOLE, zeros

# this will be True if Python's seek implementation supports data/holes seeking.
# this does not imply that it will actually work on the filesystem,
# because the FS also needs to support this.
has_seek_hole = hasattr(os, 'SEEK_DATA') and hasattr(os, 'SEEK_HOLE')

# os.readv is POSIX; on platforms without it (win32) we fall back to os.read + copy.
has_readv = hasattr(os, 'readv')

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

    Attention: after consuming a chunk, call release_chunk_data(chunk.data)!
    Otherwise, the memory backing a memoryview is not freed timely (CPython)
    or even never freed (pypy: dropped, but unreleased memoryviews over
    C-API-created bytes objects are never reclaimed by the GC there).
"""

def Chunk(data, **meta):
    return _Chunk(meta, data)


def release_chunk_data(data):
    """Release chunk data (as yielded by a chunker) after use.

    Explicitly releasing the memoryview frees the underlying buffer timely.
    This is especially important on pypy: there, a dropped (but not released)
    memoryview over a C-API-created bytes object pins the buffer via cpyext
    and the memory is never reclaimed, not even by gc.collect().
    """
    if isinstance(data, memoryview):
        data.release()


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
    Generator yielding (start, length, is_data) tuples for each range.
    is_data indicates data ranges (True) or hole ranges (False).

    Note:
    The map is generated starting from the current seek position (it
    is not required to be 0, i.e., the start of the file) and works from there up to the end of the file.
    When the generator is finished, the file pointer position will be
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
            except (OSError, ValueError) as err:
                # Building a sparse map failed:
                # - OSError: low-level lseek with SEEK_HOLE/SEEK_DATA not supported by FS/OS.
                # - ValueError: high-level file objects (e.g. io.BytesIO or some fd wrappers)
                #   don't accept SEEK_HOLE/SEEK_DATA as a valid "whence" and raise ValueError.
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
                    # Detect zero-filled blocks regardless of sparse mode.
                    # Zero detection is important to avoid reading/storing allocated zeros
                    # even when we are not using sparse file handling based on SEEK_HOLE/SEEK_DATA.
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
                    # We did not get enough data; looks like EOF.
                    return


class FileReader:
    """
    This is a buffered reader for file data.

    It maintains a buffer that is filled with Chunks from the FileFMAPReader.blockify generator.
    The data in that buffer is consumed by clients calling FileReader.read, which returns a Chunk.

    Most complexity in here comes from the desired size when a user calls FileReader.read does
    not need to match the Chunk sizes we got from the FileFMAPReader.
    """
    def __init__(self, *, fd=None, fh=-1, read_size=0, sparse=False, fmap=None, st=None):
        assert read_size > 0
        self.reader = FileFMAPReader(fd=fd, fh=fh, read_size=read_size, sparse=sparse, fmap=fmap)
        self.buffer = []  # list of Chunk objects
        self.offset = 0  # offset into the first buffer object's data
        self.remaining_bytes = 0  # total bytes available in buffer
        self.blockify_gen = None  # generator from FileFMAPReader.blockify
        self.fd = fd
        self.fh = fh
        self.fmap = fmap
        # Without sparse processing and without a given fmap there are no ranges to
        # consider - the file is read start to end. readinto() then reads directly
        # from the file into the caller's buffer (see there), instead of going
        # through the block reader.
        # Only known regular files take the direct path: reading FIFOs / devices via
        # --read-special must keep using the proven block reader path - e.g. NetBSD 10
        # was seen blocking forever in the direct path's big readv() on a FIFO, where
        # the block reader's 1 MiB os.read() calls work fine.
        self.direct = False
        if not sparse and fmap is None:
            if st is None:
                # caller did not have a stat result at hand - determine the file type here.
                try:
                    if fh >= 0:
                        st = os.fstat(fh)
                    elif fd is not None:
                        st = os.fstat(fd.fileno())
                except (AttributeError, OSError):
                    pass  # no OS-level fd (e.g. BytesIO, wrapper objects) - stay on the block reader path
            self.direct = st is not None and stat.S_ISREG(st.st_mode)
        self.direct_offset = 0  # bytes read so far via the direct path (for fadvise)

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
                # For non-data chunks, always add zeros to the result.
                # We will only yield a CH_DATA chunk with the result bytes,
                # if there was at least one CH_DATA chunk contributing to the result,
                # otherwise we will yield a CH_HOLE or CH_ALLOC chunk.
                result.extend(b'\0' * to_read)

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
            # If any chunk was CH_DATA, check if the result is all zeros.
            # This can happen when a large CH_DATA block (read at read_size granularity)
            # contains both real data and zero-filled regions, and we are slicing out
            # a zero-filled portion at the block_size granularity.
            if zeros.startswith(result):
                return Chunk(None, size=bytes_read, allocation=CH_ALLOC)
            return Chunk(bytes(result), size=bytes_read, allocation=CH_DATA)
        elif has_hole:
            # If any chunk was CH_HOLE (and none were CH_DATA), the result is CH_HOLE
            return Chunk(None, size=bytes_read, allocation=CH_HOLE)
        else:
            # Otherwise, all chunks were CH_ALLOC
            return Chunk(None, size=bytes_read, allocation=CH_ALLOC)

    def _readinto_direct(self, tv, size):
        """Read up to 'size' bytes from the file directly into 'tv' (a writable memoryview)."""
        pos = 0
        while pos < size:
            if self.fh >= 0:
                if has_readv:
                    got = os.readv(self.fh, [tv[pos:size]])
                else:
                    data = os.read(self.fh, size - pos)
                    got = len(data)
                    tv[pos:pos + got] = data
                if got > 0:
                    safe_fadvise(self.fh, self.direct_offset, got, "DONTNEED")
            else:
                try:
                    got = self.fd.readinto(tv[pos:size])
                except AttributeError:
                    # file-like object without readinto: fall back to read + copy
                    data = self.fd.read(size - pos)
                    got = len(data)
                    tv[pos:pos + got] = data
            if not got:
                break  # EOF
            pos += got
            self.direct_offset += got
        return pos

    def readinto(self, target, size):
        """
        Read up to 'size' bytes from the file directly into 'target' (a writable
        buffer, e.g. a memoryview over the caller's scan buffer).

        Fast path (known regular file, no sparse processing, no fmap given):
        the file data is read by the OS directly into 'target' - zero copies
        in user space and one syscall per request instead of one per block.

        Otherwise, unlike read(), this does not allocate or combine intermediate
        byte objects: each byte is copied exactly once, from the buffered file
        block into 'target'. Ranges stemming from holes / all-zero blocks are
        written as zero bytes ('target' may contain stale data). The caller
        detects all-zero chunks itself at chunk granularity, so no allocation
        type is returned.

        :param target: writable buffer, len(target) >= size
        :param size: number of bytes to read
        :return: number of bytes written to target (0 at EOF).
        """
        if self.direct and self.blockify_gen is None:
            # blockify_gen check: if read() was used on this reader before, keep
            # using the buffered path, for consistent file position and buffer state.
            with memoryview(target) as tv:
                return self._readinto_direct(tv, size)

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

        if not self.buffer:
            return 0

        with memoryview(target) as tv:
            bytes_to_read = min(size, self.remaining_bytes)
            bytes_read = 0
            while bytes_read < bytes_to_read and self.buffer:
                chunk = self.buffer[0]
                chunk_size = chunk.meta["size"]
                allocation = chunk.meta["allocation"]
                data = chunk.data

                if allocation not in (CH_DATA, CH_HOLE, CH_ALLOC):
                    raise ValueError(f"Invalid allocation type: {allocation}")

                # Calculate how much we can read from this chunk
                available = chunk_size - self.offset
                to_read = min(available, bytes_to_read - bytes_read)

                if allocation == CH_DATA:
                    assert data is not None
                    # one memcpy: block -> target (the source slice is a view, not a copy)
                    with memoryview(data) as dv:
                        tv[bytes_read:bytes_read + to_read] = dv[self.offset:self.offset + to_read]
                else:
                    # holes / all-zero blocks: write zeros (target may contain stale data)
                    tv[bytes_read:bytes_read + to_read] = zeros[:to_read]

                bytes_read += to_read

                # Update offset or remove chunk if fully consumed
                if to_read < available:
                    self.offset += to_read
                else:
                    self.offset = 0
                    self.buffer.pop(0)

                self.remaining_bytes -= to_read

        return bytes_read


import logging
import io
import os
import os.path
import platform
import sys
from collections import deque, OrderedDict
from datetime import datetime, timezone, timedelta
from itertools import islice
from operator import attrgetter

from ..logger import create_logger

logger = create_logger()

from .time import to_localtime
from . import msgpack
from .. import __version__ as borg_version
from .. import chunker


def prune_within(archives, hours, kept_because):
    target = datetime.now(timezone.utc) - timedelta(seconds=hours * 3600)
    kept_counter = 0
    result = []
    for a in archives:
        if a.ts > target:
            kept_counter += 1
            kept_because[a.id] = ("within", kept_counter)
            result.append(a)
    return result


PRUNING_PATTERNS = OrderedDict(
    [
        ("secondly", "%Y-%m-%d %H:%M:%S"),
        ("minutely", "%Y-%m-%d %H:%M"),
        ("hourly", "%Y-%m-%d %H"),
        ("daily", "%Y-%m-%d"),
        ("weekly", "%G-%V"),
        ("monthly", "%Y-%m"),
        ("yearly", "%Y"),
    ]
)


def prune_split(archives, rule, n, kept_because=None):
    last = None
    keep = []
    pattern = PRUNING_PATTERNS[rule]
    if kept_because is None:
        kept_because = {}
    if n == 0:
        return keep

    a = None
    for a in sorted(archives, key=attrgetter("ts"), reverse=True):
        period = to_localtime(a.ts).strftime(pattern)
        if period != last:
            last = period
            if a.id not in kept_because:
                keep.append(a)
                kept_because[a.id] = (rule, len(keep))
                if len(keep) == n:
                    break
    # Keep oldest archive if we didn't reach the target retention count
    if a is not None and len(keep) < n and a.id not in kept_because:
        keep.append(a)
        kept_because[a.id] = (rule + "[oldest]", len(keep))
    return keep


def sysinfo():
    show_sysinfo = os.environ.get("BORG_SHOW_SYSINFO", "yes").lower()
    if show_sysinfo == "no":
        return ""

    python_implementation = platform.python_implementation()
    python_version = platform.python_version()
    # platform.uname() does a shell call internally to get processor info,
    # creating #3732 issue, so rather use os.uname().
    try:
        uname = os.uname()
    except AttributeError:
        uname = None
    if sys.platform.startswith("linux"):
        linux_distribution = ("Unknown Linux", "", "")
    else:
        linux_distribution = None
    try:
        msgpack_version = ".".join(str(v) for v in msgpack.version)
    except:
        msgpack_version = "unknown"
    from ..fuse_impl import llfuse, BORG_FUSE_IMPL

    llfuse_name = llfuse.__name__ if llfuse else "None"
    llfuse_version = (" %s" % llfuse.__version__) if llfuse else ""
    llfuse_info = f"{llfuse_name}{llfuse_version} [{BORG_FUSE_IMPL}]"
    info = []
    if uname is not None:
        info.append("Platform: {}".format(" ".join(uname)))
    if linux_distribution is not None:
        info.append("Linux: %s %s %s" % linux_distribution)
    info.append(
        "Borg: {}  Python: {} {} msgpack: {} fuse: {}".format(
            borg_version, python_implementation, python_version, msgpack_version, llfuse_info
        )
    )
    info.append("PID: %d  CWD: %s" % (os.getpid(), os.getcwd()))
    info.append("sys.argv: %r" % sys.argv)
    info.append("SSH_ORIGINAL_COMMAND: %r" % os.environ.get("SSH_ORIGINAL_COMMAND"))
    info.append("")
    return "\n".join(info)


def log_multi(*msgs, level=logging.INFO, logger=logger):
    """
    log multiple lines of text, each line by a separate logging call for cosmetic reasons

    each positional argument may be a single or multiple lines (separated by newlines) of text.
    """
    lines = []
    for msg in msgs:
        lines.extend(msg.splitlines())
    for line in lines:
        logger.log(level, line)


class ChunkIteratorFileWrapper:
    """File-like wrapper for chunk iterators"""

    def __init__(self, chunk_iterator, read_callback=None):
        """
        *chunk_iterator* should be an iterator yielding bytes. These will be buffered
        internally as necessary to satisfy .read() calls.

        *read_callback* will be called with one argument, some byte string that has
        just been read and will be subsequently returned to a caller of .read().
        It can be used to update a progress display.
        """
        self.chunk_iterator = chunk_iterator
        self.chunk_offset = 0
        self.chunk = b""
        self.exhausted = False
        self.read_callback = read_callback

    def _refill(self):
        remaining = len(self.chunk) - self.chunk_offset
        if not remaining:
            try:
                chunk = next(self.chunk_iterator)
                self.chunk = memoryview(chunk)
            except StopIteration:
                self.exhausted = True
                return 0  # EOF
            self.chunk_offset = 0
            remaining = len(self.chunk)
        return remaining

    def _read(self, nbytes):
        if not nbytes:
            return b""
        remaining = self._refill()
        will_read = min(remaining, nbytes)
        self.chunk_offset += will_read
        return self.chunk[self.chunk_offset - will_read : self.chunk_offset]

    def read(self, nbytes):
        parts = []
        while nbytes and not self.exhausted:
            read_data = self._read(nbytes)
            nbytes -= len(read_data)
            parts.append(read_data)
            if self.read_callback:
                self.read_callback(read_data)
        return b"".join(parts)


def open_item(archive, item):
    """Return file-like object for archived item (with chunks)."""
    chunk_iterator = archive.pipeline.fetch_many([c.id for c in item.chunks])
    return ChunkIteratorFileWrapper(chunk_iterator)


def chunkit(it, size):
    """
    Chunk an iterator <it> into pieces of <size>.

    >>> list(chunker('ABCDEFG', 3))
    [['A', 'B', 'C'], ['D', 'E', 'F'], ['G']]
    """
    iterable = iter(it)
    return iter(lambda: list(islice(iterable, size)), [])


def consume(iterator, n=None):
    """Advance the iterator n-steps ahead. If n is none, consume entirely."""
    # Use functions that consume iterators at C speed.
    if n is None:
        # feed the entire iterator into a zero-length deque
        deque(iterator, maxlen=0)
    else:
        # advance to the empty slice starting at position n
        next(islice(iterator, n, n), None)


class ErrorIgnoringTextIOWrapper(io.TextIOWrapper):
    def read(self, n):
        if not self.closed:
            try:
                return super().read(n)
            except BrokenPipeError:
                try:
                    super().close()
                except OSError:
                    pass
        return ""

    def write(self, s):
        if not self.closed:
            try:
                return super().write(s)
            except BrokenPipeError:
                try:
                    super().close()
                except OSError:
                    pass
        return len(s)


def iter_separated(fd, sep=None, read_size=4096):
    """Iter over chunks of open file ``fd`` delimited by ``sep``. Doesn't trim."""
    buf = fd.read(read_size)
    is_str = isinstance(buf, str)
    part = "" if is_str else b""
    sep = sep or ("\n" if is_str else b"\n")
    while len(buf) > 0:
        part2, *items = buf.split(sep)
        *full, part = (part + part2, *items)  # type: ignore
        yield from full
        buf = fd.read(read_size)
    # won't yield an empty part if stream ended with `sep`
    # or if there was no data before EOF
    if len(part) > 0:  # type: ignore[arg-type]
        yield part


def get_tar_filter(fname, decompress):
    # Note that filter is None if fname is '-'.
    if fname.endswith((".tar.gz", ".tgz")):
        filter = "gzip -d" if decompress else "gzip"
    elif fname.endswith((".tar.bz2", ".tbz")):
        filter = "bzip2 -d" if decompress else "bzip2"
    elif fname.endswith((".tar.xz", ".txz")):
        filter = "xz -d" if decompress else "xz"
    elif fname.endswith((".tar.lz4",)):
        filter = "lz4 -d" if decompress else "lz4"
    elif fname.endswith((".tar.zstd",)):
        filter = "zstd -d" if decompress else "zstd"
    else:
        filter = None
    logger.debug("Automatically determined tar filter: %s", filter)
    return filter

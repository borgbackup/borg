import base64
import contextlib
import logging
import os
import posixpath
import stat
import sys
import tarfile
from collections import Counter

if sys.version_info >= (3, 14):
    from compression import zstd
else:
    from backports import zstd

from ..archive import Archive, TarfileObjectProcessors, ChunksProcessor, zero_chunk_flags, zero_chunk_id
from ..compress import get_zstd_mt_workers
from ..constants import *  # NOQA
from ..helpers import Error
from ..helpers import HardLinkManager, IncludePatternNeverMatchedWarning
from ..helpers import ProgressIndicatorPercent
from ..helpers import dash_open
from ..helpers import msgpack
from ..helpers import create_filter_process
from ..helpers import ChunkIteratorFileWrapper
from ..helpers import archivename_validator, comment_validator, PathSpec, ChunkerParams, CompressionSpec
from ..helpers import FilesystemPathSpec
from ..helpers import remove_surrogates
from ..helpers import StableDict, make_path_safe
from ..helpers import timestamp, archive_ts_now
from ..helpers import basic_json_data, json_print
from ..helpers import log_multi
from ..helpers.argparsing import ArgumentParser
from ..manifest import Manifest
from ..platform.solaris import SYSATTR_PREFIX, XATTR_SIZE_LIMIT

from ._common import with_repository, with_archive, Highlander, define_exclusion_group
from ._common import build_matcher, build_filter

from ..logger import create_logger

logger = create_logger(__name__)

# Python 3.12+ gives a deprecation warning if TarFile.extraction_filter is None.
# https://docs.python.org/3.12/library/tarfile.html#tarfile-extraction-filter
if hasattr(tarfile, "fully_trusted_filter"):
    tarfile.TarFile.extraction_filter = staticmethod(tarfile.fully_trusted_filter)  # type: ignore


def item_to_tarinfo(item, hlm, *, warning=None):
    """Transform a Borg *item* into a tarfile.TarInfo object.

    Return a tuple (tarinfo, needs_content): *tarinfo* is None if the item cannot be
    represented as a TarInfo (and should be skipped), else the TarInfo to write.
    *needs_content* is True when the caller must append the item's file content (its
    chunk data) after the header - this is the case for a regular file that is not a
    tar hard link to an earlier one.

    *hlm* is a HardLinkManager(id_type=bytes, info_type=str) mapping an already-emitted
    file's hlid to its (tar) path, so later hard links become tar LNKTYPE references.
    *warning* is an optional callback(format, *args) for reporting unsupported types.
    """
    tarinfo = tarfile.TarInfo()
    tarinfo.name = item.path
    tarinfo.mtime = item.mtime / 1e9
    tarinfo.mode = stat.S_IMODE(item.mode)
    tarinfo.uid = item.get("uid", 0)
    tarinfo.gid = item.get("gid", 0)
    tarinfo.uname = item.get("user", "")
    tarinfo.gname = item.get("group", "")
    # The linkname in tar has 2 uses:
    # for symlinks it means the destination, while for hard links it refers to the file.
    # Since hard links in tar have a different type code (LNKTYPE) the format might
    # support hardlinking arbitrary objects (including symlinks and directories), but
    # whether implementations actually support that is a whole different question...
    tarinfo.linkname = ""

    needs_content = False
    modebits = stat.S_IFMT(item.mode)
    if modebits == stat.S_IFREG:
        tarinfo.type = tarfile.REGTYPE
        if "hlid" in item:
            linkname = hlm.retrieve(id=item.hlid)
            if linkname is not None:
                # the first hard link was already added to the archive, add a tar-hard-link reference to it.
                tarinfo.type = tarfile.LNKTYPE
                tarinfo.linkname = linkname
            else:
                tarinfo.size = item.get_size()
                needs_content = True
                hlm.remember(id=item.hlid, info=item.path)
        else:
            tarinfo.size = item.get_size()
            needs_content = True
    elif modebits == stat.S_IFDIR:
        tarinfo.type = tarfile.DIRTYPE
    elif modebits == stat.S_IFLNK:
        tarinfo.type = tarfile.SYMTYPE
        tarinfo.linkname = item.target
    elif modebits == stat.S_IFBLK:
        tarinfo.type = tarfile.BLKTYPE
        tarinfo.devmajor = os.major(item.rdev)
        tarinfo.devminor = os.minor(item.rdev)
    elif modebits == stat.S_IFCHR:
        tarinfo.type = tarfile.CHRTYPE
        tarinfo.devmajor = os.major(item.rdev)
        tarinfo.devminor = os.minor(item.rdev)
    elif modebits == stat.S_IFIFO:
        tarinfo.type = tarfile.FIFOTYPE
    else:
        if warning is not None:
            warning("%s: unsupported file type %o for tar export", remove_surrogates(item.path), modebits)
        return None, False
    return tarinfo, needs_content


def item_to_paxheaders(format, item):
    """Transform (parts of) a Borg *item* into a pax_headers dict."""
    # PAX format
    # ----------
    # When using the PAX (POSIX) format, we can support some things that aren't possible
    # with classic tar formats, including GNU tar, such as:
    # - atime, ctime (DONE)
    # - possibly Linux capabilities, security.* xattrs (TODO)
    # - various additions supported by GNU tar in POSIX mode (TODO)
    #
    # BORG format
    # -----------
    # This is based on PAX, but additionally adds BORG.* pax headers.
    # Additionally to the standard tar / PAX metadata and data, it transfers
    # ALL borg item metadata in a BORG specific way.
    #
    ph = {}
    # note: for mtime this is a bit redundant as it is already done by tarfile module,
    #       but we just do it in our way to be consistent for sure.
    for name in "atime", "ctime", "mtime":
        if hasattr(item, name):
            ns = getattr(item, name)
            ph[name] = str(ns / 1e9)
    if hasattr(item, "xattrs"):
        for bkey, bvalue in item.xattrs.items():
            # we have bytes key and bytes value, but the tarfile code
            # expects str key and str value.
            key = SCHILY_XATTR + bkey.decode("utf-8", errors="surrogateescape")
            value = bvalue.decode("utf-8", errors="surrogateescape")
            ph[key] = value
    # Add POSIX access and default ACL if present
    acl_access = item.get("acl_access")
    if acl_access is not None:
        ph[SCHILY_ACL_ACCESS] = acl_access.decode("utf-8", errors="surrogateescape")
    acl_default = item.get("acl_default")
    if acl_default is not None:
        ph[SCHILY_ACL_DEFAULT] = acl_default.decode("utf-8", errors="surrogateescape")
    if format == "BORG":  # BORG format additions
        ph["BORG.item.version"] = "1"
        # BORG.item.meta - just serialize all metadata we have:
        meta_bin = msgpack.packb(item.as_dict())
        meta_text = base64.b64encode(meta_bin).decode()
        ph["BORG.item.meta"] = meta_text
    return ph


def chunks_to_sparse_info(chunks, zero_flags):
    """Compute a GNU sparse map from an item's chunk list.

    *zero_flags* tells for each chunk in *chunks* whether it is an all-zero chunk;
    runs of all-zero chunks become the holes of the sparse file. Holes are shrunk
    to whole 512-byte tar blocks (a trailing hole may end unaligned at the file's
    end): GNU tar's sparse reader processes the data segments block-wise, so it
    desyncs on unaligned segments - and this also matches what GNU tar itself
    produces, as its own hole detection is block-granular. The zero bytes shaved
    off the hole edges become part of the neighboring data segments.

    Return a tuple (map_entries, stream_plan, realsize): *map_entries* is a list of
    (offset, length) data segments - with a terminating (realsize, 0) entry if the
    file ends in a hole, like GNU tar creates it -, *stream_plan* tells how to
    produce the data segments' bytes: a list of ChunkListEntry (a chunk to fetch and
    emit completely) and int (a count of zero bytes to emit literally) elements,
    *realsize* is the logical file size.
    Return None if there is no hole (the file shall be a normal dense tar member).
    """
    if not chunks or all(not zero for zero in zero_flags):
        return None
    realsize = sum(chunk.size for chunk in chunks)
    # runs of all-zero chunks, shrunk to 512-byte block alignment, become the holes.
    holes = []

    def add_hole(start, end):
        start = -(-start // tarfile.BLOCKSIZE) * tarfile.BLOCKSIZE
        if end != realsize:  # a trailing hole may end unaligned, gtar just truncates the file
            end = end // tarfile.BLOCKSIZE * tarfile.BLOCKSIZE
        if end > start:
            holes.append((start, end))

    offset = 0
    run_start = None  # start offset of the current run of all-zero chunks
    for chunk, zero in zip(chunks, zero_flags):
        if zero and run_start is None:
            run_start = offset
        elif not zero and run_start is not None:
            add_hole(run_start, offset)
            run_start = None
        offset += chunk.size
    if run_start is not None:
        add_hole(run_start, realsize)
    if not holes:
        return None  # all zero runs were too short to make a block-aligned hole
    # the data segments are the complement of the holes.
    map_entries = []
    pos = 0
    for hole_start, hole_end in holes:
        if hole_start > pos:
            map_entries.append((pos, hole_start - pos))
        pos = hole_end
    if pos < realsize:
        map_entries.append((pos, realsize - pos))
    else:
        # the file ends in a hole: terminate the map like GNU tar does.
        map_entries.append((realsize, 0))
    # plan the emission of the data segments' bytes, chunk by chunk: data chunks are
    # emitted completely, all-zero chunks only with their parts sticking out of the
    # hole (shaved-off hole edges and the chunks of too-short zero runs) - those are
    # emitted as literal zero bytes, so all-zero chunks never need to be fetched.
    stream_plan = []
    offset = 0
    hole_idx = 0
    for chunk, zero in zip(chunks, zero_flags):
        chunk_end = offset + chunk.size
        if not zero:
            stream_plan.append(chunk)
        else:
            pos = offset
            while pos < chunk_end:
                while hole_idx < len(holes) and holes[hole_idx][1] <= pos:
                    hole_idx += 1
                if hole_idx < len(holes) and holes[hole_idx][0] <= pos:
                    pos = min(holes[hole_idx][1], chunk_end)  # covered by a hole: emit nothing
                else:
                    emit_end = min(holes[hole_idx][0], chunk_end) if hole_idx < len(holes) else chunk_end
                    stream_plan.append(emit_end - pos)
                    pos = emit_end
        offset = chunk_end
    return map_entries, stream_plan, realsize


class SparseTarInfo(tarfile.TarInfo):
    """TarInfo for GNU sparse format 1.0 members.

    A sparse member must never get a pax "size" record: readers recalculate the offset of
    the next header from it *after* the sparse processing already consumed the sparse map,
    so they desync on it - the pax-standard way of representing big sizes is broken for
    sparse members. Thus, the member's stored size (sparse map + data segments) always
    lives in the ustar size field: as standard octal while it fits (< 8 GiB, so those
    members stay as standard-conforming as sparse members can be), else base-256 encoded
    (the GNU/star big-number encoding; not POSIX, but GNU tar does the same for big
    numbers in pax mode, and GNU tar, libarchive/bsdtar and python's tarfile all read it
    in any tar format). The logical file size (GNU.sparse.realsize) is unlimited anyway.

    The base-256 field is patched in manually: python's tarfile writes base-256 only for
    GNU_FORMAT - for PAX_FORMAT it conforms to POSIX and emits a pax "size" record, the
    very thing that must be avoided here.
    """

    __slots__ = ()  # keep the TarInfo object layout, so plain TarInfos can be converted

    octal_size_limit = 8**11  # what fits into the 12-digit octal ustar size field

    def create_pax_header(self, info, encoding):
        stored_size = info["size"]
        if stored_size < self.octal_size_limit:
            return super().create_pax_header(info, encoding)
        info["size"] = 0  # suppresses both the automatic pax "size" record and the octal overflow
        buf = super().create_pax_header(info, encoding)
        # patch the base-256 encoded stored size into the ustar block's size field
        # and recompute the block's checksum.
        ustar = bytearray(buf[-tarfile.BLOCKSIZE :])
        ustar[124:136] = tarfile.itn(stored_size, 12, tarfile.GNU_FORMAT)
        chksum = tarfile.calc_chksums(bytes(ustar))[0]
        ustar[148:156] = bytes("%06o\0 " % chksum, "ascii")
        return buf[: -tarfile.BLOCKSIZE] + bytes(ustar)


def gnu_sparse_10_map(map_entries):
    """Serialize a sparse map as a GNU sparse format 1.0 map block.

    That is a series of decimal numbers delimited by newlines: the number of map
    entries, then offset and length of each entry - NUL-padded to a multiple of
    the 512 byte tar block size. It precedes the data segments in the tar member.
    """
    numbers = [len(map_entries)]
    for offset, length in map_entries:
        numbers += [offset, length]
    text = "".join(f"{number}\n" for number in numbers).encode()
    return text + b"\0" * (-len(text) % tarfile.BLOCKSIZE)


# Sentinel returned by get_tar_filter for zstd suffixes: (de)compress in-process
# via the zstd module instead of piping through an external filter program.
IN_PROCESS_ZSTD = "zstd (in-process)"

# Default zstd compression level, same as the zstd command line tool's default.
ZSTD_TAR_LEVEL = 3


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
    elif fname.endswith((".tar.zstd", ".tar.zst", ".tzst")):
        filter = IN_PROCESS_ZSTD
    else:
        filter = None
    logger.debug("Automatically determined tar filter: %s", filter)
    return filter


@contextlib.contextmanager
def create_zstd_filter(stream, stream_close, decompress):
    """In-process zstd (de)compression wrapper around *stream*, same contract as create_filter_process."""
    if decompress:
        zstream = zstd.ZstdFile(stream, "rb")
    else:
        workers = get_zstd_mt_workers(stream=True)
        if workers > 1:
            params = zstd.CompressionParameter
            options = {params.compression_level: ZSTD_TAR_LEVEL, params.nb_workers: workers}
            zstream = zstd.ZstdFile(stream, "wb", options=options)
        else:
            zstream = zstd.ZstdFile(stream, "wb", level=ZSTD_TAR_LEVEL)
    try:
        yield zstream
    except zstd.ZstdError as e:
        raise Error(f"in-process zstd filter failed: {e}") from None
    finally:
        # for compression, closing also finishes the zstd frame.
        # ZstdFile does not close a fileobj it was given, so close stream separately.
        zstream.close()
        if stream_close:
            stream.close()


XATTR_HDRTYPE = b"E"  # Solaris tar/pax extended attribute member, see #8479
SUN_XATTR_HDR_SIZE_LIMIT = 2**16  # sanity limit for xattr header members, real ones are ~100 bytes


def parse_sun_xattr_hdr(payload):
    """Parse the payload of a Solaris tar extended attribute header member, see #8479.

    Returns (typeflag, names, hardlinked): the typeflag of the attribute file, the
    NUL-separated path segments (parent file path, attribute name, ...) as bytes and
    whether the attribute is a hard link to another attribute.
    Returns None if the payload is not a Solaris xattr header (e.g. IBM i pax uses
    tarinfo type b'E' with a different, proprietary payload).
    """
    # layout (numbers are NUL-terminated ASCII decimals):
    # h_version[7] "1.0", h_size[10], h_component_len[10], h_link_component_len[10],
    # then one section per attribute path: h_namesz[7], h_typeflag[1], h_names[h_namesz].
    if len(payload) < 46 or not payload.startswith(b"1.0\x00"):
        return None

    def num(offset, width):
        field = payload[offset : offset + width].split(b"\x00", 1)[0]
        return int(field) if field.isdigit() else None

    h_size, component_len, link_len, namesz = num(7, 10), num(17, 10), num(27, 10), num(37, 7)
    if None in (h_size, component_len, link_len, namesz):
        return None
    if h_size != len(payload) or 45 + namesz > len(payload):
        return None
    typeflag = payload[44:45]
    names = payload[45 : 45 + namesz].split(b"\x00")
    while names and names[-1] == b"":
        names.pop()
    if len(names) < 2:
        return None
    return typeflag, names, link_len > 0


class DeferredItemAdder:
    """add_item wrapper deferring item storage, so that Solaris tar extended attributes,
    whose members trail the parent member (for a directory: its whole subtree), can still
    be attached to the parent item, see #8479.

    A directory stays pending while members inside it are processed (memory use is thus
    bounded by directory nesting depth), any other item only until the next item arrives.
    """

    def __init__(self, add_item):
        self._add_item = add_item
        self._pending = []  # stack of (item, add_item kwargs)

    @staticmethod
    def _covers(dir_path, path):
        # whether an item at dir_path is a directory ancestor of an item at path
        return (dir_path == "." and path != ".") or path.startswith(dir_path + "/")

    def _flush_finished(self, path, *, keep_path_item=False):
        # store pending items that cannot receive xattrs anymore once a member at *path* arrived
        while self._pending:
            item, kw = self._pending[-1]
            if keep_path_item and item.path == path:
                break
            if stat.S_ISDIR(item.mode) and self._covers(item.path, path):
                break
            self._pending.pop()
            self._add_item(item, **kw)

    def add(self, item, **kw):
        self._flush_finished(item.path)
        self._pending.append((item, kw))

    def attach_xattr(self, path, name, value):
        """Attach a name/value xattr to the pending item at *path*, return False if there is none."""
        self._flush_finished(path, keep_path_item=True)
        for item, _ in reversed(self._pending):
            if item.path == path:
                if "xattrs" in item:
                    item.xattrs[name] = value  # merge - PAX headers may already have set xattrs
                else:
                    item.xattrs = StableDict({name: value})
                return True
        return False

    def flush(self):
        while self._pending:
            item, kw = self._pending.pop()
            self._add_item(item, **kw)


def process_sun_xattrs(tar, tarinfo, adder, skipped):
    """Process a Solaris tar extended attribute header member and its value member, see #8479.

    Returns (status, pushback, hit_eof): the file status to display for the header member,
    a member consumed by lookahead that still must be dispatched normally (or None) and
    whether tar.next() already returned None (end of the tar stream reached).
    """
    hdr = None
    if tarinfo.size <= SUN_XATTR_HDR_SIZE_LIMIT:
        hdr = parse_sun_xattr_hdr(tar.extractfile(tarinfo).read())
    if hdr is None:
        skipped["skipped unrecognized extended attribute members (tarinfo type b'E')"] += 1
        return "E", None, False
    typeflag, names, hardlinked = hdr
    value_ti = tar.next()
    if value_ti is None:
        skipped["skipped Solaris extended attribute headers without a value member"] += 1
        return "E", None, True
    if value_ti.type != XATTR_HDRTYPE:
        # not the expected value member - hand it back for normal dispatching
        skipped["skipped Solaris extended attribute headers without a value member"] += 1
        return "E", value_ti, False
    # from here on, the value member is consumed together with the header member.
    attrname = names[1]
    if typeflag == b"5" or attrname == b".":
        # the hidden attribute directory itself, expected member, no borg representation
        return None, None, False
    if attrname.startswith(SYSATTR_PREFIX.encode()):
        # OS-maintained system attributes, not user xattrs - same exclusion as borg create
        return None, None, False
    if len(names) > 2 or b"/" in attrname:
        skipped["skipped Solaris extended attributes of extended attributes (unsupported)"] += 1
        return "E", None, False
    if hardlinked:
        skipped["skipped hard-linked Solaris extended attributes (unsupported)"] += 1
        return "E", None, False
    if value_ti.size > XATTR_SIZE_LIMIT:  # same limit as borg create uses on Solaris
        skipped["skipped too big Solaris extended attribute values"] += 1
        return "E", None, False
    try:
        parent_path = names[0].decode(tar.encoding or "utf-8", "surrogateescape")
        parent_path = make_path_safe(posixpath.normpath(parent_path))
    except ValueError:
        skipped["skipped Solaris extended attributes with an unsafe parent path"] += 1
        return "E", None, False
    value = tar.extractfile(value_ti).read()
    if not adder.attach_xattr(parent_path, attrname, value):
        skipped["skipped Solaris extended attributes without a parent item"] += 1
        return "E", None, False
    return None, None, False


class TarMixIn:
    @with_repository(compatibility=(Manifest.Operation.READ,))
    @with_archive
    def do_export_tar(self, args, repository, manifest, archive):
        """Export archive contents as a tarball"""
        self.output_list = args.output_list

        if args.sparse and args.tar_format not in ("BORG", "PAX"):
            raise Error("--sparse requires --tar-format BORG or PAX (GNU sparse format 1.0 members are PAX-based).")

        # A quick note about the general design of tar_filter and tarfile;
        # The tarfile module of Python can provide some compression mechanisms
        # by itself, using the built-in gzip, bz2, and lzma modules (and "tar modes"
        # such as "w:xz").
        #
        # Doing so would have three major drawbacks:
        # For one the compressor runs on the same thread as the program using the
        # tarfile, stealing valuable CPU time from Borg and thus reducing throughput.
        # Then this limits the available options - what about lz4? Brotli? zstd?
        # The third issue is that systems can ship more optimized versions than those
        # built into Python, e.g. pigz or pxz, which can use more than one thread for
        # compression.
        #
        # Therefore we externalize compression by using a filter program, which has
        # none of these drawbacks. The only issue of using an external filter is
        # that it has to be installed -- hardly a problem, considering that
        # the decompressor must be installed as well to make use of the exported tarball!
        #
        # zstd is the exception: borg requires the zstd module anyway (Python >= 3.14
        # stdlib, backports.zstd otherwise), libzstd multithreading (see the
        # BORG_ZSTD_MT_WORKERS env var) runs outside the GIL, and there is no
        # significantly more optimized external tool - so zstd tarballs are
        # (de)compressed in-process and need no external program.

        filter = get_tar_filter(args.tarfile, decompress=False) if args.tar_filter == "auto" else args.tar_filter

        tarstream = dash_open(args.tarfile, "wb")
        tarstream_close = args.tarfile != "-"

        if filter is IN_PROCESS_ZSTD:
            filter_context = create_zstd_filter(tarstream, stream_close=tarstream_close, decompress=False)
        else:
            filter_context = create_filter_process(
                filter, stream=tarstream, stream_close=tarstream_close, inbound=False
            )
        with filter_context as _stream:
            self._export_tar(args, archive, _stream)

    def _export_tar(self, args, archive, tarstream):
        # omitting args.pattern_roots here, restricting to paths only by cli args.paths:
        matcher = build_matcher(args.patterns, args.paths)

        progress = args.progress
        output_list = args.output_list
        strip_components = args.strip_components
        hlm = HardLinkManager(id_type=bytes, info_type=str)  # hlid -> path

        filter = build_filter(matcher, strip_components)

        # The | (pipe) symbol instructs tarfile to use a streaming mode of operation
        # where it never seeks on the passed fileobj.
        tar_format = dict(GNU=tarfile.GNU_FORMAT, PAX=tarfile.PAX_FORMAT, BORG=tarfile.PAX_FORMAT)[args.tar_format]
        tar = tarfile.open(fileobj=tarstream, mode="w|", format=tar_format)

        if progress:
            pi = ProgressIndicatorPercent(msg="%5.1f%% Processing: %s", step=0.1, msgid="extract")
            pi.output("Calculating size")
            extracted_size = sum(item.get_size() for item in archive.iter_items(filter))
            pi.total = extracted_size
        else:
            pi = None

        def sparse_chunk_iterator(stream_plan, map_bytes):
            """Generate a sparse member's payload: the sparse map, then the data segments'
            bytes as told by *stream_plan* (chunks to fetch, counts of literal zero bytes)."""
            yield map_bytes
            data_chunks = [entry for entry in stream_plan if not isinstance(entry, int)]
            fetched = archive.pipeline.fetch_many(data_chunks, ro_type=ROBJ_FILE_STREAM)
            for entry in stream_plan:
                yield zeros[:entry] if isinstance(entry, int) else next(fetched)

        def item_content_stream(item, stream_plan=None, map_bytes=None):
            """
            Return a file-like object that reads from the chunks of *item*
            (or produces a sparse member's payload from *stream_plan* / *map_bytes*).
            """
            if stream_plan is not None:
                chunk_iterator = sparse_chunk_iterator(stream_plan, map_bytes)
            else:
                chunk_iterator = archive.pipeline.fetch_many(item.chunks, ro_type=ROBJ_FILE_STREAM)
            if pi:
                info = [remove_surrogates(item.path)]
                return ChunkIteratorFileWrapper(
                    chunk_iterator, lambda read_bytes: pi.show(increase=len(read_bytes), info=info)
                )
            else:
                return ChunkIteratorFileWrapper(chunk_iterator)

        def sparsify_tarinfo(item, tarinfo):
            """Try to turn *tarinfo* into a GNU sparse format 1.0 member.

            If the item's content has detectable holes (runs of all-zero chunks) and storing
            it sparsely is possible and worthwhile, modify *tarinfo* accordingly (mangled
            name, stored size, GNU.sparse.* pax headers) and return (data_chunks, map_bytes);
            else return None and leave *tarinfo* alone (dense member).
            """
            if not item.chunks:
                return None
            ids = [chunk.id for chunk in item.chunks]
            sizes = [chunk.size for chunk in item.chunks]
            # Warm up the zero chunk id memo for likely hole chunk sizes, so such zero chunks
            # get detected even when their id does not repeat within this item: all-zero
            # chunks usually are max-chunk-sized (a power of two, as the chunkers do not cut
            # within runs of zeros) or a file's last chunk (a trailing hole of any size).
            candidate_sizes = {size for size in sizes if size & (size - 1) == 0} | {sizes[-1]}
            for size in candidate_sizes:
                if 0 < size <= len(zeros):
                    zero_chunk_id(archive.key.id_hash, size)
            sparse_info = chunks_to_sparse_info(item.chunks, zero_chunk_flags(ids, sizes, archive.key.id_hash))
            if sparse_info is None:
                return None
            map_entries, stream_plan, realsize = sparse_info
            if realsize != item.get_size():
                return None  # do not write self-contradicting sparse headers for an inconsistent item
            map_bytes = gnu_sparse_10_map(map_entries)
            stored_size = len(map_bytes) + sum(length for _, length in map_entries)
            if stored_size >= realsize:
                return None  # not worthwhile, the map costs more than the holes save
            # SparseTarInfo suppresses the pax "size" record (sparse readers desync on it)
            # and base-256 encodes a stored size beyond the octal ustar field limit.
            tarinfo.__class__ = SparseTarInfo
            # Do like GNU tar: store the member under a mangled name, so that a sparse-unaware
            # tar does not extract the raw map + data segments under the original name - the
            # real name is in the GNU.sparse.name pax header. GNU tar uses its pid where we
            # always use 0, for reproducible output.
            mangled_name = "GNUSparseFile.0/" + tarinfo.name
            # pax record order matters for readers applying them in-order: "path" (mangled)
            # first, the GNU.sparse.* records (real name / size) last, so the latter win.
            ph = {"path": mangled_name}
            ph.update(tarinfo.pax_headers)
            ph["GNU.sparse.major"] = "1"
            ph["GNU.sparse.minor"] = "0"
            ph["GNU.sparse.name"] = tarinfo.name
            ph["GNU.sparse.realsize"] = str(realsize)
            tarinfo.pax_headers = ph
            tarinfo.name = mangled_name
            tarinfo.size = stored_size  # sparse map + data segments, excluding the holes
            return stream_plan, map_bytes

        for item in archive.iter_items(filter):
            orig_path = item.path
            if strip_components:
                item.path = os.sep.join(orig_path.split(os.sep)[strip_components:])
            tarinfo, needs_content = item_to_tarinfo(item, hlm, warning=self.print_warning)
            if tarinfo:
                if args.tar_format in ("BORG", "PAX"):
                    tarinfo.pax_headers = item_to_paxheaders(args.tar_format, item)
                if output_list:
                    logging.getLogger("borg.output.list").info(remove_surrogates(orig_path))
                sparse_content = sparsify_tarinfo(item, tarinfo) if args.sparse and needs_content else None
                if sparse_content is not None:
                    stream_plan, map_bytes = sparse_content
                    stream = item_content_stream(item, stream_plan=stream_plan, map_bytes=map_bytes)
                else:
                    stream = item_content_stream(item) if needs_content else None
                tar.addfile(tarinfo, stream)
                if pi and sparse_content is not None:
                    # the stream callback counted only the stored bytes (sparse map + data
                    # segments), but the progress total is based on the logical file sizes.
                    pi.show(increase=max(0, item.get_size() - tarinfo.size), info=[remove_surrogates(item.path)])

        if pi:
            pi.finish()

        # This does not close the fileobj (tarstream) we passed to it -- a side effect of the | mode.
        tar.close()

        for pattern in matcher.get_unmatched_include_patterns():
            self.print_warning_instance(IncludePatternNeverMatchedWarning(pattern))

    @with_repository(cache=True, compatibility=(Manifest.Operation.WRITE,))
    def do_import_tar(self, args, repository, manifest, cache):
        """Create a backup archive from a tarball"""
        self.output_filter = args.output_filter
        self.output_list = args.output_list

        filter = get_tar_filter(args.tarfile, decompress=True) if args.tar_filter == "auto" else args.tar_filter

        tarstream = dash_open(args.tarfile, "rb")
        tarstream_close = args.tarfile != "-"

        if filter is IN_PROCESS_ZSTD:
            filter_context = create_zstd_filter(tarstream, stream_close=tarstream_close, decompress=True)
        else:
            filter_context = create_filter_process(filter, stream=tarstream, stream_close=tarstream_close, inbound=True)
        with filter_context as _stream:
            self._import_tar(args, repository, manifest, manifest.key, cache, _stream)

    def _import_tar(self, args, repository, manifest, key, cache, tarstream):
        t0 = archive_ts_now()

        archive = Archive(
            manifest,
            args.name,
            cache=cache,
            create=True,
            progress=args.progress,
            chunker_params=args.chunker_params,
            start=t0,
            log_json=args.log_json,
        )
        cp = ChunksProcessor(cache=cache, key=key, add_item=archive.add_item, rechunkify=False)
        adder = DeferredItemAdder(archive.add_item)
        tfo = TarfileObjectProcessors(
            cache=cache,
            key=key,
            process_file_chunks=cp.process_file_chunks,
            add_item=adder.add,
            chunker_params=args.chunker_params,
            show_progress=args.progress,
            log_json=args.log_json,
            file_status_printer=self.print_file_status,
        )

        tar = tarfile.open(fileobj=tarstream, mode="r|", ignore_zeros=args.ignore_zeros)

        skipped = Counter()  # skip reason -> count, summarized as warnings at the end
        pushback = None  # member consumed by xattr lookahead, still to be dispatched
        hit_eof = False
        while not hit_eof:
            tarinfo = pushback or tar.next()
            pushback = None
            if not tarinfo:
                break
            if tarinfo.isreg():
                status = tfo.process_file(tarinfo=tarinfo, status="A", type=stat.S_IFREG, tar=tar)
                archive.stats.nfiles += 1
            elif tarinfo.isdir():
                status = tfo.process_dir(tarinfo=tarinfo, status="d", type=stat.S_IFDIR)
            elif tarinfo.issym():
                status = tfo.process_symlink(tarinfo=tarinfo, status="s", type=stat.S_IFLNK)
            elif tarinfo.islnk():
                # tar uses a hard link model like: the first instance of a hard link is stored as a regular file,
                # later instances are special entries referencing back to the first instance.
                status = tfo.process_hardlink(tarinfo=tarinfo, status="h", type=stat.S_IFREG)
            elif tarinfo.isblk():
                status = tfo.process_dev(tarinfo=tarinfo, status="b", type=stat.S_IFBLK)
            elif tarinfo.ischr():
                status = tfo.process_dev(tarinfo=tarinfo, status="c", type=stat.S_IFCHR)
            elif tarinfo.isfifo():
                status = tfo.process_fifo(tarinfo=tarinfo, status="f", type=stat.S_IFIFO)
            elif tarinfo.type == XATTR_HDRTYPE:
                status, pushback, hit_eof = process_sun_xattrs(tar, tarinfo, adder, skipped)
            else:
                status = "E"
                skipped[f"skipped unsupported tarinfo type {tarinfo.type!r}"] += 1
            self.print_file_status(status, tarinfo.name)
        adder.flush()

        # This does not close the fileobj (tarstream) we passed to it -- a side effect of the | mode.
        tar.close()

        for reason, count in sorted(skipped.items()):
            self.print_warning("%s (%d members)", reason, count)

        if args.progress:
            archive.stats.show_progress(final=True)
        archive.stats += tfo.stats
        archive.save(comment=args.comment, timestamp=args.timestamp)
        args.stats |= args.json
        if args.stats:
            if args.json:
                json_print(basic_json_data(archive.manifest, cache=archive.cache, extra={"archive": archive}))
            else:
                log_multi(str(archive), str(archive.stats), logger=logging.getLogger("borg.output.stats"))

    def build_parser_tar(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        export_tar_epilog = process_epilog(
            """
        This command creates a tarball from an archive.

        When giving '-' as the output FILE, Borg will write a tar stream to standard output.

        By default (``--tar-filter=auto``) Borg will detect whether the FILE should be compressed
        based on its file extension and pipe the tarball through an appropriate filter
        before writing it to FILE:

        - .tar.gz or .tgz: gzip
        - .tar.bz2 or .tbz: bzip2
        - .tar.xz or .txz: xz
        - .tar.zstd, .tar.zst or .tzst: zstd (in-process, level 3)
        - .tar.lz4: lz4

        For zstd, Borg compresses in-process using libzstd instead of piping through an
        external program (set BORG_ZSTD_MT_WORKERS to use multiple compression threads).
        The other formats are piped through the respective external filter program.

        Alternatively, a ``--tar-filter`` program may be explicitly specified. It should
        read the uncompressed tar stream from stdin and write a compressed/filtered
        tar stream to stdout.

        Depending on the ``--tar-format`` option, these formats are created:

        +--------------+---------------------------+----------------------------+
        | --tar-format | Specification             | Metadata                   |
        +--------------+---------------------------+----------------------------+
        | BORG         | BORG specific, like PAX   | all as supported by borg   |
        +--------------+---------------------------+----------------------------+
        | PAX          | POSIX.1-2001 (pax) format | GNU + atime/ctime/mtime ns |
        |              |                           | + xattrs                   |
        +--------------+---------------------------+----------------------------+
        | GNU          | GNU tar format            | mtime s, no atime/ctime,   |
        |              |                           | no ACLs/xattrs/bsdflags    |
        +--------------+---------------------------+----------------------------+

        With ``--sparse``, files whose content contains runs of all-zero chunks are written
        as sparse tar members (GNU sparse format 1.0, as GNU tar creates it in POSIX mode),
        storing only a hole map and the non-zero data. This requires ``--tar-format BORG``
        or ``PAX``. Such tarballs can be much smaller for sparse files (e.g. disk images)
        and extract to sparse files again with GNU tar's or bsdtar's sparse support
        (as well as with ``borg import-tar`` / ``borg extract --sparse``).
        Notes: hole detection works at the granularity of borg's content chunks (it does not
        depend on the original file having been a sparse file - but some short or unaligned
        zero runs may be stored literally); sparse-unaware tar implementations will extract
        a member as ``GNUSparseFile.0/<name>`` containing the raw hole map and data (the
        same caveat applies to tarballs created by GNU tar); for members needing >= 8 GiB
        of stored (non-hole) data, the stored size is base-256 encoded in the tar header
        (the GNU/star encoding of big numbers, understood by GNU tar, libarchive/bsdtar
        and python) - logical file sizes are unlimited anyway.

        By default the entire archive is extracted but a subset of files and directories
        can be selected by passing a list of ``PATHs`` as arguments.
        The file selection can further be restricted by using the ``--exclude`` option.

        For more help on include/exclude patterns, see the :ref:`borg_patterns` command output.

        ``--progress`` can be slower than no progress display, since it makes one additional
        pass over the archive metadata.
        """
        )
        subparser = ArgumentParser(
            parents=[common_parser], description=self.do_export_tar.__doc__, epilog=export_tar_epilog
        )
        subparsers.add_subcommand("export-tar", subparser, help="create tarball from archive")
        subparser.add_argument(
            "--tar-filter",
            dest="tar_filter",
            default="auto",
            action=Highlander,
            help="filter program to pipe data through",
        )
        subparser.add_argument(
            "--list", dest="output_list", action="store_true", help="output verbose list of items (files, dirs, ...)"
        )
        subparser.add_argument(
            "--tar-format",
            metavar="FMT",
            dest="tar_format",
            default="PAX",
            choices=("BORG", "PAX", "GNU"),
            action=Highlander,
            help="select tar format: BORG, PAX or GNU",
        )
        subparser.add_argument(
            "--sparse",
            dest="sparse",
            action="store_true",
            help="write sparse tar members (GNU sparse format 1.0) for files containing all-zero "
            "chunks (BORG and PAX formats only)",
        )
        subparser.add_argument("name", metavar="NAME", type=archivename_validator, help="specify the archive name")
        subparser.add_argument(
            "tarfile", metavar="FILE", type=FilesystemPathSpec, help='output tar file. "-" to write to stdout instead.'
        )
        subparser.add_argument(
            "paths", metavar="PATH", nargs="*", type=PathSpec, help="paths to extract; patterns are supported"
        )
        define_exclusion_group(subparser, strip_components=True)

        import_tar_epilog = process_epilog(
            """
        This command creates a backup archive from a tarball.

        When giving '-' as path, Borg will read a tar stream from standard input.

        By default (--tar-filter=auto) Borg will detect whether the file is compressed
        based on its file extension and pipe the file through an appropriate filter:

        - .tar.gz or .tgz: gzip -d
        - .tar.bz2 or .tbz: bzip2 -d
        - .tar.xz or .txz: xz -d
        - .tar.zstd, .tar.zst or .tzst: zstd (in-process)
        - .tar.lz4: lz4 -d

        For zstd, Borg decompresses in-process using libzstd instead of piping through
        an external program. The other formats are piped through the respective
        external filter program.

        Alternatively, a --tar-filter program may be explicitly specified. It should
        read compressed data from stdin and output an uncompressed tar stream on
        stdout.

        Most documentation of borg create applies. Note that this command does not
        support excluding files.

        A ``--sparse`` option (as found in borg create) is not needed: sparse members in
        input tarballs (old GNU and PAX sparse formats) are read correctly and their
        holes are stored as deduplicated all-zero chunks.

        About tar formats and metadata conservation or loss, please see ``borg export-tar``.

        import-tar reads these tar formats:

        - BORG: borg specific (PAX-based)
        - PAX: POSIX.1-2001
        - GNU: GNU tar
        - POSIX.1-1988 (ustar)
        - UNIX V7 tar
        - SunOS tar with extended attributes

        Extended attributes archived by Solaris/illumos tar or pax (special member
        type "E") are imported as xattrs of the respective archive item (matching how
        borg create archives them on those platforms). System attributes
        (``SUNWattr_*``), hard-linked attributes and attributes of attributes are not
        imported. Members of other/unknown vendor-specific types are skipped and
        reported in a summarizing warning at the end.

        To import multiple tarballs into a single archive, they can be simply
        concatenated (e.g. using "cat") into a single file, and imported with an
        ``--ignore-zeros`` option to skip through the stop markers between them.
        """
        )
        subparser = ArgumentParser(
            parents=[common_parser], description=self.do_import_tar.__doc__, epilog=import_tar_epilog
        )
        subparsers.add_subcommand("import-tar", subparser, help=self.do_import_tar.__doc__)
        subparser.add_argument(
            "--tar-filter",
            dest="tar_filter",
            default="auto",
            action=Highlander,
            help="filter program to pipe data through",
        )
        subparser.add_argument(
            "-s",
            "--stats",
            dest="stats",
            action="store_true",
            default=False,
            help="print statistics for the created archive",
        )
        subparser.add_argument(
            "--list",
            dest="output_list",
            action="store_true",
            default=False,
            help="output verbose list of items (files, dirs, ...)",
        )
        subparser.add_argument(
            "--filter",
            dest="output_filter",
            metavar="STATUSCHARS",
            action=Highlander,
            help="only display items with the given status characters",
        )
        subparser.add_argument("--json", action="store_true", help="output stats as JSON (implies --stats)")
        subparser.add_argument(
            "--ignore-zeros",
            dest="ignore_zeros",
            action="store_true",
            help="ignore zero-filled blocks in the input tarball",
        )

        archive_group = subparser.add_argument_group("Archive options")
        archive_group.add_argument(
            "--comment",
            metavar="COMMENT",
            dest="comment",
            type=comment_validator,
            default="",
            action=Highlander,
            help="add a comment text to the archive",
        )
        archive_group.add_argument(
            "--timestamp",
            dest="timestamp",
            type=timestamp,
            default=None,
            action=Highlander,
            metavar="TIMESTAMP",
            help="manually specify the archive creation date/time (yyyy-mm-ddThh:mm:ss[(+|-)HH:MM] format, "
            "(+|-)HH:MM is the UTC offset, default: local time zone). Alternatively, give a reference file/directory.",
        )
        archive_group.add_argument(
            "--chunker-params",
            dest="chunker_params",
            type=ChunkerParams,
            default=CHUNKER_PARAMS,
            action=Highlander,
            metavar="PARAMS",
            help="specify the chunker parameters (ALGO, CHUNK_MIN_EXP, CHUNK_MAX_EXP, "
            "HASH_MASK_BITS, NC_LEVEL). default: %s,%d,%d,%d,%d" % CHUNKER_PARAMS,
        )
        archive_group.add_argument(
            "-C",
            "--compression",
            metavar="COMPRESSION",
            dest="compression",
            type=CompressionSpec,
            default=CompressionSpec("lz4"),
            action=Highlander,
            help="select compression algorithm, see the output of the " '"borg help compression" command for details.',
        )

        subparser.add_argument("name", metavar="NAME", type=archivename_validator, help="specify the archive name")
        subparser.add_argument(
            "tarfile",
            metavar="TARFILE",
            type=FilesystemPathSpec,
            help='input tar file. "-" to read from stdin instead.',
        )

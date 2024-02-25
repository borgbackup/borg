import base64
import errno
import json
import os
import stat
import sys
import time
from collections import OrderedDict, defaultdict
from contextlib import contextmanager
from datetime import timedelta
from functools import partial
from getpass import getuser
from io import BytesIO
from itertools import groupby, zip_longest
from typing import Iterator
from shutil import get_terminal_size

from .platformflags import is_win32
from .logger import create_logger

logger = create_logger()

from . import xattr
from .chunker import get_chunker, Chunk
from .cache import ChunkListEntry
from .crypto.key import key_factory, UnsupportedPayloadError
from .compress import CompressionSpec
from .constants import *  # NOQA
from .crypto.low_level import IntegrityError as IntegrityErrorBase
from .helpers import BackupError, BackupRaceConditionError
from .helpers import BackupOSError, BackupPermissionError, BackupFileNotFoundError, BackupIOError
from .hashindex import ChunkIndex, ChunkIndexEntry, CacheSynchronizer
from .helpers import HardLinkManager
from .helpers import ChunkIteratorFileWrapper, open_item
from .helpers import Error, IntegrityError, set_ec
from .platform import uid2user, user2uid, gid2group, group2gid
from .helpers import parse_timestamp, archive_ts_now
from .helpers import OutputTimestamp, format_timedelta, format_file_size, file_status, FileSize
from .helpers import safe_encode, make_path_safe, remove_surrogates, text_to_json, join_cmd, remove_dotdot_prefixes
from .helpers import StableDict
from .helpers import bin_to_hex
from .helpers import safe_ns
from .helpers import ellipsis_truncate, ProgressIndicatorPercent, log_multi
from .helpers import os_open, flags_normal, flags_dir
from .helpers import os_stat
from .helpers import msgpack
from .helpers import sig_int
from .helpers.lrucache import LRUCache
from .manifest import Manifest
from .patterns import PathPrefixPattern, FnmatchPattern, IECommand
from .item import Item, ArchiveItem, ItemDiff
from .platform import acl_get, acl_set, set_flags, get_flags, swidth, hostname
from .remote import cache_if_remote
from .repository import Repository, LIST_SCAN_LIMIT
from .repoobj import RepoObj

has_link = hasattr(os, "link")


class Statistics:
    def __init__(self, output_json=False, iec=False):
        self.output_json = output_json
        self.iec = iec
        self.osize = self.usize = self.nfiles = 0
        self.last_progress = 0  # timestamp when last progress was shown
        self.files_stats = defaultdict(int)
        self.chunking_time = 0.0
        self.hashing_time = 0.0
        self.rx_bytes = 0
        self.tx_bytes = 0

    def update(self, size, unique):
        self.osize += size
        if unique:
            self.usize += size

    def __add__(self, other):
        if not isinstance(other, Statistics):
            raise TypeError("can only add Statistics objects")
        stats = Statistics(self.output_json, self.iec)
        stats.osize = self.osize + other.osize
        stats.usize = self.usize + other.usize
        stats.nfiles = self.nfiles + other.nfiles
        stats.chunking_time = self.chunking_time + other.chunking_time
        stats.hashing_time = self.hashing_time + other.hashing_time
        st1, st2 = self.files_stats, other.files_stats
        stats.files_stats = defaultdict(int, {key: (st1[key] + st2[key]) for key in st1.keys() | st2.keys()})

        return stats

    def __str__(self):
        hashing_time = format_timedelta(timedelta(seconds=self.hashing_time))
        chunking_time = format_timedelta(timedelta(seconds=self.chunking_time))
        return """\
Number of files: {stats.nfiles}
Original size: {stats.osize_fmt}
Deduplicated size: {stats.usize_fmt}
Time spent in hashing: {hashing_time}
Time spent in chunking: {chunking_time}
Added files: {added_files}
Unchanged files: {unchanged_files}
Modified files: {modified_files}
Error files: {error_files}
Files changed while reading: {files_changed_while_reading}
Bytes read from remote: {stats.rx_bytes}
Bytes sent to remote: {stats.tx_bytes}
""".format(
            stats=self,
            hashing_time=hashing_time,
            chunking_time=chunking_time,
            added_files=self.files_stats["A"],
            unchanged_files=self.files_stats["U"],
            modified_files=self.files_stats["M"],
            error_files=self.files_stats["E"],
            files_changed_while_reading=self.files_stats["C"],
        )

    def __repr__(self):
        return "<{cls} object at {hash:#x} ({self.osize}, {self.usize})>".format(
            cls=type(self).__name__, hash=id(self), self=self
        )

    def as_dict(self):
        return {
            "original_size": FileSize(self.osize, iec=self.iec),
            "deduplicated_size": FileSize(self.usize, iec=self.iec),
            "nfiles": self.nfiles,
            "hashing_time": self.hashing_time,
            "chunking_time": self.chunking_time,
            "files_stats": self.files_stats,
        }

    def as_raw_dict(self):
        return {"size": self.osize, "nfiles": self.nfiles}

    @classmethod
    def from_raw_dict(cls, **kw):
        self = cls()
        self.osize = kw["size"]
        self.nfiles = kw["nfiles"]
        return self

    @property
    def osize_fmt(self):
        return format_file_size(self.osize, iec=self.iec)

    @property
    def usize_fmt(self):
        return format_file_size(self.usize, iec=self.iec)

    def show_progress(self, item=None, final=False, stream=None, dt=None):
        now = time.monotonic()
        if dt is None or now - self.last_progress > dt:
            self.last_progress = now
            if self.output_json:
                if not final:
                    data = self.as_dict()
                    if item:
                        data.update(text_to_json("path", item.path))
                else:
                    data = {}
                data.update({"time": time.time(), "type": "archive_progress", "finished": final})
                msg = json.dumps(data)
                end = "\n"
            else:
                columns, lines = get_terminal_size()
                if not final:
                    msg = "{0.osize_fmt} O {0.usize_fmt} U {0.nfiles} N ".format(self)
                    path = remove_surrogates(item.path) if item else ""
                    space = columns - swidth(msg)
                    if space < 12:
                        msg = ""
                        space = columns - swidth(msg)
                    if space >= 8:
                        msg += ellipsis_truncate(path, space)
                else:
                    msg = " " * columns
                end = "\r"
            print(msg, end=end, file=stream or sys.stderr, flush=True)


def is_special(mode):
    # file types that get special treatment in --read-special mode
    return stat.S_ISBLK(mode) or stat.S_ISCHR(mode) or stat.S_ISFIFO(mode)


class BackupIO:
    op = ""

    def __call__(self, op=""):
        self.op = op
        return self

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type and issubclass(exc_type, OSError):
            E_MAP = {
                errno.EPERM: BackupPermissionError,
                errno.EACCES: BackupPermissionError,
                errno.EBUSY: BackupPermissionError,
                errno.ENOENT: BackupFileNotFoundError,
                errno.EIO: BackupIOError,
            }
            e_cls = E_MAP.get(exc_val.errno, BackupOSError)
            raise e_cls(self.op, exc_val) from exc_val


backup_io = BackupIO()


def backup_io_iter(iterator):
    backup_io.op = "read"
    while True:
        with backup_io:
            try:
                item = next(iterator)
            except StopIteration:
                return
        yield item


def stat_update_check(st_old, st_curr):
    """
    this checks for some race conditions between the first filename-based stat()
    we did before dispatching to the (hopefully correct) file type backup handler
    and the (hopefully) fd-based fstat() we did in the handler.

    if there is a problematic difference (e.g. file type changed), we rather
    skip the file than being tricked into a security problem.

    such races should only happen if:
    - we are backing up a live filesystem (no snapshot, not inactive)
    - if files change due to normal fs activity at an unfortunate time
    - if somebody is doing an attack against us
    """
    # assuming that a file type change implicates a different inode change AND that inode numbers
    # are not duplicate in a short timeframe, this check is redundant and solved by the ino check:
    if stat.S_IFMT(st_old.st_mode) != stat.S_IFMT(st_curr.st_mode):
        # in this case, we dispatched to wrong handler - abort
        raise BackupRaceConditionError("file type changed (race condition), skipping file")
    if st_old.st_ino != st_curr.st_ino:
        # in this case, the hardlinks-related code in create_helper has the wrong inode - abort!
        raise BackupRaceConditionError("file inode changed (race condition), skipping file")
    # looks ok, we are still dealing with the same thing - return current stat:
    return st_curr


@contextmanager
def OsOpen(*, flags, path=None, parent_fd=None, name=None, noatime=False, op="open"):
    with backup_io(op):
        fd = os_open(path=path, parent_fd=parent_fd, name=name, flags=flags, noatime=noatime)
    try:
        yield fd
    finally:
        # On windows fd is None for directories.
        if fd is not None:
            os.close(fd)


class DownloadPipeline:
    def __init__(self, repository, repo_objs):
        self.repository = repository
        self.repo_objs = repo_objs

    def unpack_many(self, ids, *, filter=None, preload=False):
        """
        Return iterator of items.

        *ids* is a chunk ID list of an item stream. *filter* is a callable
        to decide whether an item will be yielded. *preload* preloads the data chunks of every yielded item.

        Warning: if *preload* is True then all data chunks of every yielded item have to be retrieved,
        otherwise preloaded chunks will accumulate in RemoteRepository and create a memory leak.
        """
        hlids_preloaded = set()
        unpacker = msgpack.Unpacker(use_list=False)
        for data in self.fetch_many(ids, ro_type=ROBJ_ARCHIVE_STREAM):
            unpacker.feed(data)
            for _item in unpacker:
                item = Item(internal_dict=_item)
                if "chunks" in item:
                    item.chunks = [ChunkListEntry(*e) for e in item.chunks]
                if filter and not filter(item):
                    continue
                if preload and "chunks" in item:
                    hlid = item.get("hlid", None)
                    if hlid is None:
                        preload_chunks = True
                    elif hlid in hlids_preloaded:
                        preload_chunks = False
                    else:
                        # not having the hardlink's chunks already preloaded for other hardlink to same inode
                        preload_chunks = True
                        hlids_preloaded.add(hlid)
                    if preload_chunks:
                        self.repository.preload([c.id for c in item.chunks])
                yield item

    def fetch_many(self, ids, is_preloaded=False, ro_type=None):
        assert ro_type is not None
        for id_, cdata in zip(ids, self.repository.get_many(ids, is_preloaded=is_preloaded)):
            _, data = self.repo_objs.parse(id_, cdata, ro_type=ro_type)
            yield data


class ChunkBuffer:
    BUFFER_SIZE = 8 * 1024 * 1024

    def __init__(self, key, chunker_params=ITEMS_CHUNKER_PARAMS):
        self.buffer = BytesIO()
        self.packer = msgpack.Packer()
        self.chunks = []
        self.key = key
        self.chunker = get_chunker(*chunker_params, seed=self.key.chunk_seed, sparse=False)
        self.saved_chunks_len = None

    def add(self, item):
        self.buffer.write(self.packer.pack(item.as_dict()))
        if self.is_full():
            self.flush()

    def write_chunk(self, chunk):
        raise NotImplementedError

    def flush(self, flush=False):
        if self.buffer.tell() == 0:
            return
        self.buffer.seek(0)
        # The chunker returns a memoryview to its internal buffer,
        # thus a copy is needed before resuming the chunker iterator.
        # the metadata stream may produce all-zero chunks, so deal
        # with CH_ALLOC (and CH_HOLE, for completeness) here.
        chunks = []
        for chunk in self.chunker.chunkify(self.buffer):
            alloc = chunk.meta["allocation"]
            if alloc == CH_DATA:
                data = bytes(chunk.data)
            elif alloc in (CH_ALLOC, CH_HOLE):
                data = zeros[: chunk.meta["size"]]
            else:
                raise ValueError("chunk allocation has unsupported value of %r" % alloc)
            chunks.append(data)
        self.buffer.seek(0)
        self.buffer.truncate(0)
        # Leave the last partial chunk in the buffer unless flush is True
        end = None if flush or len(chunks) == 1 else -1
        for chunk in chunks[:end]:
            self.chunks.append(self.write_chunk(chunk))
        if end == -1:
            self.buffer.write(chunks[-1])

    def is_full(self):
        return self.buffer.tell() > self.BUFFER_SIZE

    def save_chunks_state(self):
        # as we only append to self.chunks, remembering the current length is good enough
        self.saved_chunks_len = len(self.chunks)

    def restore_chunks_state(self):
        scl = self.saved_chunks_len
        assert scl is not None, "forgot to call save_chunks_state?"
        tail_chunks = self.chunks[scl:]
        del self.chunks[scl:]
        self.saved_chunks_len = None
        return tail_chunks


class CacheChunkBuffer(ChunkBuffer):
    def __init__(self, cache, key, stats, chunker_params=ITEMS_CHUNKER_PARAMS):
        super().__init__(key, chunker_params)
        self.cache = cache
        self.stats = stats

    def write_chunk(self, chunk):
        id_, _ = self.cache.add_chunk(
            self.key.id_hash(chunk), {}, chunk, stats=self.stats, wait=False, ro_type=ROBJ_ARCHIVE_STREAM
        )
        logger.debug(f"writing item metadata stream chunk {bin_to_hex(id_)}")
        self.cache.repository.async_response(wait=False)
        return id_


def get_item_uid_gid(item, *, numeric, uid_forced=None, gid_forced=None, uid_default=0, gid_default=0):
    if uid_forced is not None:
        uid = uid_forced
    else:
        uid = None if numeric else user2uid(item.get("user"))
        uid = item.get("uid") if uid is None else uid
        if uid is None or uid < 0:
            uid = uid_default
    if gid_forced is not None:
        gid = gid_forced
    else:
        gid = None if numeric else group2gid(item.get("group"))
        gid = item.get("gid") if gid is None else gid
        if gid is None or gid < 0:
            gid = gid_default
    return uid, gid


def archive_get_items(metadata, *, repo_objs, repository):
    if "item_ptrs" in metadata:  # looks like a v2+ archive
        assert "items" not in metadata
        items = []
        for id, cdata in zip(metadata.item_ptrs, repository.get_many(metadata.item_ptrs)):
            _, data = repo_objs.parse(id, cdata, ro_type=ROBJ_ARCHIVE_CHUNKIDS)
            ids = msgpack.unpackb(data)
            items.extend(ids)
        return items

    if "items" in metadata:  # legacy, v1 archive
        assert "item_ptrs" not in metadata
        return metadata.items


def archive_put_items(chunk_ids, *, repo_objs, cache=None, stats=None, add_reference=None):
    """gets a (potentially large) list of archive metadata stream chunk ids and writes them to repo objects"""
    item_ptrs = []
    for i in range(0, len(chunk_ids), IDS_PER_CHUNK):
        data = msgpack.packb(chunk_ids[i : i + IDS_PER_CHUNK])
        id = repo_objs.id_hash(data)
        logger.debug(f"writing item_ptrs chunk {bin_to_hex(id)}")
        if cache is not None and stats is not None:
            cache.add_chunk(id, {}, data, stats=stats, ro_type=ROBJ_ARCHIVE_CHUNKIDS)
        elif add_reference is not None:
            cdata = repo_objs.format(id, {}, data, ro_type=ROBJ_ARCHIVE_CHUNKIDS)
            add_reference(id, len(data), cdata)
        else:
            raise NotImplementedError
        item_ptrs.append(id)
    return item_ptrs


class Archive:
    class AlreadyExists(Error):
        """Archive {} already exists"""

        exit_mcode = 30

    class DoesNotExist(Error):
        """Archive {} does not exist"""

        exit_mcode = 31

    class IncompatibleFilesystemEncodingError(Error):
        """Failed to encode filename "{}" into file system encoding "{}". Consider configuring the LANG environment variable."""

        exit_mcode = 32

    def __init__(
        self,
        manifest,
        name,
        cache=None,
        create=False,
        numeric_ids=False,
        noatime=False,
        noctime=False,
        noflags=False,
        noacls=False,
        noxattrs=False,
        progress=False,
        chunker_params=CHUNKER_PARAMS,
        start=None,
        start_monotonic=None,
        end=None,
        log_json=False,
        iec=False,
    ):
        self.cwd = os.getcwd()
        assert isinstance(manifest, Manifest)
        self.manifest = manifest
        self.key = manifest.repo_objs.key
        self.repo_objs = manifest.repo_objs
        self.repository = manifest.repository
        self.cache = cache
        self.stats = Statistics(output_json=log_json, iec=iec)
        self.iec = iec
        self.show_progress = progress
        self.name = name  # overwritten later with name from archive metadata
        self.name_in_manifest = name  # can differ from .name later (if borg check fixed duplicate archive names)
        self.comment = None
        self.numeric_ids = numeric_ids
        self.noatime = noatime
        self.noctime = noctime
        self.noflags = noflags
        self.noacls = noacls
        self.noxattrs = noxattrs
        assert (start is None) == (
            start_monotonic is None
        ), "Logic error: if start is given, start_monotonic must be given as well and vice versa."
        if start is None:
            start = archive_ts_now()
            start_monotonic = time.monotonic()
        self.chunker_params = chunker_params
        self.start = start
        self.start_monotonic = start_monotonic
        if end is None:
            end = archive_ts_now()
        self.end = end
        self.pipeline = DownloadPipeline(self.repository, self.repo_objs)
        self.create = create
        if self.create:
            self.items_buffer = CacheChunkBuffer(self.cache, self.key, self.stats)
            if name in manifest.archives:
                raise self.AlreadyExists(name)
            i = 0
            while True:
                self.checkpoint_name = "{}.checkpoint{}".format(name, i and (".%d" % i) or "")
                if self.checkpoint_name not in manifest.archives:
                    break
                i += 1
        else:
            info = self.manifest.archives.get(name)
            if info is None:
                raise self.DoesNotExist(name)
            self.load(info.id)

    def _load_meta(self, id):
        cdata = self.repository.get(id)
        _, data = self.repo_objs.parse(id, cdata, ro_type=ROBJ_ARCHIVE_META)
        archive = self.key.unpack_archive(data)
        metadata = ArchiveItem(internal_dict=archive)
        if metadata.version not in (1, 2):  # legacy: still need to read v1 archives
            raise Exception("Unknown archive metadata version")
        # note: metadata.items must not get written to disk!
        metadata.items = archive_get_items(metadata, repo_objs=self.repo_objs, repository=self.repository)
        return metadata

    def load(self, id):
        self.id = id
        self.metadata = self._load_meta(self.id)
        self.name = self.metadata.name
        self.comment = self.metadata.get("comment", "")

    @property
    def ts(self):
        """Timestamp of archive creation (start) in UTC"""
        ts = self.metadata.time
        return parse_timestamp(ts)

    @property
    def ts_end(self):
        """Timestamp of archive creation (end) in UTC"""
        # fall back to time if there is no time_end present in metadata
        ts = self.metadata.get("time_end") or self.metadata.time
        return parse_timestamp(ts)

    @property
    def fpr(self):
        return bin_to_hex(self.id)

    @property
    def duration(self):
        return format_timedelta(self.end - self.start)

    @property
    def duration_from_meta(self):
        return format_timedelta(self.ts_end - self.ts)

    def info(self):
        if self.create:
            stats = self.stats
            start = self.start
            end = self.end
        else:
            stats = self.calc_stats(self.cache)
            start = self.ts
            end = self.ts_end
        info = {
            "name": self.name,
            "id": self.fpr,
            "start": OutputTimestamp(start),
            "end": OutputTimestamp(end),
            "duration": (end - start).total_seconds(),
            "stats": stats.as_dict(),
        }
        if self.create:
            info["command_line"] = join_cmd(sys.argv)
        else:
            info.update(
                {
                    "command_line": self.metadata.command_line,
                    "hostname": self.metadata.hostname,
                    "username": self.metadata.username,
                    "comment": self.metadata.get("comment", ""),
                    "chunker_params": self.metadata.get("chunker_params", ""),
                }
            )
        return info

    def __str__(self):
        return """\
Repository: {location}
Archive name: {0.name}
Archive fingerprint: {0.fpr}
Time (start): {start}
Time (end):   {end}
Duration: {0.duration}
""".format(
            self,
            start=OutputTimestamp(self.start),
            end=OutputTimestamp(self.end),
            location=self.repository._location.canonical_path(),
        )

    def __repr__(self):
        return "Archive(%r)" % self.name

    def item_filter(self, item, filter=None):
        return filter(item) if filter else True

    def iter_items(self, filter=None, preload=False):
        # note: when calling this with preload=True, later fetch_many() must be called with
        # is_preloaded=True or the RemoteRepository code will leak memory!
        yield from self.pipeline.unpack_many(
            self.metadata.items, preload=preload, filter=lambda item: self.item_filter(item, filter)
        )

    def add_item(self, item, show_progress=True, stats=None):
        if show_progress and self.show_progress:
            if stats is None:
                stats = self.stats
            stats.show_progress(item=item, dt=0.2)
        self.items_buffer.add(item)

    def prepare_checkpoint(self):
        # we need to flush the archive metadata stream to repo chunks, so that
        # we have the metadata stream chunks WITHOUT the part file item we add later.
        # The part file item will then get into its own metadata stream chunk, which we
        # can easily NOT include into the next checkpoint or the final archive.
        self.items_buffer.flush(flush=True)
        # remember the current state of self.chunks, which corresponds to the flushed chunks
        self.items_buffer.save_chunks_state()

    def write_checkpoint(self):
        metadata = self.save(self.checkpoint_name)
        # that .save() has committed the repo.
        # at next commit, we won't need this checkpoint archive any more because we will then
        # have either a newer checkpoint archive or the final archive.
        # so we can already remove it here, the next .save() will then commit this cleanup.
        # remove its manifest entry, remove its ArchiveItem chunk, remove its item_ptrs chunks:
        del self.manifest.archives[self.checkpoint_name]
        self.cache.chunk_decref(self.id, self.stats)
        for id in metadata.item_ptrs:
            self.cache.chunk_decref(id, self.stats)
        # also get rid of that part item, we do not want to have it in next checkpoint or final archive
        tail_chunks = self.items_buffer.restore_chunks_state()
        # tail_chunks contain the tail of the archive items metadata stream, not needed for next commit.
        for id in tail_chunks:
            self.cache.chunk_decref(id, self.stats)

    def save(self, name=None, comment=None, timestamp=None, stats=None, additional_metadata=None):
        name = name or self.name
        if name in self.manifest.archives:
            raise self.AlreadyExists(name)
        self.items_buffer.flush(flush=True)
        item_ptrs = archive_put_items(
            self.items_buffer.chunks, repo_objs=self.repo_objs, cache=self.cache, stats=self.stats
        )
        duration = timedelta(seconds=time.monotonic() - self.start_monotonic)
        if timestamp is None:
            end = archive_ts_now()
            start = end - duration
        else:
            start = timestamp
            end = start + duration
        self.start = start
        self.end = end
        metadata = {
            "version": 2,
            "name": name,
            "comment": comment or "",
            "item_ptrs": item_ptrs,  # see #1473
            "command_line": join_cmd(sys.argv),
            "hostname": hostname,
            "username": getuser(),
            "time": start.isoformat(timespec="microseconds"),
            "time_end": end.isoformat(timespec="microseconds"),
            "chunker_params": self.chunker_params,
        }
        # we always want to create archives with the addtl. metadata (nfiles, etc.),
        # because borg info relies on them. so, either use the given stats (from args)
        # or fall back to self.stats if it was not given.
        stats = stats or self.stats
        metadata.update({"size": stats.osize, "nfiles": stats.nfiles})
        metadata.update(additional_metadata or {})
        metadata = ArchiveItem(metadata)
        data = self.key.pack_metadata(metadata.as_dict())
        self.id = self.repo_objs.id_hash(data)
        try:
            self.cache.add_chunk(self.id, {}, data, stats=self.stats, ro_type=ROBJ_ARCHIVE_META)
        except IntegrityError as err:
            err_msg = str(err)
            # hack to avoid changing the RPC protocol by introducing new (more specific) exception class
            if "More than allowed put data" in err_msg:
                raise Error("%s - archive too big (issue #1473)!" % err_msg)
            else:
                raise
        while self.repository.async_response(wait=True) is not None:
            pass
        self.manifest.archives[name] = (self.id, metadata.time)
        self.manifest.write()
        self.repository.commit(compact=False)
        self.cache.commit()
        return metadata

    def calc_stats(self, cache, want_unique=True):
        if not want_unique:
            unique_size = 0
        else:

            def add(id):
                entry = cache.chunks[id]
                archive_index.add(id, 1, entry.size)

            archive_index = ChunkIndex()
            sync = CacheSynchronizer(archive_index)
            add(self.id)
            # we must escape any % char in the archive name, because we use it in a format string, see #6500
            arch_name_escd = self.name.replace("%", "%%")
            pi = ProgressIndicatorPercent(
                total=len(self.metadata.items),
                msg="Calculating statistics for archive %s ... %%3.0f%%%%" % arch_name_escd,
                msgid="archive.calc_stats",
            )
            for id, chunk in zip(self.metadata.items, self.repository.get_many(self.metadata.items)):
                pi.show(increase=1)
                add(id)
                _, data = self.repo_objs.parse(id, chunk, ro_type=ROBJ_ARCHIVE_STREAM)
                sync.feed(data)
            unique_size = archive_index.stats_against(cache.chunks)[1]
            pi.finish()

        stats = Statistics(iec=self.iec)
        stats.usize = unique_size
        stats.nfiles = self.metadata.nfiles
        stats.osize = self.metadata.size
        return stats

    @contextmanager
    def extract_helper(self, item, path, hlm, *, dry_run=False):
        hardlink_set = False
        # Hard link?
        if "hlid" in item:
            link_target = hlm.retrieve(id=item.hlid)
            if link_target is not None and has_link:
                if not dry_run:
                    # another hardlink to same inode (same hlid) was extracted previously, just link to it
                    with backup_io("link"):
                        os.link(link_target, path, follow_symlinks=False)
                hardlink_set = True
        yield hardlink_set
        if not hardlink_set:
            if "hlid" in item and has_link:
                # Update entry with extracted item path, so that following hardlinks don't extract twice.
                # We have hardlinking support, so we will hardlink not extract.
                hlm.remember(id=item.hlid, info=path)
            else:
                # Broken platform with no hardlinking support.
                # In this case, we *want* to extract twice, because there is no other way.
                pass

    def extract_item(
        self,
        item,
        *,
        restore_attrs=True,
        dry_run=False,
        stdout=False,
        sparse=False,
        hlm=None,
        pi=None,
        continue_extraction=False,
    ):
        """
        Extract archive item.

        :param item: the item to extract
        :param restore_attrs: restore file attributes
        :param dry_run: do not write any data
        :param stdout: write extracted data to stdout
        :param sparse: write sparse files (chunk-granularity, independent of the original being sparse)
        :param hlm: maps hlid to link_target for extracting subtrees with hardlinks correctly
        :param pi: ProgressIndicatorPercent (or similar) for file extraction progress (in bytes)
        :param continue_extraction: continue a previously interrupted extraction of same archive
        """

        def same_item(item, st):
            """is the archived item the same as the fs item at same path with stat st?"""
            if not stat.S_ISREG(st.st_mode):
                # we only "optimize" for regular files.
                # other file types are less frequent and have no content extraction we could "optimize away".
                return False
            if item.mode != st.st_mode or item.size != st.st_size:
                # the size check catches incomplete previous file extraction
                return False
            if item.get("mtime") != st.st_mtime_ns:
                # note: mtime is "extracted" late, after xattrs and ACLs, but before flags.
                return False
            # this is good enough for the intended use case:
            # continuing an extraction of same archive that initially started in an empty directory.
            # there is a very small risk that "bsdflags" of one file are wrong:
            # if a previous extraction was interrupted between setting the mtime and setting non-default flags.
            return True

        has_damaged_chunks = "chunks_healthy" in item
        if dry_run or stdout:
            with self.extract_helper(item, "", hlm, dry_run=dry_run or stdout) as hardlink_set:
                if not hardlink_set:
                    # it does not really set hardlinks due to dry_run, but we need to behave same
                    # as non-dry_run concerning fetching preloaded chunks from the pipeline or
                    # it would get stuck.
                    if "chunks" in item:
                        item_chunks_size = 0
                        for data in self.pipeline.fetch_many(
                            [c.id for c in item.chunks], is_preloaded=True, ro_type=ROBJ_FILE_STREAM
                        ):
                            if pi:
                                pi.show(increase=len(data), info=[remove_surrogates(item.path)])
                            if stdout:
                                sys.stdout.buffer.write(data)
                            item_chunks_size += len(data)
                        if stdout:
                            sys.stdout.buffer.flush()
                        if "size" in item:
                            item_size = item.size
                            if item_size != item_chunks_size:
                                raise BackupError(
                                    "Size inconsistency detected: size {}, chunks size {}".format(
                                        item_size, item_chunks_size
                                    )
                                )
            if has_damaged_chunks:
                raise BackupError("File has damaged (all-zero) chunks. Try running borg check --repair.")
            return

        dest = self.cwd
        path = os.path.join(dest, item.path)
        # Attempt to remove existing files, ignore errors on failure
        try:
            st = os.stat(path, follow_symlinks=False)
            if continue_extraction and same_item(item, st):
                return  # done! we already have fully extracted this file in a previous run.
            elif stat.S_ISDIR(st.st_mode):
                os.rmdir(path)
            else:
                os.unlink(path)
        except UnicodeEncodeError:
            raise self.IncompatibleFilesystemEncodingError(path, sys.getfilesystemencoding()) from None
        except OSError:
            pass

        def make_parent(path):
            parent_dir = os.path.dirname(path)
            if not os.path.exists(parent_dir):
                os.makedirs(parent_dir)

        mode = item.mode
        if stat.S_ISREG(mode):
            with backup_io("makedirs"):
                make_parent(path)
            with self.extract_helper(item, path, hlm) as hardlink_set:
                if hardlink_set:
                    return
                with backup_io("open"):
                    fd = open(path, "wb")
                with fd:
                    ids = [c.id for c in item.chunks]
                    for data in self.pipeline.fetch_many(ids, is_preloaded=True, ro_type=ROBJ_FILE_STREAM):
                        if pi:
                            pi.show(increase=len(data), info=[remove_surrogates(item.path)])
                        with backup_io("write"):
                            if sparse and zeros.startswith(data):
                                # all-zero chunk: create a hole in a sparse file
                                fd.seek(len(data), 1)
                            else:
                                fd.write(data)
                    with backup_io("truncate_and_attrs"):
                        pos = item_chunks_size = fd.tell()
                        fd.truncate(pos)
                        fd.flush()
                        self.restore_attrs(path, item, fd=fd.fileno())
                if "size" in item:
                    item_size = item.size
                    if item_size != item_chunks_size:
                        raise BackupError(
                            f"Size inconsistency detected: size {item_size}, chunks size {item_chunks_size}"
                        )
                if has_damaged_chunks:
                    raise BackupError("File has damaged (all-zero) chunks. Try running borg check --repair.")
            return
        with backup_io:
            # No repository access beyond this point.
            if stat.S_ISDIR(mode):
                make_parent(path)
                if not os.path.exists(path):
                    os.mkdir(path)
                if restore_attrs:
                    self.restore_attrs(path, item)
            elif stat.S_ISLNK(mode):
                make_parent(path)
                with self.extract_helper(item, path, hlm) as hardlink_set:
                    if hardlink_set:
                        # unusual, but possible: this is a hardlinked symlink.
                        return
                    target = item.target
                    try:
                        os.symlink(target, path)
                    except UnicodeEncodeError:
                        raise self.IncompatibleFilesystemEncodingError(target, sys.getfilesystemencoding()) from None
                    self.restore_attrs(path, item, symlink=True)
            elif stat.S_ISFIFO(mode):
                make_parent(path)
                with self.extract_helper(item, path, hlm) as hardlink_set:
                    if hardlink_set:
                        return
                    os.mkfifo(path)
                    self.restore_attrs(path, item)
            elif stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
                make_parent(path)
                with self.extract_helper(item, path, hlm) as hardlink_set:
                    if hardlink_set:
                        return
                    os.mknod(path, item.mode, item.rdev)
                    self.restore_attrs(path, item)
            else:
                raise Exception("Unknown archive item type %r" % item.mode)

    def restore_attrs(self, path, item, symlink=False, fd=None):
        """
        Restore filesystem attributes on *path* (*fd*) from *item*.

        Does not access the repository.
        """
        backup_io.op = "attrs"
        # This code is a bit of a mess due to OS specific differences.
        if not is_win32:
            # by using uid_default = -1 and gid_default = -1, they will not be restored if
            # the archived item has no information about them.
            uid, gid = get_item_uid_gid(item, numeric=self.numeric_ids, uid_default=-1, gid_default=-1)
            # if uid and/or gid is -1, chown will keep it as is and not change it.
            try:
                if fd:
                    os.fchown(fd, uid, gid)
                else:
                    os.chown(path, uid, gid, follow_symlinks=False)
            except OSError:
                pass
            if fd:
                os.fchmod(fd, item.mode)
            else:
                # To check whether a particular function in the os module accepts False for its
                # follow_symlinks parameter, the in operator on supports_follow_symlinks should be
                # used. However, os.chmod is special as some platforms without a working lchmod() do
                # have fchmodat(), which has a flag that makes it behave like lchmod(). fchmodat()
                # is ignored when deciding whether or not os.chmod should be set in
                # os.supports_follow_symlinks. Work around this by using try/except.
                try:
                    os.chmod(path, item.mode, follow_symlinks=False)
                except NotImplementedError:
                    if not symlink:
                        os.chmod(path, item.mode)
            if not self.noacls:
                acl_set(path, item, self.numeric_ids, fd=fd)
            if not self.noxattrs and "xattrs" in item:
                # chown removes Linux capabilities, so set the extended attributes at the end, after chown,
                # since they include the Linux capabilities in the "security.capability" attribute.
                warning = xattr.set_all(fd or path, item.xattrs, follow_symlinks=False)
                if warning:
                    set_ec(EXIT_WARNING)
            # set timestamps rather late
            mtime = item.mtime
            atime = item.atime if "atime" in item else mtime
            if "birthtime" in item:
                birthtime = item.birthtime
                try:
                    # This should work on FreeBSD, NetBSD, and Darwin and be harmless on other platforms.
                    # See utimes(2) on either of the BSDs for details.
                    if fd:
                        os.utime(fd, None, ns=(atime, birthtime))
                    else:
                        os.utime(path, None, ns=(atime, birthtime), follow_symlinks=False)
                except OSError:
                    # some systems don't support calling utime on a symlink
                    pass
            try:
                if fd:
                    os.utime(fd, None, ns=(atime, mtime))
                else:
                    os.utime(path, None, ns=(atime, mtime), follow_symlinks=False)
            except OSError:
                # some systems don't support calling utime on a symlink
                pass
            # bsdflags include the immutable flag and need to be set last:
            if not self.noflags and "bsdflags" in item:
                try:
                    set_flags(path, item.bsdflags, fd=fd)
                except OSError:
                    pass
        else:  # win32
            # set timestamps rather late
            mtime = item.mtime
            atime = item.atime if "atime" in item else mtime
            try:
                # note: no fd support on win32
                os.utime(path, None, ns=(atime, mtime))
            except OSError:
                # some systems don't support calling utime on a symlink
                pass

    def set_meta(self, key, value):
        metadata = self._load_meta(self.id)
        setattr(metadata, key, value)
        if "items" in metadata:
            del metadata.items
        data = self.key.pack_metadata(metadata.as_dict())
        new_id = self.key.id_hash(data)
        self.cache.add_chunk(new_id, {}, data, stats=self.stats, ro_type=ROBJ_ARCHIVE_META)
        self.manifest.archives[self.name] = (new_id, metadata.time)
        self.cache.chunk_decref(self.id, self.stats)
        self.id = new_id

    def rename(self, name):
        if name in self.manifest.archives:
            raise self.AlreadyExists(name)
        oldname = self.name
        self.name = name
        self.set_meta("name", name)
        del self.manifest.archives[oldname]

    def delete(self, stats, progress=False, forced=False):
        class ChunksIndexError(Error):
            """Chunk ID {} missing from chunks index, corrupted chunks index - aborting transaction."""

        exception_ignored = object()

        def fetch_async_response(wait=True):
            try:
                return self.repository.async_response(wait=wait)
            except Repository.ObjectNotFound:
                nonlocal error
                # object not in repo - strange, but we wanted to delete it anyway.
                if forced == 0:
                    raise
                error = True
                return exception_ignored  # must not return None here

        def chunk_decref(id, stats):
            try:
                self.cache.chunk_decref(id, stats, wait=False)
            except KeyError:
                cid = bin_to_hex(id)
                raise ChunksIndexError(cid)
            else:
                fetch_async_response(wait=False)

        error = False
        try:
            unpacker = msgpack.Unpacker(use_list=False)
            items_ids = self.metadata.items
            pi = ProgressIndicatorPercent(
                total=len(items_ids), msg="Decrementing references %3.0f%%", msgid="archive.delete"
            )
            for i, (items_id, data) in enumerate(zip(items_ids, self.repository.get_many(items_ids))):
                if progress:
                    pi.show(i)
                _, data = self.repo_objs.parse(items_id, data, ro_type=ROBJ_ARCHIVE_STREAM)
                unpacker.feed(data)
                chunk_decref(items_id, stats)
                try:
                    for item in unpacker:
                        item = Item(internal_dict=item)
                        if "chunks" in item:
                            for chunk_id, size in item.chunks:
                                chunk_decref(chunk_id, stats)
                except (TypeError, ValueError):
                    # if items metadata spans multiple chunks and one chunk got dropped somehow,
                    # it could be that unpacker yields bad types
                    if forced == 0:
                        raise
                    error = True
            if progress:
                pi.finish()
        except (msgpack.UnpackException, Repository.ObjectNotFound):
            # items metadata corrupted
            if forced == 0:
                raise
            error = True

        # delete the blocks that store all the references that end up being loaded into metadata.items:
        for id in self.metadata.item_ptrs:
            chunk_decref(id, stats)

        # in forced delete mode, we try hard to delete at least the manifest entry,
        # if possible also the archive superblock, even if processing the items raises
        # some harmless exception.
        chunk_decref(self.id, stats)
        del self.manifest.archives[self.name]
        while fetch_async_response(wait=True) is not None:
            # we did async deletes, process outstanding results (== exceptions),
            # so there is nothing pending when we return and our caller wants to commit.
            pass
        if error:
            logger.warning("forced deletion succeeded, but the deleted archive was corrupted.")
            logger.warning("borg check --repair is required to free all space.")

    @staticmethod
    def compare_archives_iter(
        archive1: "Archive", archive2: "Archive", matcher=None, can_compare_chunk_ids=False
    ) -> Iterator[ItemDiff]:
        """
        Yields an ItemDiff instance describing changes/indicating equality.

        :param matcher: PatternMatcher class to restrict results to only matching paths.
        :param can_compare_chunk_ids: Whether --chunker-params are the same for both archives.
        """

        def compare_items(path: str, item1: Item, item2: Item):
            return ItemDiff(
                path,
                item1,
                item2,
                archive1.pipeline.fetch_many([c.id for c in item1.get("chunks", [])], ro_type=ROBJ_FILE_STREAM),
                archive2.pipeline.fetch_many([c.id for c in item2.get("chunks", [])], ro_type=ROBJ_FILE_STREAM),
                can_compare_chunk_ids=can_compare_chunk_ids,
            )

        orphans_archive1: OrderedDict[str, Item] = OrderedDict()
        orphans_archive2: OrderedDict[str, Item] = OrderedDict()

        assert matcher is not None, "matcher must be set"

        for item1, item2 in zip_longest(
            archive1.iter_items(lambda item: matcher.match(item.path)),
            archive2.iter_items(lambda item: matcher.match(item.path)),
        ):
            if item1 and item2 and item1.path == item2.path:
                yield compare_items(item1.path, item1, item2)
                continue
            if item1:
                matching_orphan = orphans_archive2.pop(item1.path, None)
                if matching_orphan:
                    yield compare_items(item1.path, item1, matching_orphan)
                else:
                    orphans_archive1[item1.path] = item1
            if item2:
                matching_orphan = orphans_archive1.pop(item2.path, None)
                if matching_orphan:
                    yield compare_items(matching_orphan.path, matching_orphan, item2)
                else:
                    orphans_archive2[item2.path] = item2
        # At this point orphans_* contain items that had no matching partner in the other archive
        for added in orphans_archive2.values():
            path = added.path
            deleted_item = Item.create_deleted(path)
            yield compare_items(path, deleted_item, added)
        for deleted in orphans_archive1.values():
            path = deleted.path
            deleted_item = Item.create_deleted(path)
            yield compare_items(path, deleted, deleted_item)


class MetadataCollector:
    def __init__(self, *, noatime, noctime, nobirthtime, numeric_ids, noflags, noacls, noxattrs):
        self.noatime = noatime
        self.noctime = noctime
        self.numeric_ids = numeric_ids
        self.noflags = noflags
        self.noacls = noacls
        self.noxattrs = noxattrs
        self.nobirthtime = nobirthtime

    def stat_simple_attrs(self, st):
        attrs = {}
        attrs["mode"] = st.st_mode
        # borg can work with archives only having mtime (very old borg archives do not have
        # atime/ctime). it can be useful to omit atime/ctime, if they change without the
        # file content changing - e.g. to get better metadata deduplication.
        attrs["mtime"] = safe_ns(st.st_mtime_ns)
        if not self.noatime:
            attrs["atime"] = safe_ns(st.st_atime_ns)
        if not self.noctime:
            attrs["ctime"] = safe_ns(st.st_ctime_ns)
        if not self.nobirthtime and hasattr(st, "st_birthtime"):
            # sadly, there's no stat_result.st_birthtime_ns
            attrs["birthtime"] = safe_ns(int(st.st_birthtime * 10**9))
        attrs["uid"] = st.st_uid
        attrs["gid"] = st.st_gid
        if not self.numeric_ids:
            user = uid2user(st.st_uid)
            if user is not None:
                attrs["user"] = user
            group = gid2group(st.st_gid)
            if group is not None:
                attrs["group"] = group
        return attrs

    def stat_ext_attrs(self, st, path, fd=None):
        attrs = {}
        if not self.noflags:
            with backup_io("extended stat (flags)"):
                flags = get_flags(path, st, fd=fd)
            attrs["bsdflags"] = flags
        if not self.noxattrs:
            with backup_io("extended stat (xattrs)"):
                xattrs = xattr.get_all(fd or path, follow_symlinks=False)
            attrs["xattrs"] = StableDict(xattrs)
        if not self.noacls:
            with backup_io("extended stat (ACLs)"):
                acl_get(path, attrs, st, self.numeric_ids, fd=fd)
        return attrs

    def stat_attrs(self, st, path, fd=None):
        attrs = self.stat_simple_attrs(st)
        attrs.update(self.stat_ext_attrs(st, path, fd=fd))
        return attrs


# remember a few recently used all-zero chunk hashes in this mapping.
# (hash_func, chunk_length) -> chunk_hash
# we play safe and have the hash_func in the mapping key, in case we
# have different hash_funcs within the same borg run.
zero_chunk_ids = LRUCache(10)  # type: ignore[var-annotated]


def cached_hash(chunk, id_hash):
    allocation = chunk.meta["allocation"]
    if allocation == CH_DATA:
        data = chunk.data
        chunk_id = id_hash(data)
    elif allocation in (CH_HOLE, CH_ALLOC):
        size = chunk.meta["size"]
        assert size <= len(zeros)
        data = memoryview(zeros)[:size]
        try:
            chunk_id = zero_chunk_ids[(id_hash, size)]
        except KeyError:
            chunk_id = id_hash(data)
            zero_chunk_ids[(id_hash, size)] = chunk_id
    else:
        raise ValueError("unexpected allocation type")
    return chunk_id, data


class ChunksProcessor:
    # Processes an iterator of chunks for an Item

    def __init__(
        self,
        *,
        key,
        cache,
        add_item,
        prepare_checkpoint,
        write_checkpoint,
        checkpoint_interval,
        checkpoint_volume,
        rechunkify,
    ):
        self.key = key
        self.cache = cache
        self.add_item = add_item
        self.prepare_checkpoint = prepare_checkpoint
        self.write_checkpoint = write_checkpoint
        self.rechunkify = rechunkify
        # time interval based checkpointing
        self.checkpoint_interval = checkpoint_interval
        self.last_checkpoint = time.monotonic()
        # file content volume based checkpointing
        self.checkpoint_volume = checkpoint_volume
        self.current_volume = 0
        self.last_volume_checkpoint = 0

    def write_part_file(self, item):
        self.prepare_checkpoint()
        item = Item(internal_dict=item.as_dict())
        # for borg recreate, we already have a size member in the source item (giving the total file size),
        # but we consider only a part of the file here, thus we must recompute the size from the chunks:
        item.get_size(memorize=True, from_chunks=True)
        item.path += ".borg_part"
        self.add_item(item, show_progress=False)
        self.write_checkpoint()

    def maybe_checkpoint(self, item):
        checkpoint_done = False
        sig_int_triggered = sig_int and sig_int.action_triggered()
        if (
            sig_int_triggered
            or (self.checkpoint_interval and time.monotonic() - self.last_checkpoint > self.checkpoint_interval)
            or (self.checkpoint_volume and self.current_volume - self.last_volume_checkpoint >= self.checkpoint_volume)
        ):
            if sig_int_triggered:
                logger.info("checkpoint requested: starting checkpoint creation...")
            self.write_part_file(item)
            checkpoint_done = True
            self.last_checkpoint = time.monotonic()
            self.last_volume_checkpoint = self.current_volume
            if sig_int_triggered:
                sig_int.action_completed()
                logger.info("checkpoint requested: finished checkpoint creation!")
        return checkpoint_done  # whether a checkpoint archive was created

    def process_file_chunks(self, item, cache, stats, show_progress, chunk_iter, chunk_processor=None):
        if not chunk_processor:

            def chunk_processor(chunk):
                started_hashing = time.monotonic()
                chunk_id, data = cached_hash(chunk, self.key.id_hash)
                stats.hashing_time += time.monotonic() - started_hashing
                chunk_entry = cache.add_chunk(chunk_id, {}, data, stats=stats, wait=False, ro_type=ROBJ_FILE_STREAM)
                self.cache.repository.async_response(wait=False)
                return chunk_entry

        item.chunks = []
        # if we rechunkify, we'll get a fundamentally different chunks list, thus we need
        # to get rid of .chunks_healthy, as it might not correspond to .chunks any more.
        if self.rechunkify and "chunks_healthy" in item:
            del item.chunks_healthy
        for chunk in chunk_iter:
            chunk_entry = chunk_processor(chunk)
            item.chunks.append(chunk_entry)
            self.current_volume += chunk_entry[1]
            if show_progress:
                stats.show_progress(item=item, dt=0.2)
            self.maybe_checkpoint(item)


class FilesystemObjectProcessors:
    # When ported to threading, then this doesn't need chunker, cache, key any more.
    # write_checkpoint should then be in the item buffer,
    # and process_file becomes a callback passed to __init__.

    def __init__(
        self,
        *,
        metadata_collector,
        cache,
        key,
        add_item,
        process_file_chunks,
        chunker_params,
        show_progress,
        sparse,
        log_json,
        iec,
        file_status_printer=None,
    ):
        self.metadata_collector = metadata_collector
        self.cache = cache
        self.key = key
        self.add_item = add_item
        self.process_file_chunks = process_file_chunks
        self.show_progress = show_progress
        self.print_file_status = file_status_printer or (lambda *args: None)

        self.hlm = HardLinkManager(id_type=tuple, info_type=(list, type(None)))  # (dev, ino) -> chunks or None
        self.stats = Statistics(output_json=log_json, iec=iec)  # threading: done by cache (including progress)
        self.cwd = os.getcwd()
        self.chunker = get_chunker(*chunker_params, seed=key.chunk_seed, sparse=sparse)

    @contextmanager
    def create_helper(self, path, st, status=None, hardlinkable=True, strip_prefix=None):
        if strip_prefix is not None:
            assert not path.endswith(os.sep)
            if strip_prefix.startswith(path + os.sep):
                # still on a directory level that shall be stripped - do not create an item for this!
                yield None, "x", False, None
                return
            # adjust path, remove stripped directory levels
            path = path.removeprefix(strip_prefix)

        sanitized_path = remove_dotdot_prefixes(path)
        item = Item(path=sanitized_path)
        hardlinked = hardlinkable and st.st_nlink > 1
        hl_chunks = None
        update_map = False
        if hardlinked:
            status = "h"  # hardlink
            nothing = object()
            chunks = self.hlm.retrieve(id=(st.st_ino, st.st_dev), default=nothing)
            if chunks is nothing:
                update_map = True
            elif chunks is not None:
                hl_chunks = chunks
            item.hlid = self.hlm.hardlink_id_from_inode(ino=st.st_ino, dev=st.st_dev)
        yield item, status, hardlinked, hl_chunks
        self.add_item(item, stats=self.stats)
        if update_map:
            # remember the hlid of this fs object and if the item has chunks,
            # also remember them, so we do not have to re-chunk a hardlink.
            chunks = item.chunks if "chunks" in item else None
            self.hlm.remember(id=(st.st_ino, st.st_dev), info=chunks)

    def process_dir_with_fd(self, *, path, fd, st, strip_prefix):
        with self.create_helper(path, st, "d", hardlinkable=False, strip_prefix=strip_prefix) as (
            item,
            status,
            hardlinked,
            hl_chunks,
        ):
            if item is not None:
                item.update(self.metadata_collector.stat_attrs(st, path, fd=fd))
            return status

    def process_dir(self, *, path, parent_fd, name, st, strip_prefix):
        with self.create_helper(path, st, "d", hardlinkable=False, strip_prefix=strip_prefix) as (
            item,
            status,
            hardlinked,
            hl_chunks,
        ):
            if item is None:
                return status
            with OsOpen(path=path, parent_fd=parent_fd, name=name, flags=flags_dir, noatime=True, op="dir_open") as fd:
                # fd is None for directories on windows, in that case a race condition check is not possible.
                if fd is not None:
                    with backup_io("fstat"):
                        st = stat_update_check(st, os.fstat(fd))
                item.update(self.metadata_collector.stat_attrs(st, path, fd=fd))
                return status

    def process_fifo(self, *, path, parent_fd, name, st, strip_prefix):
        with self.create_helper(path, st, "f", strip_prefix=strip_prefix) as (
            item,
            status,
            hardlinked,
            hl_chunks,
        ):  # fifo
            if item is None:
                return status
            with OsOpen(path=path, parent_fd=parent_fd, name=name, flags=flags_normal, noatime=True) as fd:
                with backup_io("fstat"):
                    st = stat_update_check(st, os.fstat(fd))
                item.update(self.metadata_collector.stat_attrs(st, path, fd=fd))
                return status

    def process_dev(self, *, path, parent_fd, name, st, dev_type, strip_prefix):
        with self.create_helper(path, st, dev_type, strip_prefix=strip_prefix) as (
            item,
            status,
            hardlinked,
            hl_chunks,
        ):  # char/block device
            # looks like we can not work fd-based here without causing issues when trying to open/close the device
            if item is None:
                return status
            with backup_io("stat"):
                st = stat_update_check(st, os_stat(path=path, parent_fd=parent_fd, name=name, follow_symlinks=False))
            item.rdev = st.st_rdev
            item.update(self.metadata_collector.stat_attrs(st, path))
            return status

    def process_symlink(self, *, path, parent_fd, name, st, strip_prefix):
        with self.create_helper(path, st, "s", hardlinkable=True, strip_prefix=strip_prefix) as (
            item,
            status,
            hardlinked,
            hl_chunks,
        ):
            if item is None:
                return status
            fname = name if name is not None and parent_fd is not None else path
            with backup_io("readlink"):
                target = os.readlink(fname, dir_fd=parent_fd)
            item.target = target
            item.update(self.metadata_collector.stat_attrs(st, path))  # can't use FD here?
            return status

    def process_pipe(self, *, path, cache, fd, mode, user=None, group=None):
        status = "i"  # stdin (or other pipe)
        self.print_file_status(status, path)
        status = None  # we already printed the status
        if user is not None:
            uid = user2uid(user)
            if uid is None:
                raise Error("no such user: %s" % user)
        else:
            uid = None
        if group is not None:
            gid = group2gid(group)
            if gid is None:
                raise Error("no such group: %s" % group)
        else:
            gid = None
        t = int(time.time()) * 1000000000
        item = Item(path=path, mode=mode & 0o107777 | 0o100000, mtime=t, atime=t, ctime=t)  # forcing regular file mode
        if user is not None:
            item.user = user
        if group is not None:
            item.group = group
        if uid is not None:
            item.uid = uid
        if gid is not None:
            item.gid = gid
        try:
            self.process_file_chunks(
                item, cache, self.stats, self.show_progress, backup_io_iter(self.chunker.chunkify(fd))
            )
        except BackupOSError:
            # see comments in process_file's exception handler, same issue here.
            for chunk in item.get("chunks", []):
                cache.chunk_decref(chunk.id, self.stats, wait=False)
            raise
        else:
            item.get_size(memorize=True)
            self.stats.nfiles += 1
            self.add_item(item, stats=self.stats)
            return status

    def process_file(self, *, path, parent_fd, name, st, cache, flags=flags_normal, last_try=False, strip_prefix):
        with self.create_helper(path, st, None, strip_prefix=strip_prefix) as (
            item,
            status,
            hardlinked,
            hl_chunks,
        ):  # no status yet
            if item is None:
                return status
            with OsOpen(path=path, parent_fd=parent_fd, name=name, flags=flags, noatime=True) as fd:
                with backup_io("fstat"):
                    st = stat_update_check(st, os.fstat(fd))
                item.update(self.metadata_collector.stat_simple_attrs(st))
                is_special_file = is_special(st.st_mode)
                if is_special_file:
                    # we process a special file like a regular file. reflect that in mode,
                    # so it can be extracted / accessed in FUSE mount like a regular file.
                    # this needs to be done early, so that part files also get the patched mode.
                    item.mode = stat.S_IFREG | stat.S_IMODE(item.mode)
                # we begin processing chunks now (writing or incref'ing them to the repository),
                # which might require cleanup (see except-branch):
                try:
                    if hl_chunks is not None:  # create_helper gave us chunks from a previous hardlink
                        item.chunks = []
                        for chunk_id, chunk_size in hl_chunks:
                            # process one-by-one, so we will know in item.chunks how far we got
                            chunk_entry = cache.chunk_incref(chunk_id, self.stats)
                            item.chunks.append(chunk_entry)
                    else:  # normal case, no "2nd+" hardlink
                        if not is_special_file:
                            hashed_path = safe_encode(os.path.join(self.cwd, path))
                            started_hashing = time.monotonic()
                            path_hash = self.key.id_hash(hashed_path)
                            self.stats.hashing_time += time.monotonic() - started_hashing
                            known, ids = cache.file_known_and_unchanged(hashed_path, path_hash, st)
                        else:
                            # in --read-special mode, we may be called for special files.
                            # there should be no information in the cache about special files processed in
                            # read-special mode, but we better play safe as this was wrong in the past:
                            hashed_path = path_hash = None
                            known, ids = False, None
                        if ids is not None:
                            # Make sure all ids are available
                            for id_ in ids:
                                if not cache.seen_chunk(id_):
                                    # cache said it is unmodified, but we lost a chunk: process file like modified
                                    status = "M"
                                    break
                            else:
                                item.chunks = []
                                for chunk_id in ids:
                                    # process one-by-one, so we will know in item.chunks how far we got
                                    chunk_entry = cache.chunk_incref(chunk_id, self.stats)
                                    item.chunks.append(chunk_entry)
                                status = "U"  # regular file, unchanged
                        else:
                            status = "M" if known else "A"  # regular file, modified or added
                        self.print_file_status(status, path)
                        # Only chunkify the file if needed
                        changed_while_backup = False
                        if "chunks" not in item:
                            with backup_io("read"):
                                self.process_file_chunks(
                                    item,
                                    cache,
                                    self.stats,
                                    self.show_progress,
                                    backup_io_iter(self.chunker.chunkify(None, fd)),
                                )
                                self.stats.chunking_time = self.chunker.chunking_time
                            if not is_win32:  # TODO for win32
                                with backup_io("fstat2"):
                                    st2 = os.fstat(fd)
                                # special files:
                                # - fifos change naturally, because they are fed from the other side. no problem.
                                # - blk/chr devices don't change ctime anyway.
                                changed_while_backup = not is_special_file and st.st_ctime_ns != st2.st_ctime_ns
                            if changed_while_backup:
                                # regular file changed while we backed it up, might be inconsistent/corrupt!
                                if last_try:
                                    status = "C"  # crap! retries did not help.
                                else:
                                    raise BackupError("file changed while we read it!")
                            if not is_special_file and not changed_while_backup:
                                # we must not memorize special files, because the contents of e.g. a
                                # block or char device will change without its mtime/size/inode changing.
                                # also, we must not memorize a potentially inconsistent/corrupt file that
                                # changed while we backed it up.
                                cache.memorize_file(hashed_path, path_hash, st, [c.id for c in item.chunks])
                        self.stats.files_stats[status] += 1  # must be done late
                        if not changed_while_backup:
                            status = None  # we already called print_file_status
                    self.stats.nfiles += 1
                    item.update(self.metadata_collector.stat_ext_attrs(st, path, fd=fd))
                    item.get_size(memorize=True)
                    return status
                except BackupOSError:
                    # Something went wrong and we might need to clean up a bit.
                    # Maybe we have already incref'ed some file content chunks in the repo -
                    # but we will not add an item (see add_item in create_helper) and thus
                    # they would be orphaned chunks in case that we commit the transaction.
                    for chunk in item.get("chunks", []):
                        cache.chunk_decref(chunk.id, self.stats, wait=False)
                    # Now that we have cleaned up the chunk references, we can re-raise the exception.
                    # This will skip processing of this file, but might retry or continue with the next one.
                    raise


class TarfileObjectProcessors:
    def __init__(
        self,
        *,
        cache,
        key,
        add_item,
        process_file_chunks,
        chunker_params,
        show_progress,
        log_json,
        iec,
        file_status_printer=None,
    ):
        self.cache = cache
        self.key = key
        self.add_item = add_item
        self.process_file_chunks = process_file_chunks
        self.show_progress = show_progress
        self.print_file_status = file_status_printer or (lambda *args: None)

        self.stats = Statistics(output_json=log_json, iec=iec)  # threading: done by cache (including progress)
        self.chunker = get_chunker(*chunker_params, seed=key.chunk_seed, sparse=False)
        self.hlm = HardLinkManager(id_type=str, info_type=list)  # path -> chunks

    @contextmanager
    def create_helper(self, tarinfo, status=None, type=None):
        ph = tarinfo.pax_headers
        if ph and "BORG.item.version" in ph:
            assert ph["BORG.item.version"] == "1"
            meta_bin = base64.b64decode(ph["BORG.item.meta"])
            meta_dict = msgpack.unpackb(meta_bin, object_hook=StableDict)
            item = Item(internal_dict=meta_dict)
        else:

            def s_to_ns(s):
                return safe_ns(int(float(s) * 1e9))

            item = Item(
                path=make_path_safe(tarinfo.name),
                mode=tarinfo.mode | type,
                uid=tarinfo.uid,
                gid=tarinfo.gid,
                mtime=s_to_ns(tarinfo.mtime),
            )
            if tarinfo.uname:
                item.user = tarinfo.uname
            if tarinfo.gname:
                item.group = tarinfo.gname
            if ph:
                # note: for mtime this is a bit redundant as it is already done by tarfile module,
                #       but we just do it in our way to be consistent for sure.
                for name in "atime", "ctime", "mtime":
                    if name in ph:
                        ns = s_to_ns(ph[name])
                        setattr(item, name, ns)
        yield item, status
        # if we get here, "with"-block worked ok without error/exception, the item was processed ok...
        self.add_item(item, stats=self.stats)

    def process_dir(self, *, tarinfo, status, type):
        with self.create_helper(tarinfo, status, type) as (item, status):
            return status

    def process_fifo(self, *, tarinfo, status, type):
        with self.create_helper(tarinfo, status, type) as (item, status):
            return status

    def process_dev(self, *, tarinfo, status, type):
        with self.create_helper(tarinfo, status, type) as (item, status):
            item.rdev = os.makedev(tarinfo.devmajor, tarinfo.devminor)
            return status

    def process_symlink(self, *, tarinfo, status, type):
        with self.create_helper(tarinfo, status, type) as (item, status):
            item.target = tarinfo.linkname
            return status

    def process_hardlink(self, *, tarinfo, status, type):
        with self.create_helper(tarinfo, status, type) as (item, status):
            # create a not hardlinked borg item, reusing the chunks, see HardLinkManager.__doc__
            chunks = self.hlm.retrieve(tarinfo.linkname)
            if chunks is not None:
                item.chunks = chunks
            item.get_size(memorize=True, from_chunks=True)
            self.stats.nfiles += 1
            return status

    def process_file(self, *, tarinfo, status, type, tar):
        with self.create_helper(tarinfo, status, type) as (item, status):
            self.print_file_status(status, tarinfo.name)
            status = None  # we already printed the status
            try:
                fd = tar.extractfile(tarinfo)
                self.process_file_chunks(
                    item, self.cache, self.stats, self.show_progress, backup_io_iter(self.chunker.chunkify(fd))
                )
                item.get_size(memorize=True, from_chunks=True)
                self.stats.nfiles += 1
                # we need to remember ALL files, see HardLinkManager.__doc__
                self.hlm.remember(id=tarinfo.name, info=item.chunks)
                return status
            except BackupOSError:
                # see comment in FilesystemObjectProcessors.process_file, same issue here.
                for chunk in item.get("chunks", []):
                    self.cache.chunk_decref(chunk.id, self.stats, wait=False)
                raise


def valid_msgpacked_dict(d, keys_serialized):
    """check if the data <d> looks like a msgpacked dict"""
    d_len = len(d)
    if d_len == 0:
        return False
    if d[0] & 0xF0 == 0x80:  # object is a fixmap (up to 15 elements)
        offs = 1
    elif d[0] == 0xDE:  # object is a map16 (up to 2^16-1 elements)
        offs = 3
    else:
        # object is not a map (dict)
        # note: we must not have dicts with > 2^16-1 elements
        return False
    if d_len <= offs:
        return False
    # is the first dict key a bytestring?
    if d[offs] & 0xE0 == 0xA0:  # key is a small bytestring (up to 31 chars)
        pass
    elif d[offs] in (0xD9, 0xDA, 0xDB):  # key is a str8, str16 or str32
        pass
    else:
        # key is not a bytestring
        return False
    # is the bytestring any of the expected key names?
    key_serialized = d[offs:]
    return any(key_serialized.startswith(pattern) for pattern in keys_serialized)


class RobustUnpacker:
    """A restartable/robust version of the streaming msgpack unpacker"""

    def __init__(self, validator, item_keys):
        super().__init__()
        self.item_keys = [msgpack.packb(name) for name in item_keys]
        self.validator = validator
        self._buffered_data = []
        self._resync = False
        self._unpacker = msgpack.Unpacker(object_hook=StableDict)

    def resync(self):
        self._buffered_data = []
        self._resync = True

    def feed(self, data):
        if self._resync:
            self._buffered_data.append(data)
        else:
            self._unpacker.feed(data)

    def __iter__(self):
        return self

    def __next__(self):
        if self._resync:
            data = b"".join(self._buffered_data)
            while self._resync:
                if not data:
                    raise StopIteration
                # Abort early if the data does not look like a serialized item dict
                if not valid_msgpacked_dict(data, self.item_keys):
                    data = data[1:]
                    continue
                self._unpacker = msgpack.Unpacker(object_hook=StableDict)
                self._unpacker.feed(data)
                try:
                    item = next(self._unpacker)
                except (msgpack.UnpackException, StopIteration):
                    # as long as we are resyncing, we also ignore StopIteration
                    pass
                else:
                    if self.validator(item):
                        self._resync = False
                        return item
                data = data[1:]
        else:
            return next(self._unpacker)


class ArchiveChecker:
    def __init__(self):
        self.error_found = False
        self.possibly_superseded = set()

    def check(
        self,
        repository,
        *,
        verify_data=False,
        repair=False,
        match=None,
        sort_by="",
        first=0,
        last=0,
        older=None,
        newer=None,
        oldest=None,
        newest=None,
    ):
        """Perform a set of checks on 'repository'

        :param repair: enable repair mode, write updated or corrected data into repository
        :param first/last/sort_by: only check this number of first/last archives ordered by sort_by
        :param match: only check archives matching this pattern
        :param older/newer: only check archives older/newer than timedelta from now
        :param oldest/newest: only check archives older/newer than timedelta from oldest/newest archive timestamp
        :param verify_data: integrity verification of data referenced by archives
        """
        logger.info("Starting archive consistency check...")
        self.check_all = not any((first, last, match, older, newer, oldest, newest))
        self.repair = repair
        self.repository = repository
        self.init_chunks()
        if not self.chunks:
            logger.error("Repository contains no apparent data at all, cannot continue check/repair.")
            return False
        self.key = self.make_key(repository)
        self.repo_objs = RepoObj(self.key)
        if verify_data:
            self.verify_data()
        if Manifest.MANIFEST_ID not in self.chunks:
            logger.error("Repository manifest not found!")
            self.error_found = True
            self.manifest = self.rebuild_manifest()
        else:
            try:
                self.manifest = Manifest.load(repository, (Manifest.Operation.CHECK,), key=self.key)
            except IntegrityErrorBase as exc:
                logger.error("Repository manifest is corrupted: %s", exc)
                self.error_found = True
                del self.chunks[Manifest.MANIFEST_ID]
                self.manifest = self.rebuild_manifest()
        self.rebuild_refcounts(
            match=match, first=first, last=last, sort_by=sort_by, older=older, oldest=oldest, newer=newer, newest=newest
        )
        self.orphan_chunks_check()
        self.finish()
        if self.error_found:
            logger.error("Archive consistency check complete, problems found.")
        else:
            logger.info("Archive consistency check complete, no problems found.")
        return self.repair or not self.error_found

    def init_chunks(self):
        """Fetch a list of all object keys from repository"""
        # Explicitly set the initial usable hash table capacity to avoid performance issues
        # due to hash table "resonance".
        # Since reconstruction of archive items can add some new chunks, add 10 % headroom.
        self.chunks = ChunkIndex(usable=len(self.repository) * 1.1)
        marker = None
        while True:
            result = self.repository.list(limit=LIST_SCAN_LIMIT, marker=marker)
            if not result:
                break
            marker = result[-1]
            init_entry = ChunkIndexEntry(refcount=0, size=0)
            for id_ in result:
                self.chunks[id_] = init_entry

    def make_key(self, repository):
        attempt = 0
        for chunkid, _ in self.chunks.iteritems():
            attempt += 1
            if attempt > 999:
                # we did a lot of attempts, but could not create the key via key_factory, give up.
                break
            cdata = repository.get(chunkid)
            try:
                return key_factory(repository, cdata)
            except UnsupportedPayloadError:
                # we get here, if the cdata we got has a corrupted key type byte
                pass  # ignore it, just try the next chunk
        if attempt == 0:
            msg = "make_key: repository has no chunks at all!"
        else:
            msg = "make_key: failed to create the key (tried %d chunks)" % attempt
        raise IntegrityError(msg)

    def verify_data(self):
        logger.info("Starting cryptographic data integrity verification...")
        chunks_count_index = len(self.chunks)
        chunks_count_segments = 0
        errors = 0
        defect_chunks = []
        pi = ProgressIndicatorPercent(
            total=chunks_count_index, msg="Verifying data %6.2f%%", step=0.01, msgid="check.verify_data"
        )
        state = None
        while True:
            chunk_ids, state = self.repository.scan(limit=100, state=state)
            if not chunk_ids:
                break
            chunks_count_segments += len(chunk_ids)
            chunk_data_iter = self.repository.get_many(chunk_ids)
            chunk_ids_revd = list(reversed(chunk_ids))
            while chunk_ids_revd:
                pi.show()
                chunk_id = chunk_ids_revd.pop(-1)  # better efficiency
                try:
                    encrypted_data = next(chunk_data_iter)
                except (Repository.ObjectNotFound, IntegrityErrorBase) as err:
                    self.error_found = True
                    errors += 1
                    logger.error("chunk %s: %s", bin_to_hex(chunk_id), err)
                    if isinstance(err, IntegrityErrorBase):
                        defect_chunks.append(chunk_id)
                    # as the exception killed our generator, make a new one for remaining chunks:
                    if chunk_ids_revd:
                        chunk_ids = list(reversed(chunk_ids_revd))
                        chunk_data_iter = self.repository.get_many(chunk_ids)
                else:
                    try:
                        # we must decompress, so it'll call assert_id() in there:
                        self.repo_objs.parse(chunk_id, encrypted_data, decompress=True, ro_type=ROBJ_DONTCARE)
                    except IntegrityErrorBase as integrity_error:
                        self.error_found = True
                        errors += 1
                        logger.error("chunk %s, integrity error: %s", bin_to_hex(chunk_id), integrity_error)
                        defect_chunks.append(chunk_id)
        pi.finish()
        if chunks_count_index != chunks_count_segments:
            logger.error("Repo/Chunks index object count vs. segment files object count mismatch.")
            logger.error(
                "Repo/Chunks index: %d objects != segment files: %d objects", chunks_count_index, chunks_count_segments
            )
        if defect_chunks:
            if self.repair:
                # if we kill the defect chunk here, subsequent actions within this "borg check"
                # run will find missing chunks and replace them with all-zero replacement
                # chunks and flag the files as "repaired".
                # if another backup is done later and the missing chunks get backed up again,
                # a "borg check" afterwards can heal all files where this chunk was missing.
                logger.warning(
                    "Found defect chunks. They will be deleted now, so affected files can "
                    "get repaired now and maybe healed later."
                )
                for defect_chunk in defect_chunks:
                    # remote repo (ssh): retry might help for strange network / NIC / RAM errors
                    # as the chunk will be retransmitted from remote server.
                    # local repo (fs): as chunks.iteritems loop usually pumps a lot of data through,
                    # a defect chunk is likely not in the fs cache any more and really gets re-read
                    # from the underlying media.
                    try:
                        encrypted_data = self.repository.get(defect_chunk)
                        # we must decompress, so it'll call assert_id() in there:
                        self.repo_objs.parse(defect_chunk, encrypted_data, decompress=True, ro_type=ROBJ_DONTCARE)
                    except IntegrityErrorBase:
                        # failed twice -> get rid of this chunk
                        del self.chunks[defect_chunk]
                        self.repository.delete(defect_chunk)
                        logger.debug("chunk %s deleted.", bin_to_hex(defect_chunk))
                    else:
                        logger.warning("chunk %s not deleted, did not consistently fail.", bin_to_hex(defect_chunk))
            else:
                logger.warning(
                    "Found defect chunks. With --repair, they would get deleted, so affected "
                    "files could get repaired then and maybe healed later."
                )
                for defect_chunk in defect_chunks:
                    logger.debug("chunk %s is defect.", bin_to_hex(defect_chunk))
        log = logger.error if errors else logger.info
        log(
            "Finished cryptographic data integrity verification, verified %d chunks with %d integrity errors.",
            chunks_count_segments,
            errors,
        )

    def rebuild_manifest(self):
        """Rebuild the manifest object if it is missing

        Iterates through all objects in the repository looking for archive metadata blocks.
        """

        def valid_archive(obj):
            if not isinstance(obj, dict):
                return False
            return REQUIRED_ARCHIVE_KEYS.issubset(obj)

        logger.info("Rebuilding missing manifest, this might take some time...")
        # as we have lost the manifest, we do not know any more what valid item keys we had.
        # collecting any key we encounter in a damaged repo seems unwise, thus we just use
        # the hardcoded list from the source code. thus, it is not recommended to rebuild a
        # lost manifest on a older borg version than the most recent one that was ever used
        # within this repository (assuming that newer borg versions support more item keys).
        manifest = Manifest(self.key, self.repository)
        pi = ProgressIndicatorPercent(
            total=len(self.chunks), msg="Rebuilding manifest %6.2f%%", step=0.01, msgid="check.rebuild_manifest"
        )
        for chunk_id, _ in self.chunks.iteritems():
            pi.show()
            cdata = self.repository.get(chunk_id)
            try:
                meta, data = self.repo_objs.parse(chunk_id, cdata, ro_type=ROBJ_DONTCARE)
            except IntegrityErrorBase as exc:
                logger.error("Skipping corrupted chunk: %s", exc)
                self.error_found = True
                continue
            if meta["type"] != ROBJ_ARCHIVE_META:
                continue
            try:
                archive = msgpack.unpackb(data)
            # Ignore exceptions that might be raised when feeding msgpack with invalid data
            except msgpack.UnpackException:
                continue
            if valid_archive(archive):
                archive = self.key.unpack_archive(data)
                archive = ArchiveItem(internal_dict=archive)
                name = archive.name
                logger.info("Found archive %s", name)
                if name in manifest.archives:
                    i = 1
                    while True:
                        new_name = "%s.%d" % (name, i)
                        if new_name not in manifest.archives:
                            break
                        i += 1
                    logger.warning("Duplicate archive name %s, storing as %s", name, new_name)
                    name = new_name
                manifest.archives[name] = (chunk_id, archive.time)
        pi.finish()
        logger.info("Manifest rebuild complete.")
        return manifest

    def rebuild_refcounts(
        self, first=0, last=0, sort_by="", match=None, older=None, newer=None, oldest=None, newest=None
    ):
        """Rebuild object reference counts by walking the metadata

        Missing and/or incorrect data is repaired when detected
        """
        # Exclude the manifest from chunks (manifest entry might be already deleted from self.chunks)
        self.chunks.pop(Manifest.MANIFEST_ID, None)

        def mark_as_possibly_superseded(id_):
            if self.chunks.get(id_, ChunkIndexEntry(0, 0)).refcount == 0:
                self.possibly_superseded.add(id_)

        def add_callback(chunk):
            id_ = self.key.id_hash(chunk)
            cdata = self.repo_objs.format(id_, {}, chunk, ro_type=ROBJ_ARCHIVE_STREAM)
            add_reference(id_, len(chunk), cdata)
            return id_

        def add_reference(id_, size, cdata=None):
            try:
                self.chunks.incref(id_)
            except KeyError:
                assert cdata is not None
                self.chunks[id_] = ChunkIndexEntry(refcount=1, size=size)
                if self.repair:
                    self.repository.put(id_, cdata)

        def verify_file_chunks(archive_name, item):
            """Verifies that all file chunks are present.

            Missing file chunks will be replaced with new chunks of the same length containing all zeros.
            If a previously missing file chunk re-appears, the replacement chunk is replaced by the correct one.
            """

            def replacement_chunk(size):
                chunk = Chunk(None, allocation=CH_ALLOC, size=size)
                chunk_id, data = cached_hash(chunk, self.key.id_hash)
                cdata = self.repo_objs.format(chunk_id, {}, data, ro_type=ROBJ_FILE_STREAM)
                return chunk_id, size, cdata

            offset = 0
            chunk_list = []
            chunks_replaced = False
            has_chunks_healthy = "chunks_healthy" in item
            chunks_current = item.chunks
            chunks_healthy = item.chunks_healthy if has_chunks_healthy else chunks_current
            if has_chunks_healthy and len(chunks_current) != len(chunks_healthy):
                # should never happen, but there was issue #3218.
                logger.warning(f"{archive_name}: {item.path}: Invalid chunks_healthy metadata removed!")
                del item.chunks_healthy
                has_chunks_healthy = False
                chunks_healthy = chunks_current
            for chunk_current, chunk_healthy in zip(chunks_current, chunks_healthy):
                chunk_id, size = chunk_healthy
                if chunk_id not in self.chunks:
                    # a chunk of the healthy list is missing
                    if chunk_current == chunk_healthy:
                        logger.error(
                            "{}: {}: New missing file chunk detected (Byte {}-{}, Chunk {}). "
                            "Replacing with all-zero chunk.".format(
                                archive_name, item.path, offset, offset + size, bin_to_hex(chunk_id)
                            )
                        )
                        self.error_found = chunks_replaced = True
                        chunk_id, size, cdata = replacement_chunk(size)
                        add_reference(chunk_id, size, cdata)
                    else:
                        logger.info(
                            "{}: {}: Previously missing file chunk is still missing (Byte {}-{}, Chunk {}). "
                            "It has an all-zero replacement chunk already.".format(
                                archive_name, item.path, offset, offset + size, bin_to_hex(chunk_id)
                            )
                        )
                        chunk_id, size = chunk_current
                        if chunk_id in self.chunks:
                            add_reference(chunk_id, size)
                        else:
                            logger.warning(
                                "{}: {}: Missing all-zero replacement chunk detected (Byte {}-{}, Chunk {}). "
                                "Generating new replacement chunk.".format(
                                    archive_name, item.path, offset, offset + size, bin_to_hex(chunk_id)
                                )
                            )
                            self.error_found = chunks_replaced = True
                            chunk_id, size, cdata = replacement_chunk(size)
                            add_reference(chunk_id, size, cdata)
                else:
                    if chunk_current == chunk_healthy:
                        # normal case, all fine.
                        add_reference(chunk_id, size)
                    else:
                        logger.info(
                            "{}: {}: Healed previously missing file chunk! (Byte {}-{}, Chunk {}).".format(
                                archive_name, item.path, offset, offset + size, bin_to_hex(chunk_id)
                            )
                        )
                        add_reference(chunk_id, size)
                        mark_as_possibly_superseded(chunk_current[0])  # maybe orphaned the all-zero replacement chunk
                chunk_list.append([chunk_id, size])  # list-typed element as chunks_healthy is list-of-lists
                offset += size
            if chunks_replaced and not has_chunks_healthy:
                # if this is first repair, remember the correct chunk IDs, so we can maybe heal the file later
                item.chunks_healthy = item.chunks
            if has_chunks_healthy and chunk_list == chunks_healthy:
                logger.info(f"{archive_name}: {item.path}: Completely healed previously damaged file!")
                del item.chunks_healthy
            item.chunks = chunk_list
            if "size" in item:
                item_size = item.size
                item_chunks_size = item.get_size(from_chunks=True)
                if item_size != item_chunks_size:
                    # just warn, but keep the inconsistency, so that borg extract can warn about it.
                    logger.warning(
                        "{}: {}: size inconsistency detected: size {}, chunks size {}".format(
                            archive_name, item.path, item_size, item_chunks_size
                        )
                    )

        def robust_iterator(archive):
            """Iterates through all archive items

            Missing item chunks will be skipped and the msgpack stream will be restarted
            """
            item_keys = self.manifest.item_keys
            required_item_keys = REQUIRED_ITEM_KEYS
            unpacker = RobustUnpacker(
                lambda item: isinstance(item, StableDict) and "path" in item, self.manifest.item_keys
            )
            _state = 0

            def missing_chunk_detector(chunk_id):
                nonlocal _state
                if _state % 2 != int(chunk_id not in self.chunks):
                    _state += 1
                return _state

            def report(msg, chunk_id, chunk_no):
                cid = bin_to_hex(chunk_id)
                msg += " [chunk: %06d_%s]" % (chunk_no, cid)  # see "debug dump-archive-items"
                self.error_found = True
                logger.error(msg)

            def list_keys_safe(keys):
                return ", ".join(k.decode(errors="replace") if isinstance(k, bytes) else str(k) for k in keys)

            def valid_item(obj):
                if not isinstance(obj, StableDict):
                    return False, "not a dictionary"
                keys = set(obj)
                if not required_item_keys.issubset(keys):
                    return False, "missing required keys: " + list_keys_safe(required_item_keys - keys)
                if not keys.issubset(item_keys):
                    return False, "invalid keys: " + list_keys_safe(keys - item_keys)
                return True, ""

            i = 0
            archive_items = archive_get_items(archive, repo_objs=self.repo_objs, repository=repository)
            for state, items in groupby(archive_items, missing_chunk_detector):
                items = list(items)
                if state % 2:
                    for chunk_id in items:
                        report("item metadata chunk missing", chunk_id, i)
                        i += 1
                    continue
                if state > 0:
                    unpacker.resync()
                for chunk_id, cdata in zip(items, repository.get_many(items)):
                    try:
                        _, data = self.repo_objs.parse(chunk_id, cdata, ro_type=ROBJ_ARCHIVE_STREAM)
                        unpacker.feed(data)
                        for item in unpacker:
                            valid, reason = valid_item(item)
                            if valid:
                                yield Item(internal_dict=item)
                            else:
                                report(
                                    "Did not get expected metadata dict when unpacking item metadata (%s)" % reason,
                                    chunk_id,
                                    i,
                                )
                    except IntegrityError as integrity_error:
                        # repo_objs.parse() detected integrity issues.
                        # maybe the repo gave us a valid cdata, but not for the chunk_id we wanted.
                        # or the authentication of cdata failed, meaning the encrypted data was corrupted.
                        report(str(integrity_error), chunk_id, i)
                    except msgpack.UnpackException:
                        report("Unpacker crashed while unpacking item metadata, trying to resync...", chunk_id, i)
                        unpacker.resync()
                    except Exception:
                        report("Exception while decrypting or unpacking item metadata", chunk_id, i)
                        raise
                    i += 1

        sort_by = sort_by.split(",")
        if any((first, last, match, older, newer, newest, oldest)):
            archive_infos = self.manifest.archives.list(
                sort_by=sort_by,
                match=match,
                first=first,
                last=last,
                oldest=oldest,
                newest=newest,
                older=older,
                newer=newer,
            )
            if match and not archive_infos:
                logger.warning("--match-archives %s does not match any archives", match)
            if first and len(archive_infos) < first:
                logger.warning("--first %d archives: only found %d archives", first, len(archive_infos))
            if last and len(archive_infos) < last:
                logger.warning("--last %d archives: only found %d archives", last, len(archive_infos))
        else:
            archive_infos = self.manifest.archives.list(sort_by=sort_by, consider_checkpoints=True)
        num_archives = len(archive_infos)

        pi = ProgressIndicatorPercent(
            total=num_archives, msg="Checking archives %3.1f%%", step=0.1, msgid="check.rebuild_refcounts"
        )
        with cache_if_remote(self.repository) as repository:
            for i, info in enumerate(archive_infos):
                pi.show(i)
                logger.info(f"Analyzing archive {info.name} ({i + 1}/{num_archives})")
                archive_id = info.id
                if archive_id not in self.chunks:
                    logger.error("Archive metadata block %s is missing!", bin_to_hex(archive_id))
                    self.error_found = True
                    del self.manifest.archives[info.name]
                    continue
                mark_as_possibly_superseded(archive_id)
                cdata = self.repository.get(archive_id)
                try:
                    _, data = self.repo_objs.parse(archive_id, cdata, ro_type=ROBJ_ARCHIVE_META)
                except IntegrityError as integrity_error:
                    logger.error("Archive metadata block %s is corrupted: %s", bin_to_hex(archive_id), integrity_error)
                    self.error_found = True
                    del self.manifest.archives[info.name]
                    continue
                archive = self.key.unpack_archive(data)
                archive = ArchiveItem(internal_dict=archive)
                if archive.version != 2:
                    raise Exception("Unknown archive metadata version")
                items_buffer = ChunkBuffer(self.key)
                items_buffer.write_chunk = add_callback
                for item in robust_iterator(archive):
                    if "chunks" in item:
                        verify_file_chunks(info.name, item)
                    items_buffer.add(item)
                items_buffer.flush(flush=True)
                for previous_item_id in archive_get_items(
                    archive, repo_objs=self.repo_objs, repository=self.repository
                ):
                    mark_as_possibly_superseded(previous_item_id)
                for previous_item_ptr in archive.item_ptrs:
                    mark_as_possibly_superseded(previous_item_ptr)
                archive.item_ptrs = archive_put_items(
                    items_buffer.chunks, repo_objs=self.repo_objs, add_reference=add_reference
                )
                data = self.key.pack_metadata(archive.as_dict())
                new_archive_id = self.key.id_hash(data)
                cdata = self.repo_objs.format(new_archive_id, {}, data, ro_type=ROBJ_ARCHIVE_META)
                add_reference(new_archive_id, len(data), cdata)
                self.manifest.archives[info.name] = (new_archive_id, info.ts)
            pi.finish()

    def orphan_chunks_check(self):
        if self.check_all:
            unused = {id_ for id_, entry in self.chunks.iteritems() if entry.refcount == 0}
            orphaned = unused - self.possibly_superseded
            if orphaned:
                logger.error(f"{len(orphaned)} orphaned objects found!")
                for chunk_id in orphaned:
                    logger.debug(f"chunk {bin_to_hex(chunk_id)} is orphaned.")
                self.error_found = True
            if self.repair and unused:
                logger.info(
                    "Deleting %d orphaned and %d superseded objects..." % (len(orphaned), len(self.possibly_superseded))
                )
                for id_ in unused:
                    self.repository.delete(id_)
                logger.info("Finished deleting orphaned/superseded objects.")
        else:
            logger.info("Orphaned objects check skipped (needs all archives checked).")

    def finish(self):
        if self.repair:
            logger.info("Writing Manifest.")
            self.manifest.write()
            logger.info("Committing repo.")
            self.repository.commit(compact=False)


class ArchiveRecreater:
    class Interrupted(Exception):
        def __init__(self, metadata=None):
            self.metadata = metadata or {}

    @staticmethod
    def is_temporary_archive(archive_name):
        return archive_name.endswith(".recreate")

    def __init__(
        self,
        manifest,
        cache,
        matcher,
        exclude_caches=False,
        exclude_if_present=None,
        keep_exclude_tags=False,
        chunker_params=None,
        compression=None,
        dry_run=False,
        stats=False,
        progress=False,
        file_status_printer=None,
        timestamp=None,
        checkpoint_interval=1800,
        checkpoint_volume=0,
    ):
        self.manifest = manifest
        self.repository = manifest.repository
        self.key = manifest.key
        self.repo_objs = manifest.repo_objs
        self.cache = cache

        self.matcher = matcher
        self.exclude_caches = exclude_caches
        self.exclude_if_present = exclude_if_present or []
        self.keep_exclude_tags = keep_exclude_tags

        self.rechunkify = chunker_params is not None
        if self.rechunkify:
            logger.debug("Rechunking archives to %s", chunker_params)
        self.chunker_params = chunker_params or CHUNKER_PARAMS
        self.compression = compression or CompressionSpec("none")
        self.seen_chunks = set()

        self.timestamp = timestamp
        self.dry_run = dry_run
        self.stats = stats
        self.progress = progress
        self.print_file_status = file_status_printer or (lambda *args: None)
        self.checkpoint_interval = None if dry_run else checkpoint_interval
        self.checkpoint_volume = None if dry_run else checkpoint_volume

    def recreate(self, archive_name, comment=None, target_name=None):
        assert not self.is_temporary_archive(archive_name)
        archive = self.open_archive(archive_name)
        target = self.create_target(archive, target_name)
        if self.exclude_if_present or self.exclude_caches:
            self.matcher_add_tagged_dirs(archive)
        if self.matcher.empty() and not target.recreate_rechunkify and comment is None and target_name is None:
            # nothing to do
            return False
        self.process_items(archive, target)
        replace_original = target_name is None
        self.save(archive, target, comment, replace_original=replace_original)
        return True

    def process_items(self, archive, target):
        matcher = self.matcher

        for item in archive.iter_items():
            if not matcher.match(item.path):
                self.print_file_status("-", item.path)  # excluded (either by "-" or by "!")
                continue
            if self.dry_run:
                self.print_file_status("+", item.path)  # included
            else:
                self.process_item(archive, target, item)
        if self.progress:
            target.stats.show_progress(final=True)

    def process_item(self, archive, target, item):
        status = file_status(item.mode)
        if "chunks" in item:
            self.print_file_status(status, item.path)
            status = None
            self.process_chunks(archive, target, item)
            target.stats.nfiles += 1
        target.add_item(item, stats=target.stats)
        self.print_file_status(status, item.path)

    def process_chunks(self, archive, target, item):
        if not target.recreate_rechunkify:
            for chunk_id, size in item.chunks:
                self.cache.chunk_incref(chunk_id, target.stats)
            return item.chunks
        chunk_iterator = self.iter_chunks(archive, target, list(item.chunks))
        chunk_processor = partial(self.chunk_processor, target)
        target.process_file_chunks(item, self.cache, target.stats, self.progress, chunk_iterator, chunk_processor)

    def chunk_processor(self, target, chunk):
        chunk_id, data = cached_hash(chunk, self.key.id_hash)
        if chunk_id in self.seen_chunks:
            return self.cache.chunk_incref(chunk_id, target.stats)
        chunk_entry = self.cache.add_chunk(chunk_id, {}, data, stats=target.stats, wait=False, ro_type=ROBJ_FILE_STREAM)
        self.cache.repository.async_response(wait=False)
        self.seen_chunks.add(chunk_entry.id)
        return chunk_entry

    def iter_chunks(self, archive, target, chunks):
        chunk_iterator = archive.pipeline.fetch_many([chunk_id for chunk_id, _ in chunks], ro_type=ROBJ_FILE_STREAM)
        if target.recreate_rechunkify:
            # The target.chunker will read the file contents through ChunkIteratorFileWrapper chunk-by-chunk
            # (does not load the entire file into memory)
            file = ChunkIteratorFileWrapper(chunk_iterator)
            yield from target.chunker.chunkify(file)
        else:
            for chunk in chunk_iterator:
                yield Chunk(chunk, size=len(chunk), allocation=CH_DATA)

    def save(self, archive, target, comment=None, replace_original=True):
        if self.dry_run:
            return
        if comment is None:
            comment = archive.metadata.get("comment", "")

        # Keep for the statistics if necessary
        if self.stats:
            _start = target.start

        if self.timestamp is None:
            additional_metadata = {
                "time": archive.metadata.time,
                "time_end": archive.metadata.get("time_end") or archive.metadata.time,
                "command_line": archive.metadata.command_line,
                # but also remember recreate metadata:
                "recreate_command_line": join_cmd(sys.argv),
            }
        else:
            additional_metadata = {
                "command_line": archive.metadata.command_line,
                # but also remember recreate metadata:
                "recreate_command_line": join_cmd(sys.argv),
            }

        target.save(comment=comment, timestamp=self.timestamp, additional_metadata=additional_metadata)
        if replace_original:
            archive.delete(Statistics(), progress=self.progress)
            target.rename(archive.name)
        if self.stats:
            target.start = _start
            target.end = archive_ts_now()
            log_multi(str(target), str(target.stats))

    def matcher_add_tagged_dirs(self, archive):
        """Add excludes to the matcher created by exclude_cache and exclude_if_present."""

        def exclude(dir, tag_item):
            if self.keep_exclude_tags:
                tag_files.append(PathPrefixPattern(tag_item.path, recurse_dir=False))
                tagged_dirs.append(FnmatchPattern(dir + "/", recurse_dir=False))
            else:
                tagged_dirs.append(PathPrefixPattern(dir, recurse_dir=False))

        matcher = self.matcher
        tag_files = []
        tagged_dirs = []

        for item in archive.iter_items(
            filter=lambda item: os.path.basename(item.path) == CACHE_TAG_NAME or matcher.match(item.path)
        ):
            dir, tag_file = os.path.split(item.path)
            if tag_file in self.exclude_if_present:
                exclude(dir, item)
            elif self.exclude_caches and tag_file == CACHE_TAG_NAME and stat.S_ISREG(item.mode):
                file = open_item(archive, item)
                if file.read(len(CACHE_TAG_CONTENTS)) == CACHE_TAG_CONTENTS:
                    exclude(dir, item)
        matcher.add(tag_files, IECommand.Include)
        matcher.add(tagged_dirs, IECommand.ExcludeNoRecurse)

    def create_target(self, archive, target_name=None):
        """Create target archive."""
        target_name = target_name or archive.name + ".recreate"
        target = self.create_target_archive(target_name)
        # If the archives use the same chunker params, then don't rechunkify
        source_chunker_params = tuple(archive.metadata.get("chunker_params", []))
        if len(source_chunker_params) == 4 and isinstance(source_chunker_params[0], int):
            # this is a borg < 1.2 chunker_params tuple, no chunker algo specified, but we only had buzhash:
            source_chunker_params = (CH_BUZHASH,) + source_chunker_params
        target.recreate_rechunkify = self.rechunkify and source_chunker_params != target.chunker_params
        if target.recreate_rechunkify:
            logger.debug(
                "Rechunking archive from %s to %s", source_chunker_params or "(unknown)", target.chunker_params
            )
        target.process_file_chunks = ChunksProcessor(
            cache=self.cache,
            key=self.key,
            add_item=target.add_item,
            prepare_checkpoint=target.prepare_checkpoint,
            write_checkpoint=target.write_checkpoint,
            checkpoint_interval=self.checkpoint_interval,
            checkpoint_volume=self.checkpoint_volume,
            rechunkify=target.recreate_rechunkify,
        ).process_file_chunks
        target.chunker = get_chunker(*target.chunker_params, seed=self.key.chunk_seed, sparse=False)
        return target

    def create_target_archive(self, name):
        target = Archive(
            self.manifest,
            name,
            create=True,
            progress=self.progress,
            chunker_params=self.chunker_params,
            cache=self.cache,
        )
        return target

    def open_archive(self, name, **kwargs):
        return Archive(self.manifest, name, cache=self.cache, **kwargs)

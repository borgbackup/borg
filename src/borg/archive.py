import json
import os
import socket
import stat
import sys
import time
from collections import OrderedDict
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from functools import partial
from getpass import getuser
from io import BytesIO
from itertools import groupby, zip_longest
from shutil import get_terminal_size

from .platformflags import is_win32, is_linux, is_freebsd, is_darwin
from .logger import create_logger

logger = create_logger()

from . import xattr
from .chunker import get_chunker, Chunk
from .cache import ChunkListEntry
from .crypto.key import key_factory, UnsupportedPayloadError
from .compress import Compressor, CompressionSpec
from .constants import *  # NOQA
from .crypto.low_level import IntegrityError as IntegrityErrorBase
from .hashindex import ChunkIndex, ChunkIndexEntry, CacheSynchronizer
from .helpers import Manifest
from .helpers import hardlinkable
from .helpers import ChunkIteratorFileWrapper, open_item
from .helpers import Error, IntegrityError, set_ec
from .platform import uid2user, user2uid, gid2group, group2gid
from .helpers import parse_timestamp, to_localtime
from .helpers import OutputTimestamp, format_timedelta, format_file_size, file_status, FileSize
from .helpers import safe_encode, safe_decode, make_path_safe, remove_surrogates
from .helpers import StableDict
from .helpers import bin_to_hex
from .helpers import safe_ns
from .helpers import ellipsis_truncate, ProgressIndicatorPercent, log_multi
from .helpers import os_open, flags_normal, flags_dir
from .helpers import os_stat
from .helpers import msgpack
from .helpers import sig_int
from .lrucache import LRUCache
from .patterns import PathPrefixPattern, FnmatchPattern, IECommand
from .item import Item, ArchiveItem, ItemDiff
from .platform import acl_get, acl_set, set_flags, get_flags, swidth, hostname
from .remote import cache_if_remote
from .repository import Repository, LIST_SCAN_LIMIT

has_link = hasattr(os, 'link')


class Statistics:

    def __init__(self, output_json=False, iec=False):
        self.output_json = output_json
        self.iec = iec
        self.osize = self.csize = self.usize = self.nfiles = 0
        self.osize_parts = self.csize_parts = self.usize_parts = self.nfiles_parts = 0
        self.last_progress = 0  # timestamp when last progress was shown

    def update(self, size, csize, unique, part=False):
        if not part:
            self.osize += size
            self.csize += csize
            if unique:
                self.usize += csize
        else:
            self.osize_parts += size
            self.csize_parts += csize
            if unique:
                self.usize_parts += csize

    def __add__(self, other):
        if not isinstance(other, Statistics):
            raise TypeError('can only add Statistics objects')
        stats = Statistics(self.output_json, self.iec)
        stats.osize = self.osize + other.osize
        stats.csize = self.csize + other.csize
        stats.usize = self.usize + other.usize
        stats.nfiles = self.nfiles + other.nfiles
        stats.osize_parts = self.osize_parts + other.osize_parts
        stats.csize_parts = self.csize_parts + other.csize_parts
        stats.usize_parts = self.usize_parts + other.usize_parts
        stats.nfiles_parts = self.nfiles_parts + other.nfiles_parts
        return stats

    summary = "{label:15} {stats.osize_fmt:>20s} {stats.csize_fmt:>20s} {stats.usize_fmt:>20s}"

    def __str__(self):
        return self.summary.format(stats=self, label='This archive:')

    def __repr__(self):
        return "<{cls} object at {hash:#x} ({self.osize}, {self.csize}, {self.usize})>".format(
            cls=type(self).__name__, hash=id(self), self=self)

    def as_dict(self):
        return {
            'original_size': FileSize(self.osize, iec=self.iec),
            'compressed_size': FileSize(self.csize, iec=self.iec),
            'deduplicated_size': FileSize(self.usize, iec=self.iec),
            'nfiles': self.nfiles,
        }

    def as_raw_dict(self):
        return {
            'size': self.osize,
            'csize': self.csize,
            'nfiles': self.nfiles,
            'size_parts': self.osize_parts,
            'csize_parts': self.csize_parts,
            'nfiles_parts': self.nfiles_parts,
        }

    @classmethod
    def from_raw_dict(cls, **kw):
        self = cls()
        self.osize = kw['size']
        self.csize = kw['csize']
        self.nfiles = kw['nfiles']
        self.osize_parts = kw['size_parts']
        self.csize_parts = kw['csize_parts']
        self.nfiles_parts = kw['nfiles_parts']
        return self

    @property
    def osize_fmt(self):
        return format_file_size(self.osize, iec=self.iec)

    @property
    def usize_fmt(self):
        return format_file_size(self.usize, iec=self.iec)

    @property
    def csize_fmt(self):
        return format_file_size(self.csize, iec=self.iec)

    def show_progress(self, item=None, final=False, stream=None, dt=None):
        now = time.monotonic()
        if dt is None or now - self.last_progress > dt:
            self.last_progress = now
            if self.output_json:
                if not final:
                    data = self.as_dict()
                    data['path'] = remove_surrogates(item.path if item else '')
                else:
                    data = {}
                data.update({
                    'time': time.time(),
                    'type': 'archive_progress',
                    'finished': final,
                })
                msg = json.dumps(data)
                end = '\n'
            else:
                columns, lines = get_terminal_size()
                if not final:
                    msg = '{0.osize_fmt} O {0.csize_fmt} C {0.usize_fmt} D {0.nfiles} N '.format(self)
                    path = remove_surrogates(item.path) if item else ''
                    space = columns - swidth(msg)
                    if space < 12:
                        msg = ''
                        space = columns - swidth(msg)
                    if space >= 8:
                        msg += ellipsis_truncate(path, space)
                else:
                    msg = ' ' * columns
                end = '\r'
            print(msg, end=end, file=stream or sys.stderr, flush=True)


def is_special(mode):
    # file types that get special treatment in --read-special mode
    return stat.S_ISBLK(mode) or stat.S_ISCHR(mode) or stat.S_ISFIFO(mode)


class BackupError(Exception):
    """
    Exception raised for non-OSError-based exceptions while accessing backup files.
    """


class BackupOSError(Exception):
    """
    Wrapper for OSError raised while accessing backup files.

    Borg does different kinds of IO, and IO failures have different consequences.
    This wrapper represents failures of input file or extraction IO.
    These are non-critical and are only reported (exit code = 1, warning).

    Any unwrapped IO error is critical and aborts execution (for example repository IO failure).
    """
    def __init__(self, op, os_error):
        self.op = op
        self.os_error = os_error
        self.errno = os_error.errno
        self.strerror = os_error.strerror
        self.filename = os_error.filename

    def __str__(self):
        if self.op:
            return f'{self.op}: {self.os_error}'
        else:
            return str(self.os_error)


class BackupIO:
    op = ''

    def __call__(self, op=''):
        self.op = op
        return self

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type and issubclass(exc_type, OSError):
            raise BackupOSError(self.op, exc_val) from exc_val


backup_io = BackupIO()


def backup_io_iter(iterator):
    backup_io.op = 'read'
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
        raise BackupError('file type changed (race condition), skipping file')
    if st_old.st_ino != st_curr.st_ino:
        # in this case, the hardlinks-related code in create_helper has the wrong inode - abort!
        raise BackupError('file inode changed (race condition), skipping file')
    # looks ok, we are still dealing with the same thing - return current stat:
    return st_curr


@contextmanager
def OsOpen(*, flags, path=None, parent_fd=None, name=None, noatime=False, op='open'):
    with backup_io(op):
        fd = os_open(path=path, parent_fd=parent_fd, name=name, flags=flags, noatime=noatime)
    try:
        yield fd
    finally:
        # On windows fd is None for directories.
        if fd is not None:
            os.close(fd)


class DownloadPipeline:

    def __init__(self, repository, key):
        self.repository = repository
        self.key = key

    def unpack_many(self, ids, filter=None, partial_extract=False, preload=False, hardlink_masters=None):
        """
        Return iterator of items.

        *ids* is a chunk ID list of an item stream. *filter* is a callable
        to decide whether an item will be yielded. *preload* preloads the data chunks of every yielded item.

        Warning: if *preload* is True then all data chunks of every yielded item have to be retrieved,
        otherwise preloaded chunks will accumulate in RemoteRepository and create a memory leak.
        """
        def _preload(chunks):
            self.repository.preload([c.id for c in chunks])

        masters_preloaded = set()
        unpacker = msgpack.Unpacker(use_list=False)
        for data in self.fetch_many(ids):
            unpacker.feed(data)
            items = [Item(internal_dict=item) for item in unpacker]
            for item in items:
                if 'chunks' in item:
                    item.chunks = [ChunkListEntry(*e) for e in item.chunks]

            if filter:
                items = [item for item in items if filter(item)]

            if preload:
                if filter and partial_extract:
                    # if we do only a partial extraction, it gets a bit
                    # complicated with computing the preload items: if a hardlink master item is not
                    # selected (== not extracted), we will still need to preload its chunks if a
                    # corresponding hardlink slave is selected (== is extracted).
                    # due to a side effect of the filter() call, we now have hardlink_masters dict populated.
                    for item in items:
                        if hardlinkable(item.mode):
                            source = item.get('source')
                            if source is None:  # maybe a hardlink master
                                if 'chunks' in item:
                                    _preload(item.chunks)
                                # if this is a hl master, remember that we already preloaded all chunks of it (if any):
                                if item.get('hardlink_master', True):
                                    masters_preloaded.add(item.path)
                            else:  # hardlink slave
                                if source not in masters_preloaded:
                                    # we only need to preload *once* (for the 1st selected slave)
                                    chunks, _ = hardlink_masters[source]
                                    if chunks is not None:
                                        _preload(chunks)
                                    masters_preloaded.add(source)
                else:
                    # easy: we do not have a filter, thus all items are selected, thus we need to preload all chunks.
                    for item in items:
                        if 'chunks' in item:
                            _preload(item.chunks)

            for item in items:
                yield item

    def fetch_many(self, ids, is_preloaded=False):
        for id_, data in zip(ids, self.repository.get_many(ids, is_preloaded=is_preloaded)):
            yield self.key.decrypt(id_, data)


class ChunkBuffer:
    BUFFER_SIZE = 8 * 1024 * 1024

    def __init__(self, key, chunker_params=ITEMS_CHUNKER_PARAMS):
        self.buffer = BytesIO()
        self.packer = msgpack.Packer()
        self.chunks = []
        self.key = key
        self.chunker = get_chunker(*chunker_params, seed=self.key.chunk_seed)

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
            alloc = chunk.meta['allocation']
            if alloc == CH_DATA:
                data = bytes(chunk.data)
            elif alloc in (CH_ALLOC, CH_HOLE):
                data = zeros[:chunk.meta['size']]
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


class CacheChunkBuffer(ChunkBuffer):

    def __init__(self, cache, key, stats, chunker_params=ITEMS_CHUNKER_PARAMS):
        super().__init__(key, chunker_params)
        self.cache = cache
        self.stats = stats

    def write_chunk(self, chunk):
        id_, _, _ = self.cache.add_chunk(self.key.id_hash(chunk), chunk, self.stats, wait=False)
        self.cache.repository.async_response(wait=False)
        return id_


def get_item_uid_gid(item, *, numeric, uid_forced=None, gid_forced=None, uid_default=0, gid_default=0):
    if uid_forced is not None:
        uid = uid_forced
    else:
        uid = None if numeric else user2uid(item.user)
        uid = item.uid if uid is None else uid
        if uid < 0:
            uid = uid_default
    if gid_forced is not None:
        gid = gid_forced
    else:
        gid = None if numeric else group2gid(item.group)
        gid = item.gid if gid is None else gid
        if gid < 0:
            gid = gid_default
    return uid, gid


class Archive:

    class DoesNotExist(Error):
        """Archive {} does not exist"""

    class AlreadyExists(Error):
        """Archive {} already exists"""

    class IncompatibleFilesystemEncodingError(Error):
        """Failed to encode filename "{}" into file system encoding "{}". Consider configuring the LANG environment variable."""

    def __init__(self, repository, key, manifest, name, cache=None, create=False,
                 checkpoint_interval=1800, numeric_ids=False, noatime=False, noctime=False,
                 noflags=False, noacls=False, noxattrs=False,
                 progress=False, chunker_params=CHUNKER_PARAMS, start=None, start_monotonic=None, end=None,
                 consider_part_files=False, log_json=False, iec=False):
        self.cwd = os.getcwd()
        self.key = key
        self.repository = repository
        self.cache = cache
        self.manifest = manifest
        self.hard_links = {}
        self.stats = Statistics(output_json=log_json, iec=iec)
        self.iec = iec
        self.show_progress = progress
        self.name = name  # overwritten later with name from archive metadata
        self.name_in_manifest = name  # can differ from .name later (if borg check fixed duplicate archive names)
        self.comment = None
        self.checkpoint_interval = checkpoint_interval
        self.numeric_ids = numeric_ids
        self.noatime = noatime
        self.noctime = noctime
        self.noflags = noflags
        self.noacls = noacls
        self.noxattrs = noxattrs
        assert (start is None) == (start_monotonic is None), 'Logic error: if start is given, start_monotonic must be given as well and vice versa.'
        if start is None:
            start = datetime.utcnow()
            start_monotonic = time.monotonic()
        self.chunker_params = chunker_params
        self.start = start
        self.start_monotonic = start_monotonic
        if end is None:
            end = datetime.utcnow()
        self.end = end
        self.consider_part_files = consider_part_files
        self.pipeline = DownloadPipeline(self.repository, self.key)
        self.create = create
        if self.create:
            self.items_buffer = CacheChunkBuffer(self.cache, self.key, self.stats)
            if name in manifest.archives:
                raise self.AlreadyExists(name)
            i = 0
            while True:
                self.checkpoint_name = '{}.checkpoint{}'.format(name, i and ('.%d' % i) or '')
                if self.checkpoint_name not in manifest.archives:
                    break
                i += 1
        else:
            info = self.manifest.archives.get(name)
            if info is None:
                raise self.DoesNotExist(name)
            self.load(info.id)

    def _load_meta(self, id):
        data = self.key.decrypt(id, self.repository.get(id))
        metadata = ArchiveItem(internal_dict=msgpack.unpackb(data))
        if metadata.version != 1:
            raise Exception('Unknown archive metadata version')
        return metadata

    def load(self, id):
        self.id = id
        self.metadata = self._load_meta(self.id)
        self.metadata.cmdline = [safe_decode(arg) for arg in self.metadata.cmdline]
        self.name = self.metadata.name
        self.comment = self.metadata.get('comment', '')

    @property
    def ts(self):
        """Timestamp of archive creation (start) in UTC"""
        ts = self.metadata.time
        return parse_timestamp(ts)

    @property
    def ts_end(self):
        """Timestamp of archive creation (end) in UTC"""
        # fall back to time if there is no time_end present in metadata
        ts = self.metadata.get('time_end') or self.metadata.time
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
            start = self.start.replace(tzinfo=timezone.utc)
            end = self.end.replace(tzinfo=timezone.utc)
        else:
            stats = self.calc_stats(self.cache)
            start = self.ts
            end = self.ts_end
        info = {
            'name': self.name,
            'id': self.fpr,
            'start': OutputTimestamp(start),
            'end': OutputTimestamp(end),
            'duration': (end - start).total_seconds(),
            'stats': stats.as_dict(),
            'limits': {
                'max_archive_size': self.cache.chunks[self.id].csize / MAX_DATA_SIZE,
            },
        }
        if self.create:
            info['command_line'] = sys.argv
        else:
            info.update({
                'command_line': self.metadata.cmdline,
                'hostname': self.metadata.hostname,
                'username': self.metadata.username,
                'comment': self.metadata.get('comment', ''),
                'chunker_params': self.metadata.get('chunker_params', ''),
            })
        return info

    def __str__(self):
        return '''\
Repository: {location}
Archive name: {0.name}
Archive fingerprint: {0.fpr}
Time (start): {start}
Time (end):   {end}
Duration: {0.duration}
Number of files: {0.stats.nfiles}
Utilization of max. archive size: {csize_max:.0%}
'''.format(
            self,
            start=OutputTimestamp(self.start.replace(tzinfo=timezone.utc)),
            end=OutputTimestamp(self.end.replace(tzinfo=timezone.utc)),
            csize_max=self.cache.chunks[self.id].csize / MAX_DATA_SIZE,
            location=self.repository._location.canonical_path()
)

    def __repr__(self):
        return 'Archive(%r)' % self.name

    def item_filter(self, item, filter=None):
        if not self.consider_part_files and 'part' in item:
            # this is a part(ial) file, we usually don't want to consider it.
            return False
        return filter(item) if filter else True

    def iter_items(self, filter=None, partial_extract=False, preload=False, hardlink_masters=None):
        # note: when calling this with preload=True, later fetch_many() must be called with
        # is_preloaded=True or the RemoteRepository code will leak memory!
        assert not (filter and partial_extract and preload) or hardlink_masters is not None
        for item in self.pipeline.unpack_many(self.metadata.items, partial_extract=partial_extract,
                                              preload=preload, hardlink_masters=hardlink_masters,
                                              filter=lambda item: self.item_filter(item, filter)):
            yield item

    def add_item(self, item, show_progress=True, stats=None):
        if show_progress and self.show_progress:
            if stats is None:
                stats = self.stats
            stats.show_progress(item=item, dt=0.2)
        self.items_buffer.add(item)

    def write_checkpoint(self):
        self.save(self.checkpoint_name)
        del self.manifest.archives[self.checkpoint_name]
        self.cache.chunk_decref(self.id, self.stats)

    def save(self, name=None, comment=None, timestamp=None, stats=None, additional_metadata=None):
        name = name or self.name
        if name in self.manifest.archives:
            raise self.AlreadyExists(name)
        self.items_buffer.flush(flush=True)
        duration = timedelta(seconds=time.monotonic() - self.start_monotonic)
        if timestamp is None:
            end = datetime.utcnow()
            start = end - duration
        else:
            end = timestamp + duration
            start = timestamp
        self.start = start
        self.end = end
        metadata = {
            'version': 1,
            'name': name,
            'comment': comment or '',
            'items': self.items_buffer.chunks,
            'cmdline': sys.argv,
            'hostname': hostname,
            'username': getuser(),
            'time': start.strftime(ISO_FORMAT),
            'time_end': end.strftime(ISO_FORMAT),
            'chunker_params': self.chunker_params,
        }
        if stats is not None:
            metadata.update({
                'size': stats.osize,
                'csize': stats.csize,
                'nfiles': stats.nfiles,
                'size_parts': stats.osize_parts,
                'csize_parts': stats.csize_parts,
                'nfiles_parts': stats.nfiles_parts})
        metadata.update(additional_metadata or {})
        metadata = ArchiveItem(metadata)
        data = self.key.pack_and_authenticate_metadata(metadata.as_dict(), context=b'archive')
        self.id = self.key.id_hash(data)
        try:
            self.cache.add_chunk(self.id, data, self.stats)
        except IntegrityError as err:
            err_msg = str(err)
            # hack to avoid changing the RPC protocol by introducing new (more specific) exception class
            if 'More than allowed put data' in err_msg:
                raise Error('%s - archive too big (issue #1473)!' % err_msg)
            else:
                raise
        while self.repository.async_response(wait=True) is not None:
            pass
        self.manifest.archives[name] = (self.id, metadata.time)
        self.manifest.write()
        self.repository.commit(compact=False)
        self.cache.commit()

    def calc_stats(self, cache, want_unique=True):
        # caching wrapper around _calc_stats which is rather slow for archives made with borg < 1.2
        have_borg12_meta = self.metadata.get('nfiles') is not None
        try:
            if want_unique:
                # usize is neither contained in the borg 1.2 archive metadata nor in the
                # pre12_meta cache entry representing the same information for 1.1 archives.
                # usize is not a static property of an archive, but must get dynamically calculated,
                # thus we must trigger a call to self._calc_stats() to get it.
                raise KeyError
            stats = Statistics.from_raw_dict(**cache.pre12_meta[self.fpr])
        except KeyError:  # not in pre12_meta cache
            stats = self._calc_stats(cache, want_unique=want_unique)
            if not have_borg12_meta:
                cache.pre12_meta[self.fpr] = stats.as_raw_dict()
        return stats

    def _calc_stats(self, cache, want_unique=True):
        have_borg12_meta = self.metadata.get('nfiles') is not None

        if have_borg12_meta and not want_unique:
            unique_csize = 0
        else:
            def add(id):
                entry = cache.chunks[id]
                archive_index.add(id, 1, entry.size, entry.csize)

            archive_index = ChunkIndex()
            sync = CacheSynchronizer(archive_index)
            add(self.id)
            # we must escape any % char in the archive name, because we use it in a format string, see #6500
            arch_name_escd = self.name.replace('%', '%%')
            pi = ProgressIndicatorPercent(total=len(self.metadata.items),
                                          msg='Calculating statistics for archive %s ... %%3.0f%%%%' % arch_name_escd,
                                          msgid='archive.calc_stats')
            for id, chunk in zip(self.metadata.items, self.repository.get_many(self.metadata.items)):
                pi.show(increase=1)
                add(id)
                data = self.key.decrypt(id, chunk)
                sync.feed(data)
            unique_csize = archive_index.stats_against(cache.chunks)[3]
            pi.finish()

        stats = Statistics(iec=self.iec)
        stats.usize = unique_csize  # the part files use same chunks as the full file
        if not have_borg12_meta:
            if self.consider_part_files:
                stats.nfiles = sync.num_files_totals
                stats.osize = sync.size_totals
                stats.csize = sync.csize_totals
            else:
                stats.nfiles = sync.num_files_totals - sync.num_files_parts
                stats.osize = sync.size_totals - sync.size_parts
                stats.csize = sync.csize_totals - sync.csize_parts
        else:
            if self.consider_part_files:
                stats.nfiles = self.metadata.nfiles_parts + self.metadata.nfiles
                stats.osize = self.metadata.size_parts + self.metadata.size
                stats.csize = self.metadata.csize_parts + self.metadata.csize
            else:
                stats.nfiles = self.metadata.nfiles
                stats.osize = self.metadata.size
                stats.csize = self.metadata.csize
        return stats

    @contextmanager
    def extract_helper(self, dest, item, path, stripped_components, original_path, hardlink_masters):
        hardlink_set = False
        # Hard link?
        if 'source' in item:
            source = os.path.join(dest, *item.source.split(os.sep)[stripped_components:])
            chunks, link_target = hardlink_masters.get(item.source, (None, source))
            if link_target and has_link:
                # Hard link was extracted previously, just link
                with backup_io('link'):
                    os.link(link_target, path)
                    hardlink_set = True
            elif chunks is not None:
                # assign chunks to this item, since the item which had the chunks was not extracted
                item.chunks = chunks
        yield hardlink_set
        if not hardlink_set and hardlink_masters:
            if has_link:
                # Update master entry with extracted item path, so that following hardlinks don't extract twice.
                # We have hardlinking support, so we will hardlink not extract.
                hardlink_masters[item.get('source') or original_path] = (None, path)
            else:
                # Broken platform with no hardlinking support.
                # In this case, we *want* to extract twice, because there is no other way.
                pass

    def extract_item(self, item, restore_attrs=True, dry_run=False, stdout=False, sparse=False,
                     hardlink_masters=None, stripped_components=0, original_path=None, pi=None):
        """
        Extract archive item.

        :param item: the item to extract
        :param restore_attrs: restore file attributes
        :param dry_run: do not write any data
        :param stdout: write extracted data to stdout
        :param sparse: write sparse files (chunk-granularity, independent of the original being sparse)
        :param hardlink_masters: maps paths to (chunks, link_target) for extracting subtrees with hardlinks correctly
        :param stripped_components: stripped leading path components to correct hard link extraction
        :param original_path: 'path' key as stored in archive
        :param pi: ProgressIndicatorPercent (or similar) for file extraction progress (in bytes)
        """
        hardlink_masters = hardlink_masters or {}
        has_damaged_chunks = 'chunks_healthy' in item
        if dry_run or stdout:
            if 'chunks' in item:
                item_chunks_size = 0
                for data in self.pipeline.fetch_many([c.id for c in item.chunks], is_preloaded=True):
                    if pi:
                        pi.show(increase=len(data), info=[remove_surrogates(item.path)])
                    if stdout:
                        sys.stdout.buffer.write(data)
                    item_chunks_size += len(data)
                if stdout:
                    sys.stdout.buffer.flush()
                if 'size' in item:
                    item_size = item.size
                    if item_size != item_chunks_size:
                        raise BackupError('Size inconsistency detected: size {}, chunks size {}'.format(
                                          item_size, item_chunks_size))
            if has_damaged_chunks:
                raise BackupError('File has damaged (all-zero) chunks. Try running borg check --repair.')
            return

        original_path = original_path or item.path
        dest = self.cwd
        if item.path.startswith(('/', '../')):
            raise Exception('Path should be relative and local')
        path = os.path.join(dest, item.path)
        # Attempt to remove existing files, ignore errors on failure
        try:
            st = os.stat(path, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
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
            with backup_io('makedirs'):
                make_parent(path)
            with self.extract_helper(dest, item, path, stripped_components, original_path,
                                     hardlink_masters) as hardlink_set:
                if hardlink_set:
                    return
                with backup_io('open'):
                    fd = open(path, 'wb')
                with fd:
                    ids = [c.id for c in item.chunks]
                    for data in self.pipeline.fetch_many(ids, is_preloaded=True):
                        if pi:
                            pi.show(increase=len(data), info=[remove_surrogates(item.path)])
                        with backup_io('write'):
                            if sparse and zeros.startswith(data):
                                # all-zero chunk: create a hole in a sparse file
                                fd.seek(len(data), 1)
                            else:
                                fd.write(data)
                    with backup_io('truncate_and_attrs'):
                        pos = item_chunks_size = fd.tell()
                        fd.truncate(pos)
                        fd.flush()
                        self.restore_attrs(path, item, fd=fd.fileno())
                if 'size' in item:
                    item_size = item.size
                    if item_size != item_chunks_size:
                        raise BackupError('Size inconsistency detected: size {}, chunks size {}'.format(
                                          item_size, item_chunks_size))
                if has_damaged_chunks:
                    raise BackupError('File has damaged (all-zero) chunks. Try running borg check --repair.')
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
                source = item.source
                try:
                    os.symlink(source, path)
                except UnicodeEncodeError:
                    raise self.IncompatibleFilesystemEncodingError(source, sys.getfilesystemencoding()) from None
                self.restore_attrs(path, item, symlink=True)
            elif stat.S_ISFIFO(mode):
                make_parent(path)
                with self.extract_helper(dest, item, path, stripped_components, original_path,
                                         hardlink_masters) as hardlink_set:
                    if hardlink_set:
                        return
                    os.mkfifo(path)
                    self.restore_attrs(path, item)
            elif stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
                make_parent(path)
                with self.extract_helper(dest, item, path, stripped_components, original_path,
                                         hardlink_masters) as hardlink_set:
                    if hardlink_set:
                        return
                    os.mknod(path, item.mode, item.rdev)
                    self.restore_attrs(path, item)
            else:
                raise Exception('Unknown archive item type %r' % item.mode)

    def restore_attrs(self, path, item, symlink=False, fd=None):
        """
        Restore filesystem attributes on *path* (*fd*) from *item*.

        Does not access the repository.
        """
        backup_io.op = 'attrs'
        uid, gid = get_item_uid_gid(item, numeric=self.numeric_ids)
        # This code is a bit of a mess due to os specific differences
        if not is_win32:
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
            mtime = item.mtime
            if 'atime' in item:
                atime = item.atime
            else:
                # old archives only had mtime in item metadata
                atime = mtime
            if 'birthtime' in item:
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
            if not self.noacls:
                acl_set(path, item, self.numeric_ids, fd=fd)
            if not self.noxattrs:
                # chown removes Linux capabilities, so set the extended attributes at the end, after chown, since they include
                # the Linux capabilities in the "security.capability" attribute.
                warning = xattr.set_all(fd or path, item.get('xattrs', {}), follow_symlinks=False)
                if warning:
                    set_ec(EXIT_WARNING)
            # bsdflags include the immutable flag and need to be set last:
            if not self.noflags and 'bsdflags' in item:
                try:
                    set_flags(path, item.bsdflags, fd=fd)
                except OSError:
                    pass

    def set_meta(self, key, value):
        metadata = self._load_meta(self.id)
        setattr(metadata, key, value)
        data = msgpack.packb(metadata.as_dict())
        new_id = self.key.id_hash(data)
        self.cache.add_chunk(new_id, data, self.stats)
        self.manifest.archives[self.name] = (new_id, metadata.time)
        self.cache.chunk_decref(self.id, self.stats)
        self.id = new_id

    def rename(self, name):
        if name in self.manifest.archives:
            raise self.AlreadyExists(name)
        oldname = self.name
        self.name = name
        self.set_meta('name', name)
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

        def chunk_decref(id, stats, part=False):
            try:
                self.cache.chunk_decref(id, stats, wait=False, part=part)
            except KeyError:
                cid = bin_to_hex(id)
                raise ChunksIndexError(cid)
            else:
                fetch_async_response(wait=False)

        error = False
        try:
            unpacker = msgpack.Unpacker(use_list=False)
            items_ids = self.metadata.items
            pi = ProgressIndicatorPercent(total=len(items_ids), msg="Decrementing references %3.0f%%", msgid='archive.delete')
            for (i, (items_id, data)) in enumerate(zip(items_ids, self.repository.get_many(items_ids))):
                if progress:
                    pi.show(i)
                data = self.key.decrypt(items_id, data)
                unpacker.feed(data)
                chunk_decref(items_id, stats)
                try:
                    for item in unpacker:
                        item = Item(internal_dict=item)
                        if 'chunks' in item:
                            part = not self.consider_part_files and 'part' in item
                            for chunk_id, size, csize in item.chunks:
                                chunk_decref(chunk_id, stats, part=part)
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
            logger.warning('forced deletion succeeded, but the deleted archive was corrupted.')
            logger.warning('borg check --repair is required to free all space.')

    @staticmethod
    def compare_archives_iter(archive1, archive2, matcher=None, can_compare_chunk_ids=False):
        """
        Yields tuples with a path and an ItemDiff instance describing changes/indicating equality.

        :param matcher: PatternMatcher class to restrict results to only matching paths.
        :param can_compare_chunk_ids: Whether --chunker-params are the same for both archives.
        """

        def hardlink_master_seen(item):
            return 'source' not in item or not hardlinkable(item.mode) or item.source in hardlink_masters

        def is_hardlink_master(item):
            return item.get('hardlink_master', True) and 'source' not in item and hardlinkable(item.mode)

        def update_hardlink_masters(item1, item2):
            if is_hardlink_master(item1) or is_hardlink_master(item2):
                hardlink_masters[item1.path] = (item1, item2)

        def has_hardlink_master(item, hardlink_masters):
            return hardlinkable(item.mode) and item.get('source') in hardlink_masters

        def compare_items(item1, item2):
            if has_hardlink_master(item1, hardlink_masters):
                item1 = hardlink_masters[item1.source][0]
            if has_hardlink_master(item2, hardlink_masters):
                item2 = hardlink_masters[item2.source][1]
            return ItemDiff(item1, item2,
                            archive1.pipeline.fetch_many([c.id for c in item1.get('chunks', [])]),
                            archive2.pipeline.fetch_many([c.id for c in item2.get('chunks', [])]),
                            can_compare_chunk_ids=can_compare_chunk_ids)

        def defer_if_necessary(item1, item2):
            """Adds item tuple to deferred if necessary and returns True, if items were deferred"""
            update_hardlink_masters(item1, item2)
            defer = not hardlink_master_seen(item1) or not hardlink_master_seen(item2)
            if defer:
                deferred.append((item1, item2))
            return defer

        orphans_archive1 = OrderedDict()
        orphans_archive2 = OrderedDict()
        deferred = []
        hardlink_masters = {}

        for item1, item2 in zip_longest(
                archive1.iter_items(lambda item: matcher.match(item.path)),
                archive2.iter_items(lambda item: matcher.match(item.path)),
        ):
            if item1 and item2 and item1.path == item2.path:
                if not defer_if_necessary(item1, item2):
                    yield (item1.path, compare_items(item1, item2))
                continue
            if item1:
                matching_orphan = orphans_archive2.pop(item1.path, None)
                if matching_orphan:
                    if not defer_if_necessary(item1, matching_orphan):
                        yield (item1.path, compare_items(item1, matching_orphan))
                else:
                    orphans_archive1[item1.path] = item1
            if item2:
                matching_orphan = orphans_archive1.pop(item2.path, None)
                if matching_orphan:
                    if not defer_if_necessary(matching_orphan, item2):
                        yield (matching_orphan.path, compare_items(matching_orphan, item2))
                else:
                    orphans_archive2[item2.path] = item2
        # At this point orphans_* contain items that had no matching partner in the other archive
        for added in orphans_archive2.values():
            path = added.path
            deleted_item = Item.create_deleted(path)
            update_hardlink_masters(deleted_item, added)
            yield (path, compare_items(deleted_item, added))
        for deleted in orphans_archive1.values():
            path = deleted.path
            deleted_item = Item.create_deleted(path)
            update_hardlink_masters(deleted, deleted_item)
            yield (path, compare_items(deleted, deleted_item))
        for item1, item2 in deferred:
            assert hardlink_master_seen(item1)
            assert hardlink_master_seen(item2)
            yield (path, compare_items(item1, item2))


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
        attrs = dict(
            mode=st.st_mode,
            uid=st.st_uid,
            gid=st.st_gid,
            mtime=safe_ns(st.st_mtime_ns),
        )
        # borg can work with archives only having mtime (older attic archives do not have
        # atime/ctime). it can be useful to omit atime/ctime, if they change without the
        # file content changing - e.g. to get better metadata deduplication.
        if not self.noatime:
            attrs['atime'] = safe_ns(st.st_atime_ns)
        if not self.noctime:
            attrs['ctime'] = safe_ns(st.st_ctime_ns)
        if not self.nobirthtime and hasattr(st, 'st_birthtime'):
            # sadly, there's no stat_result.st_birthtime_ns
            attrs['birthtime'] = safe_ns(int(st.st_birthtime * 10**9))
        if self.numeric_ids:
            attrs['user'] = attrs['group'] = None
        else:
            attrs['user'] = uid2user(st.st_uid)
            attrs['group'] = gid2group(st.st_gid)
        return attrs

    def stat_ext_attrs(self, st, path, fd=None):
        attrs = {}
        with backup_io('extended stat'):
            flags = 0 if self.noflags else get_flags(path, st, fd=fd)
            xattrs = {} if self.noxattrs else xattr.get_all(fd or path, follow_symlinks=False)
            if not self.noacls:
                acl_get(path, attrs, st, self.numeric_ids, fd=fd)
        if xattrs:
            attrs['xattrs'] = StableDict(xattrs)
        if flags:
            attrs['bsdflags'] = flags
        return attrs

    def stat_attrs(self, st, path, fd=None):
        attrs = self.stat_simple_attrs(st)
        attrs.update(self.stat_ext_attrs(st, path, fd=fd))
        return attrs


# remember a few recently used all-zero chunk hashes in this mapping.
# (hash_func, chunk_length) -> chunk_hash
# we play safe and have the hash_func in the mapping key, in case we
# have different hash_funcs within the same borg run.
zero_chunk_ids = LRUCache(10, dispose=lambda _: None)


def cached_hash(chunk, id_hash):
    allocation = chunk.meta['allocation']
    if allocation == CH_DATA:
        data = chunk.data
        chunk_id = id_hash(data)
    elif allocation in (CH_HOLE, CH_ALLOC):
        size = chunk.meta['size']
        assert size <= len(zeros)
        data = memoryview(zeros)[:size]
        try:
            chunk_id = zero_chunk_ids[(id_hash, size)]
        except KeyError:
            chunk_id = id_hash(data)
            zero_chunk_ids[(id_hash, size)] = chunk_id
    else:
        raise ValueError('unexpected allocation type')
    return chunk_id, data


class ChunksProcessor:
    # Processes an iterator of chunks for an Item

    def __init__(self, *, key, cache,
                 add_item, write_checkpoint,
                 checkpoint_interval, rechunkify):
        self.key = key
        self.cache = cache
        self.add_item = add_item
        self.write_checkpoint = write_checkpoint
        self.checkpoint_interval = checkpoint_interval
        self.last_checkpoint = time.monotonic()
        self.rechunkify = rechunkify

    def write_part_file(self, item, from_chunk, number):
        item = Item(internal_dict=item.as_dict())
        length = len(item.chunks)
        # the item should only have the *additional* chunks we processed after the last partial item:
        item.chunks = item.chunks[from_chunk:]
        # for borg recreate, we already have a size member in the source item (giving the total file size),
        # but we consider only a part of the file here, thus we must recompute the size from the chunks:
        item.get_size(memorize=True, from_chunks=True)
        item.path += '.borg_part_%d' % number
        item.part = number
        number += 1
        self.add_item(item, show_progress=False)
        self.write_checkpoint()
        return length, number

    def maybe_checkpoint(self, item, from_chunk, part_number, forced=False):
        sig_int_triggered = sig_int and sig_int.action_triggered()
        if forced or sig_int_triggered or \
            self.checkpoint_interval and time.monotonic() - self.last_checkpoint > self.checkpoint_interval:
            if sig_int_triggered:
                logger.info('checkpoint requested: starting checkpoint creation...')
            from_chunk, part_number = self.write_part_file(item, from_chunk, part_number)
            self.last_checkpoint = time.monotonic()
            if sig_int_triggered:
                sig_int.action_completed()
                logger.info('checkpoint requested: finished checkpoint creation!')
        return from_chunk, part_number

    def process_file_chunks(self, item, cache, stats, show_progress, chunk_iter, chunk_processor=None):
        if not chunk_processor:
            def chunk_processor(chunk):
                chunk_id, data = cached_hash(chunk, self.key.id_hash)
                chunk_entry = cache.add_chunk(chunk_id, data, stats, wait=False)
                self.cache.repository.async_response(wait=False)
                return chunk_entry

        item.chunks = []
        # if we rechunkify, we'll get a fundamentally different chunks list, thus we need
        # to get rid of .chunks_healthy, as it might not correspond to .chunks any more.
        if self.rechunkify and 'chunks_healthy' in item:
            del item.chunks_healthy
        from_chunk = 0
        part_number = 1
        for chunk in chunk_iter:
            item.chunks.append(chunk_processor(chunk))
            if show_progress:
                stats.show_progress(item=item, dt=0.2)
            from_chunk, part_number = self.maybe_checkpoint(item, from_chunk, part_number, forced=False)
        else:
            if part_number > 1:
                if item.chunks[from_chunk:]:
                    # if we already have created a part item inside this file, we want to put the final
                    # chunks (if any) into a part item also (so all parts can be concatenated to get
                    # the complete file):
                    from_chunk, part_number = self.maybe_checkpoint(item, from_chunk, part_number, forced=True)

                # if we created part files, we have referenced all chunks from the part files,
                # but we also will reference the same chunks also from the final, complete file:
                for chunk in item.chunks:
                    cache.chunk_incref(chunk.id, stats, size=chunk.size, part=True)
                stats.nfiles_parts += part_number - 1


class FilesystemObjectProcessors:
    # When ported to threading, then this doesn't need chunker, cache, key any more.
    # write_checkpoint should then be in the item buffer,
    # and process_file becomes a callback passed to __init__.

    def __init__(self, *, metadata_collector, cache, key,
                 add_item, process_file_chunks,
                 chunker_params, show_progress, sparse,
                 log_json, iec, file_status_printer=None):
        self.metadata_collector = metadata_collector
        self.cache = cache
        self.key = key
        self.add_item = add_item
        self.process_file_chunks = process_file_chunks
        self.show_progress = show_progress
        self.print_file_status = file_status_printer or (lambda *args: None)

        self.hard_links = {}
        self.stats = Statistics(output_json=log_json, iec=iec)  # threading: done by cache (including progress)
        self.cwd = os.getcwd()
        self.chunker = get_chunker(*chunker_params, seed=key.chunk_seed, sparse=sparse)

    @contextmanager
    def create_helper(self, path, st, status=None, hardlinkable=True):
        safe_path = make_path_safe(path)
        item = Item(path=safe_path)
        hardlink_master = False
        hardlinked = hardlinkable and st.st_nlink > 1
        if hardlinked:
            source = self.hard_links.get((st.st_ino, st.st_dev))
            if source is not None:
                item.source = source
                status = 'h'  # hardlink (to already seen inodes)
            else:
                hardlink_master = True
        yield item, status, hardlinked, hardlink_master
        # if we get here, "with"-block worked ok without error/exception, the item was processed ok...
        self.add_item(item, stats=self.stats)
        # ... and added to the archive, so we can remember it to refer to it later in the archive:
        if hardlink_master:
            self.hard_links[(st.st_ino, st.st_dev)] = safe_path

    def process_dir_with_fd(self, *, path, fd, st):
        with self.create_helper(path, st, 'd', hardlinkable=False) as (item, status, hardlinked, hardlink_master):
            item.update(self.metadata_collector.stat_attrs(st, path, fd=fd))
            return status

    def process_dir(self, *, path, parent_fd, name, st):
        with self.create_helper(path, st, 'd', hardlinkable=False) as (item, status, hardlinked, hardlink_master):
            with OsOpen(path=path, parent_fd=parent_fd, name=name, flags=flags_dir,
                        noatime=True, op='dir_open') as fd:
                # fd is None for directories on windows, in that case a race condition check is not possible.
                if fd is not None:
                    with backup_io('fstat'):
                        st = stat_update_check(st, os.fstat(fd))
                item.update(self.metadata_collector.stat_attrs(st, path, fd=fd))
                return status

    def process_fifo(self, *, path, parent_fd, name, st):
        with self.create_helper(path, st, 'f') as (item, status, hardlinked, hardlink_master):  # fifo
            with OsOpen(path=path, parent_fd=parent_fd, name=name, flags=flags_normal, noatime=True) as fd:
                with backup_io('fstat'):
                    st = stat_update_check(st, os.fstat(fd))
                item.update(self.metadata_collector.stat_attrs(st, path, fd=fd))
                return status

    def process_dev(self, *, path, parent_fd, name, st, dev_type):
        with self.create_helper(path, st, dev_type) as (item, status, hardlinked, hardlink_master):  # char/block device
            # looks like we can not work fd-based here without causing issues when trying to open/close the device
            with backup_io('stat'):
                st = stat_update_check(st, os_stat(path=path, parent_fd=parent_fd, name=name, follow_symlinks=False))
            item.rdev = st.st_rdev
            item.update(self.metadata_collector.stat_attrs(st, path))
            return status

    def process_symlink(self, *, path, parent_fd, name, st):
        # note: using hardlinkable=False because we can not support hardlinked symlinks,
        #       due to the dual-use of item.source, see issue #2343:
        # hardlinked symlinks will be archived [and extracted] as non-hardlinked symlinks.
        with self.create_helper(path, st, 's', hardlinkable=False) as (item, status, hardlinked, hardlink_master):
            fname = name if name is not None and parent_fd is not None else path
            with backup_io('readlink'):
                source = os.readlink(fname, dir_fd=parent_fd)
            item.source = source
            item.update(self.metadata_collector.stat_attrs(st, path))  # can't use FD here?
            return status

    def process_pipe(self, *, path, cache, fd, mode, user, group):
        status = 'i'  # stdin (or other pipe)
        self.print_file_status(status, path)
        status = None  # we already printed the status
        uid = user2uid(user)
        if uid is None:
            raise Error("no such user: %s" % user)
        gid = group2gid(group)
        if gid is None:
            raise Error("no such group: %s" % group)
        t = int(time.time()) * 1000000000
        item = Item(
            path=path,
            mode=mode & 0o107777 | 0o100000,  # forcing regular file mode
            uid=uid, user=user,
            gid=gid, group=group,
            mtime=t, atime=t, ctime=t,
        )
        self.process_file_chunks(item, cache, self.stats, self.show_progress, backup_io_iter(self.chunker.chunkify(fd)))
        item.get_size(memorize=True)
        self.stats.nfiles += 1
        self.add_item(item, stats=self.stats)
        return status

    def process_file(self, *, path, parent_fd, name, st, cache, flags=flags_normal):
        with self.create_helper(path, st, None) as (item, status, hardlinked, hardlink_master):  # no status yet
            with OsOpen(path=path, parent_fd=parent_fd, name=name, flags=flags, noatime=True) as fd:
                with backup_io('fstat'):
                    st = stat_update_check(st, os.fstat(fd))
                item.update(self.metadata_collector.stat_simple_attrs(st))
                is_special_file = is_special(st.st_mode)
                if is_special_file:
                    # we process a special file like a regular file. reflect that in mode,
                    # so it can be extracted / accessed in FUSE mount like a regular file.
                    # this needs to be done early, so that part files also get the patched mode.
                    item.mode = stat.S_IFREG | stat.S_IMODE(item.mode)
                if not hardlinked or hardlink_master:
                    if not is_special_file:
                        hashed_path = safe_encode(os.path.join(self.cwd, path))
                        path_hash = self.key.id_hash(hashed_path)
                        known, ids = cache.file_known_and_unchanged(hashed_path, path_hash, st)
                    else:
                        # in --read-special mode, we may be called for special files.
                        # there should be no information in the cache about special files processed in
                        # read-special mode, but we better play safe as this was wrong in the past:
                        hashed_path = path_hash = None
                        known, ids = False, None
                    chunks = None
                    if ids is not None:
                        # Make sure all ids are available
                        for id_ in ids:
                            if not cache.seen_chunk(id_):
                                status = 'M'  # cache said it is unmodified, but we lost a chunk: process file like modified
                                break
                        else:
                            chunks = [cache.chunk_incref(id_, self.stats) for id_ in ids]
                            status = 'U'  # regular file, unchanged
                    else:
                        status = 'M' if known else 'A'  # regular file, modified or added
                    self.print_file_status(status, path)
                    status = None  # we already printed the status
                    item.hardlink_master = hardlinked
                    # Only chunkify the file if needed
                    if chunks is not None:
                        item.chunks = chunks
                    else:
                        with backup_io('read'):
                            self.process_file_chunks(item, cache, self.stats, self.show_progress, backup_io_iter(self.chunker.chunkify(None, fd)))
                        if is_win32:
                            changed_while_backup = False  # TODO
                        else:
                            with backup_io('fstat2'):
                                st2 = os.fstat(fd)
                            # special files:
                            # - fifos change naturally, because they are fed from the other side. no problem.
                            # - blk/chr devices don't change ctime anyway.
                            changed_while_backup = not is_special_file and st.st_ctime_ns != st2.st_ctime_ns
                        if changed_while_backup:
                            status = 'C'  # regular file changed while we backed it up, might be inconsistent/corrupt!
                        if not is_special_file and not changed_while_backup:
                            # we must not memorize special files, because the contents of e.g. a
                            # block or char device will change without its mtime/size/inode changing.
                            # also, we must not memorize a potentially inconsistent/corrupt file that
                            # changed while we backed it up.
                            cache.memorize_file(hashed_path, path_hash, st, [c.id for c in item.chunks])
                    self.stats.nfiles += 1
                item.update(self.metadata_collector.stat_ext_attrs(st, path, fd=fd))
                item.get_size(memorize=True)
                return status


class TarfileObjectProcessors:
    def __init__(self, *, cache, key,
                 add_item, process_file_chunks,
                 chunker_params, show_progress,
                 log_json, iec, file_status_printer=None):
        self.cache = cache
        self.key = key
        self.add_item = add_item
        self.process_file_chunks = process_file_chunks
        self.show_progress = show_progress
        self.print_file_status = file_status_printer or (lambda *args: None)

        self.stats = Statistics(output_json=log_json, iec=iec)  # threading: done by cache (including progress)
        self.chunker = get_chunker(*chunker_params, seed=key.chunk_seed, sparse=False)

    @contextmanager
    def create_helper(self, tarinfo, status=None, type=None):
        item = Item(path=make_path_safe(tarinfo.name), mode=tarinfo.mode | type,
                    uid=tarinfo.uid, gid=tarinfo.gid, user=tarinfo.uname or None, group=tarinfo.gname or None,
                    mtime=safe_ns(int(tarinfo.mtime * 1000**3)))
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

    def process_link(self, *, tarinfo, status, type):
        with self.create_helper(tarinfo, status, type) as (item, status):
            item.source = tarinfo.linkname
            return status

    def process_file(self, *, tarinfo, status, type, tar):
        with self.create_helper(tarinfo, status, type) as (item, status):
            self.print_file_status(status, tarinfo.name)
            status = None  # we already printed the status
            fd = tar.extractfile(tarinfo)
            self.process_file_chunks(item, self.cache, self.stats, self.show_progress,
                                     backup_io_iter(self.chunker.chunkify(fd)))
            item.get_size(memorize=True)
            self.stats.nfiles += 1
            return status


def valid_msgpacked_dict(d, keys_serialized):
    """check if the data <d> looks like a msgpacked dict"""
    d_len = len(d)
    if d_len == 0:
        return False
    if d[0] & 0xf0 == 0x80:  # object is a fixmap (up to 15 elements)
        offs = 1
    elif d[0] == 0xde:  # object is a map16 (up to 2^16-1 elements)
        offs = 3
    else:
        # object is not a map (dict)
        # note: we must not have dicts with > 2^16-1 elements
        return False
    if d_len <= offs:
        return False
    # is the first dict key a bytestring?
    if d[offs] & 0xe0 == 0xa0:  # key is a small bytestring (up to 31 chars)
        pass
    elif d[offs] in (0xd9, 0xda, 0xdb):  # key is a str8, str16 or str32
        pass
    else:
        # key is not a bytestring
        return False
    # is the bytestring any of the expected key names?
    key_serialized = d[offs:]
    return any(key_serialized.startswith(pattern) for pattern in keys_serialized)


class RobustUnpacker:
    """A restartable/robust version of the streaming msgpack unpacker
    """
    def __init__(self, validator, item_keys):
        super().__init__()
        self.item_keys = [msgpack.packb(name.encode()) for name in item_keys]
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
            data = b''.join(self._buffered_data)
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

    def check(self, repository, repair=False, archive=None, first=0, last=0, sort_by='', glob=None,
              verify_data=False, save_space=False):
        """Perform a set of checks on 'repository'

        :param repair: enable repair mode, write updated or corrected data into repository
        :param archive: only check this archive
        :param first/last/sort_by: only check this number of first/last archives ordered by sort_by
        :param glob: only check archives matching this glob
        :param verify_data: integrity verification of data referenced by archives
        :param save_space: Repository.commit(save_space)
        """
        logger.info('Starting archive consistency check...')
        self.check_all = archive is None and not any((first, last, glob))
        self.repair = repair
        self.repository = repository
        self.init_chunks()
        if not self.chunks:
            logger.error('Repository contains no apparent data at all, cannot continue check/repair.')
            return False
        self.key = self.make_key(repository)
        if verify_data:
            self.verify_data()
        if Manifest.MANIFEST_ID not in self.chunks:
            logger.error("Repository manifest not found!")
            self.error_found = True
            self.manifest = self.rebuild_manifest()
        else:
            try:
                self.manifest, _ = Manifest.load(repository, (Manifest.Operation.CHECK,), key=self.key)
            except IntegrityErrorBase as exc:
                logger.error('Repository manifest is corrupted: %s', exc)
                self.error_found = True
                del self.chunks[Manifest.MANIFEST_ID]
                self.manifest = self.rebuild_manifest()
        self.rebuild_refcounts(archive=archive, first=first, last=last, sort_by=sort_by, glob=glob)
        self.orphan_chunks_check()
        self.finish(save_space=save_space)
        if self.error_found:
            logger.error('Archive consistency check complete, problems found.')
        else:
            logger.info('Archive consistency check complete, no problems found.')
        return self.repair or not self.error_found

    def init_chunks(self):
        """Fetch a list of all object keys from repository
        """
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
            init_entry = ChunkIndexEntry(refcount=0, size=0, csize=0)
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
            msg = 'make_key: repository has no chunks at all!'
        else:
            msg = 'make_key: failed to create the key (tried %d chunks)' % attempt
        raise IntegrityError(msg)

    def verify_data(self):
        logger.info('Starting cryptographic data integrity verification...')
        chunks_count_index = len(self.chunks)
        chunks_count_segments = 0
        errors = 0
        defect_chunks = []
        pi = ProgressIndicatorPercent(total=chunks_count_index, msg="Verifying data %6.2f%%", step=0.01,
                                      msgid='check.verify_data')
        marker = None
        while True:
            chunk_ids = self.repository.scan(limit=100, marker=marker)
            if not chunk_ids:
                break
            chunks_count_segments += len(chunk_ids)
            marker = chunk_ids[-1]
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
                    logger.error('chunk %s: %s', bin_to_hex(chunk_id), err)
                    if isinstance(err, IntegrityErrorBase):
                        defect_chunks.append(chunk_id)
                    # as the exception killed our generator, make a new one for remaining chunks:
                    if chunk_ids_revd:
                        chunk_ids = list(reversed(chunk_ids_revd))
                        chunk_data_iter = self.repository.get_many(chunk_ids)
                else:
                    _chunk_id = None if chunk_id == Manifest.MANIFEST_ID else chunk_id
                    try:
                        self.key.decrypt(_chunk_id, encrypted_data)
                    except IntegrityErrorBase as integrity_error:
                        self.error_found = True
                        errors += 1
                        logger.error('chunk %s, integrity error: %s', bin_to_hex(chunk_id), integrity_error)
                        defect_chunks.append(chunk_id)
        pi.finish()
        if chunks_count_index != chunks_count_segments:
            logger.error('Repo/Chunks index object count vs. segment files object count mismatch.')
            logger.error('Repo/Chunks index: %d objects != segment files: %d objects',
                         chunks_count_index, chunks_count_segments)
        if defect_chunks:
            if self.repair:
                # if we kill the defect chunk here, subsequent actions within this "borg check"
                # run will find missing chunks and replace them with all-zero replacement
                # chunks and flag the files as "repaired".
                # if another backup is done later and the missing chunks get backupped again,
                # a "borg check" afterwards can heal all files where this chunk was missing.
                logger.warning('Found defect chunks. They will be deleted now, so affected files can '
                               'get repaired now and maybe healed later.')
                for defect_chunk in defect_chunks:
                    # remote repo (ssh): retry might help for strange network / NIC / RAM errors
                    # as the chunk will be retransmitted from remote server.
                    # local repo (fs): as chunks.iteritems loop usually pumps a lot of data through,
                    # a defect chunk is likely not in the fs cache any more and really gets re-read
                    # from the underlying media.
                    try:
                        encrypted_data = self.repository.get(defect_chunk)
                        _chunk_id = None if defect_chunk == Manifest.MANIFEST_ID else defect_chunk
                        self.key.decrypt(_chunk_id, encrypted_data)
                    except IntegrityErrorBase:
                        # failed twice -> get rid of this chunk
                        del self.chunks[defect_chunk]
                        self.repository.delete(defect_chunk)
                        logger.debug('chunk %s deleted.', bin_to_hex(defect_chunk))
                    else:
                        logger.warning('chunk %s not deleted, did not consistently fail.', bin_to_hex(defect_chunk))
            else:
                logger.warning('Found defect chunks. With --repair, they would get deleted, so affected '
                               'files could get repaired then and maybe healed later.')
                for defect_chunk in defect_chunks:
                    logger.debug('chunk %s is defect.', bin_to_hex(defect_chunk))
        log = logger.error if errors else logger.info
        log('Finished cryptographic data integrity verification, verified %d chunks with %d integrity errors.',
            chunks_count_segments, errors)

    def rebuild_manifest(self):
        """Rebuild the manifest object if it is missing

        Iterates through all objects in the repository looking for archive metadata blocks.
        """
        required_archive_keys = frozenset(key.encode() for key in REQUIRED_ARCHIVE_KEYS)

        def valid_archive(obj):
            if not isinstance(obj, dict):
                return False
            keys = set(obj)
            return required_archive_keys.issubset(keys)

        logger.info('Rebuilding missing manifest, this might take some time...')
        # as we have lost the manifest, we do not know any more what valid item keys we had.
        # collecting any key we encounter in a damaged repo seems unwise, thus we just use
        # the hardcoded list from the source code. thus, it is not recommended to rebuild a
        # lost manifest on a older borg version than the most recent one that was ever used
        # within this repository (assuming that newer borg versions support more item keys).
        manifest = Manifest(self.key, self.repository)
        archive_keys_serialized = [msgpack.packb(name.encode()) for name in ARCHIVE_KEYS]
        pi = ProgressIndicatorPercent(total=len(self.chunks), msg="Rebuilding manifest %6.2f%%", step=0.01,
                                      msgid='check.rebuild_manifest')
        for chunk_id, _ in self.chunks.iteritems():
            pi.show()
            cdata = self.repository.get(chunk_id)
            try:
                data = self.key.decrypt(chunk_id, cdata)
            except IntegrityErrorBase as exc:
                logger.error('Skipping corrupted chunk: %s', exc)
                self.error_found = True
                continue
            if not valid_msgpacked_dict(data, archive_keys_serialized):
                continue
            if b'cmdline' not in data or b'\xa7version\x01' not in data:
                continue
            try:
                archive = msgpack.unpackb(data)
            # Ignore exceptions that might be raised when feeding msgpack with invalid data
            except msgpack.UnpackException:
                continue
            if valid_archive(archive):
                archive = ArchiveItem(internal_dict=archive)
                name = archive.name
                logger.info('Found archive %s', name)
                if name in manifest.archives:
                    i = 1
                    while True:
                        new_name = '%s.%d' % (name, i)
                        if new_name not in manifest.archives:
                            break
                        i += 1
                    logger.warning('Duplicate archive name %s, storing as %s', name, new_name)
                    name = new_name
                manifest.archives[name] = (chunk_id, archive.time)
        pi.finish()
        logger.info('Manifest rebuild complete.')
        return manifest

    def rebuild_refcounts(self, archive=None, first=0, last=0, sort_by='', glob=None):
        """Rebuild object reference counts by walking the metadata

        Missing and/or incorrect data is repaired when detected
        """
        # Exclude the manifest from chunks (manifest entry might be already deleted from self.chunks)
        self.chunks.pop(Manifest.MANIFEST_ID, None)

        def mark_as_possibly_superseded(id_):
            if self.chunks.get(id_, ChunkIndexEntry(0, 0, 0)).refcount == 0:
                self.possibly_superseded.add(id_)

        def add_callback(chunk):
            id_ = self.key.id_hash(chunk)
            cdata = self.key.encrypt(chunk)
            add_reference(id_, len(chunk), len(cdata), cdata)
            return id_

        def add_reference(id_, size, csize, cdata=None):
            try:
                self.chunks.incref(id_)
            except KeyError:
                assert cdata is not None
                self.chunks[id_] = ChunkIndexEntry(refcount=1, size=size, csize=csize)
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
                cdata = self.key.encrypt(data)
                csize = len(cdata)
                return chunk_id, size, csize, cdata

            offset = 0
            chunk_list = []
            chunks_replaced = False
            has_chunks_healthy = 'chunks_healthy' in item
            chunks_current = item.chunks
            chunks_healthy = item.chunks_healthy if has_chunks_healthy else chunks_current
            if has_chunks_healthy and len(chunks_current) != len(chunks_healthy):
                # should never happen, but there was issue #3218.
                logger.warning(f'{archive_name}: {item.path}: Invalid chunks_healthy metadata removed!')
                del item.chunks_healthy
                has_chunks_healthy = False
                chunks_healthy = chunks_current
            for chunk_current, chunk_healthy in zip(chunks_current, chunks_healthy):
                chunk_id, size, csize = chunk_healthy
                if chunk_id not in self.chunks:
                    # a chunk of the healthy list is missing
                    if chunk_current == chunk_healthy:
                        logger.error('{}: {}: New missing file chunk detected (Byte {}-{}, Chunk {}). '
                                     'Replacing with all-zero chunk.'.format(
                                     archive_name, item.path, offset, offset + size, bin_to_hex(chunk_id)))
                        self.error_found = chunks_replaced = True
                        chunk_id, size, csize, cdata = replacement_chunk(size)
                        add_reference(chunk_id, size, csize, cdata)
                    else:
                        logger.info('{}: {}: Previously missing file chunk is still missing (Byte {}-{}, Chunk {}). '
                                    'It has an all-zero replacement chunk already.'.format(
                                    archive_name, item.path, offset, offset + size, bin_to_hex(chunk_id)))
                        chunk_id, size, csize = chunk_current
                        if chunk_id in self.chunks:
                            add_reference(chunk_id, size, csize)
                        else:
                            logger.warning('{}: {}: Missing all-zero replacement chunk detected (Byte {}-{}, Chunk {}). '
                                           'Generating new replacement chunk.'.format(
                                           archive_name, item.path, offset, offset + size, bin_to_hex(chunk_id)))
                            self.error_found = chunks_replaced = True
                            chunk_id, size, csize, cdata = replacement_chunk(size)
                            add_reference(chunk_id, size, csize, cdata)
                else:
                    if chunk_current == chunk_healthy:
                        # normal case, all fine.
                        add_reference(chunk_id, size, csize)
                    else:
                        logger.info('{}: {}: Healed previously missing file chunk! (Byte {}-{}, Chunk {}).'.format(
                            archive_name, item.path, offset, offset + size, bin_to_hex(chunk_id)))
                        add_reference(chunk_id, size, csize)
                        mark_as_possibly_superseded(chunk_current[0])  # maybe orphaned the all-zero replacement chunk
                chunk_list.append([chunk_id, size, csize])  # list-typed element as chunks_healthy is list-of-lists
                offset += size
            if chunks_replaced and not has_chunks_healthy:
                # if this is first repair, remember the correct chunk IDs, so we can maybe heal the file later
                item.chunks_healthy = item.chunks
            if has_chunks_healthy and chunk_list == chunks_healthy:
                logger.info(f'{archive_name}: {item.path}: Completely healed previously damaged file!')
                del item.chunks_healthy
            item.chunks = chunk_list
            if 'size' in item:
                item_size = item.size
                item_chunks_size = item.get_size(compressed=False, from_chunks=True)
                if item_size != item_chunks_size:
                    # just warn, but keep the inconsistency, so that borg extract can warn about it.
                    logger.warning('{}: {}: size inconsistency detected: size {}, chunks size {}'.format(
                                   archive_name, item.path, item_size, item_chunks_size))

        def robust_iterator(archive):
            """Iterates through all archive items

            Missing item chunks will be skipped and the msgpack stream will be restarted
            """
            item_keys = frozenset(key.encode() for key in self.manifest.item_keys)
            required_item_keys = frozenset(key.encode() for key in REQUIRED_ITEM_KEYS)
            unpacker = RobustUnpacker(lambda item: isinstance(item, StableDict) and b'path' in item,
                                      self.manifest.item_keys)
            _state = 0

            def missing_chunk_detector(chunk_id):
                nonlocal _state
                if _state % 2 != int(chunk_id not in self.chunks):
                    _state += 1
                return _state

            def report(msg, chunk_id, chunk_no):
                cid = bin_to_hex(chunk_id)
                msg += ' [chunk: %06d_%s]' % (chunk_no, cid)  # see "debug dump-archive-items"
                self.error_found = True
                logger.error(msg)

            def list_keys_safe(keys):
                return ', '.join(k.decode(errors='replace') if isinstance(k, bytes) else str(k) for k in keys)

            def valid_item(obj):
                if not isinstance(obj, StableDict):
                    return False, 'not a dictionary'
                # A bug in Attic up to and including release 0.13 added a (meaningless) b'acl' key to every item.
                # We ignore it here, should it exist. See test_attic013_acl_bug for details.
                obj.pop(b'acl', None)
                keys = set(obj)
                if not required_item_keys.issubset(keys):
                    return False, 'missing required keys: ' + list_keys_safe(required_item_keys - keys)
                if not keys.issubset(item_keys):
                    return False, 'invalid keys: ' + list_keys_safe(keys - item_keys)
                return True, ''

            i = 0
            for state, items in groupby(archive.items, missing_chunk_detector):
                items = list(items)
                if state % 2:
                    for chunk_id in items:
                        report('item metadata chunk missing', chunk_id, i)
                        i += 1
                    continue
                if state > 0:
                    unpacker.resync()
                for chunk_id, cdata in zip(items, repository.get_many(items)):
                    try:
                        data = self.key.decrypt(chunk_id, cdata)
                        unpacker.feed(data)
                        for item in unpacker:
                            valid, reason = valid_item(item)
                            if valid:
                                yield Item(internal_dict=item)
                            else:
                                report('Did not get expected metadata dict when unpacking item metadata (%s)' % reason, chunk_id, i)
                    except IntegrityError as integrity_error:
                        # key.decrypt() detected integrity issues.
                        # maybe the repo gave us a valid cdata, but not for the chunk_id we wanted.
                        # or the authentication of cdata failed, meaning the encrypted data was corrupted.
                        report(str(integrity_error), chunk_id, i)
                    except msgpack.UnpackException:
                        report('Unpacker crashed while unpacking item metadata, trying to resync...', chunk_id, i)
                        unpacker.resync()
                    except Exception:
                        report('Exception while decrypting or unpacking item metadata', chunk_id, i)
                        raise
                    i += 1

        if archive is None:
            sort_by = sort_by.split(',')
            if any((first, last, glob)):
                archive_infos = self.manifest.archives.list(sort_by=sort_by, glob=glob, first=first, last=last)
                if glob and not archive_infos:
                    logger.warning('--glob-archives %s does not match any archives', glob)
                if first and len(archive_infos) < first:
                    logger.warning('--first %d archives: only found %d archives', first, len(archive_infos))
                if last and len(archive_infos) < last:
                    logger.warning('--last %d archives: only found %d archives', last, len(archive_infos))
            else:
                archive_infos = self.manifest.archives.list(sort_by=sort_by)
        else:
            # we only want one specific archive
            try:
                archive_infos = [self.manifest.archives[archive]]
            except KeyError:
                logger.error("Archive '%s' not found.", archive)
                self.error_found = True
                return
        num_archives = len(archive_infos)

        pi = ProgressIndicatorPercent(total=num_archives, msg='Checking archives %3.1f%%', step=0.1,
                                      msgid='check.rebuild_refcounts')
        with cache_if_remote(self.repository) as repository:
            for i, info in enumerate(archive_infos):
                pi.show(i)
                logger.info(f'Analyzing archive {info.name} ({i + 1}/{num_archives})')
                archive_id = info.id
                if archive_id not in self.chunks:
                    logger.error('Archive metadata block %s is missing!', bin_to_hex(archive_id))
                    self.error_found = True
                    del self.manifest.archives[info.name]
                    continue
                mark_as_possibly_superseded(archive_id)
                cdata = self.repository.get(archive_id)
                try:
                    data = self.key.decrypt(archive_id, cdata)
                except IntegrityError as integrity_error:
                    logger.error('Archive metadata block %s is corrupted: %s', bin_to_hex(archive_id), integrity_error)
                    self.error_found = True
                    del self.manifest.archives[info.name]
                    continue
                archive = ArchiveItem(internal_dict=msgpack.unpackb(data))
                if archive.version != 1:
                    raise Exception('Unknown archive metadata version')
                archive.cmdline = [safe_decode(arg) for arg in archive.cmdline]
                items_buffer = ChunkBuffer(self.key)
                items_buffer.write_chunk = add_callback
                for item in robust_iterator(archive):
                    if 'chunks' in item:
                        verify_file_chunks(info.name, item)
                    items_buffer.add(item)
                items_buffer.flush(flush=True)
                for previous_item_id in archive.items:
                    mark_as_possibly_superseded(previous_item_id)
                archive.items = items_buffer.chunks
                data = msgpack.packb(archive.as_dict())
                new_archive_id = self.key.id_hash(data)
                cdata = self.key.encrypt(data)
                add_reference(new_archive_id, len(data), len(cdata), cdata)
                self.manifest.archives[info.name] = (new_archive_id, info.ts)
            pi.finish()

    def orphan_chunks_check(self):
        if self.check_all:
            unused = {id_ for id_, entry in self.chunks.iteritems() if entry.refcount == 0}
            orphaned = unused - self.possibly_superseded
            if orphaned:
                logger.error(f'{len(orphaned)} orphaned objects found!')
                self.error_found = True
            if self.repair and unused:
                logger.info('Deleting %d orphaned and %d superseded objects...' % (
                    len(orphaned), len(self.possibly_superseded)))
                for id_ in unused:
                    self.repository.delete(id_)
                logger.info('Finished deleting orphaned/superseded objects.')
        else:
            logger.info('Orphaned objects check skipped (needs all archives checked).')

    def finish(self, save_space=False):
        if self.repair:
            logger.info('Writing Manifest.')
            self.manifest.write()
            logger.info('Committing repo.')
            self.repository.commit(compact=False, save_space=save_space)


class ArchiveRecreater:
    class Interrupted(Exception):
        def __init__(self, metadata=None):
            self.metadata = metadata or {}

    @staticmethod
    def is_temporary_archive(archive_name):
        return archive_name.endswith('.recreate')

    def __init__(self, repository, manifest, key, cache, matcher,
                 exclude_caches=False, exclude_if_present=None, keep_exclude_tags=False,
                 chunker_params=None, compression=None, recompress=False, always_recompress=False,
                 dry_run=False, stats=False, progress=False, file_status_printer=None,
                 timestamp=None, checkpoint_interval=1800):
        self.repository = repository
        self.key = key
        self.manifest = manifest
        self.cache = cache

        self.matcher = matcher
        self.exclude_caches = exclude_caches
        self.exclude_if_present = exclude_if_present or []
        self.keep_exclude_tags = keep_exclude_tags

        self.rechunkify = chunker_params is not None
        if self.rechunkify:
            logger.debug('Rechunking archives to %s', chunker_params)
        self.chunker_params = chunker_params or CHUNKER_PARAMS
        self.recompress = recompress
        self.always_recompress = always_recompress
        self.compression = compression or CompressionSpec('none')
        self.seen_chunks = set()

        self.timestamp = timestamp
        self.dry_run = dry_run
        self.stats = stats
        self.progress = progress
        self.print_file_status = file_status_printer or (lambda *args: None)
        self.checkpoint_interval = None if dry_run else checkpoint_interval

    def recreate(self, archive_name, comment=None, target_name=None):
        assert not self.is_temporary_archive(archive_name)
        archive = self.open_archive(archive_name)
        target = self.create_target(archive, target_name)
        if self.exclude_if_present or self.exclude_caches:
            self.matcher_add_tagged_dirs(archive)
        if self.matcher.empty() and not self.recompress and not target.recreate_rechunkify and comment is None:
            return False
        self.process_items(archive, target)
        replace_original = target_name is None
        self.save(archive, target, comment, replace_original=replace_original)
        return True

    def process_items(self, archive, target):
        matcher = self.matcher
        target_is_subset = not matcher.empty()
        hardlink_masters = {} if target_is_subset else None

        def item_is_hardlink_master(item):
            return (target_is_subset and
                    hardlinkable(item.mode) and
                    item.get('hardlink_master', True) and
                    'source' not in item)

        for item in archive.iter_items():
            if not matcher.match(item.path):
                self.print_file_status('x', item.path)
                if item_is_hardlink_master(item):
                    hardlink_masters[item.path] = (item.get('chunks'), item.get('chunks_healthy'), None)
                continue
            if target_is_subset and hardlinkable(item.mode) and item.get('source') in hardlink_masters:
                # master of this hard link is outside the target subset
                chunks, chunks_healthy, new_source = hardlink_masters[item.source]
                if new_source is None:
                    # First item to use this master, move the chunks
                    item.chunks = chunks
                    if chunks_healthy is not None:
                        item.chunks_healthy = chunks_healthy
                    hardlink_masters[item.source] = (None, None, item.path)
                    del item.source
                else:
                    # Master was already moved, only update this item's source
                    item.source = new_source
            if self.dry_run:
                self.print_file_status('-', item.path)
            else:
                self.process_item(archive, target, item)
        if self.progress:
            target.stats.show_progress(final=True)

    def process_item(self, archive, target, item):
        status = file_status(item.mode)
        if 'chunks' in item:
            self.print_file_status(status, item.path)
            status = None
            self.process_chunks(archive, target, item)
            target.stats.nfiles += 1
        target.add_item(item, stats=target.stats)
        self.print_file_status(status, item.path)

    def process_chunks(self, archive, target, item):
        if not self.recompress and not target.recreate_rechunkify:
            for chunk_id, size, csize in item.chunks:
                self.cache.chunk_incref(chunk_id, target.stats)
            return item.chunks
        chunk_iterator = self.iter_chunks(archive, target, list(item.chunks))
        chunk_processor = partial(self.chunk_processor, target)
        target.process_file_chunks(item, self.cache, target.stats, self.progress, chunk_iterator, chunk_processor)

    def chunk_processor(self, target, chunk):
        chunk_id, data = cached_hash(chunk, self.key.id_hash)
        if chunk_id in self.seen_chunks:
            return self.cache.chunk_incref(chunk_id, target.stats)
        overwrite = self.recompress
        if self.recompress and not self.always_recompress and chunk_id in self.cache.chunks:
            # Check if this chunk is already compressed the way we want it
            old_chunk = self.key.decrypt(None, self.repository.get(chunk_id), decompress=False)
            if Compressor.detect(old_chunk).name == self.key.compressor.decide(data).name:
                # Stored chunk has the same compression we wanted
                overwrite = False
        chunk_entry = self.cache.add_chunk(chunk_id, data, target.stats, overwrite=overwrite, wait=False)
        self.cache.repository.async_response(wait=False)
        self.seen_chunks.add(chunk_entry.id)
        return chunk_entry

    def iter_chunks(self, archive, target, chunks):
        chunk_iterator = archive.pipeline.fetch_many([chunk_id for chunk_id, _, _ in chunks])
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
            comment = archive.metadata.get('comment', '')

        # Keep for the statistics if necessary
        if self.stats:
            _start = target.start

        if self.timestamp is None:
            additional_metadata = {
                'time': archive.metadata.time,
                'time_end': archive.metadata.get('time_end') or archive.metadata.time,
                'cmdline': archive.metadata.cmdline,
                # but also remember recreate metadata:
                'recreate_cmdline': sys.argv,
            }
        else:
            additional_metadata = {
                'cmdline': archive.metadata.cmdline,
                # but also remember recreate metadata:
                'recreate_cmdline': sys.argv,
            }

        target.save(comment=comment, timestamp=self.timestamp,
                    stats=target.stats, additional_metadata=additional_metadata)
        if replace_original:
            archive.delete(Statistics(), progress=self.progress)
            target.rename(archive.name)
        if self.stats:
            target.start = _start
            target.end = datetime.utcnow()
            log_multi(DASHES,
                      str(target),
                      DASHES,
                      str(target.stats),
                      str(self.cache),
                      DASHES)

    def matcher_add_tagged_dirs(self, archive):
        """Add excludes to the matcher created by exclude_cache and exclude_if_present."""
        def exclude(dir, tag_item):
            if self.keep_exclude_tags:
                tag_files.append(PathPrefixPattern(tag_item.path, recurse_dir=False))
                tagged_dirs.append(FnmatchPattern(dir + '/', recurse_dir=False))
            else:
                tagged_dirs.append(PathPrefixPattern(dir, recurse_dir=False))

        matcher = self.matcher
        tag_files = []
        tagged_dirs = []

        # to support reading hard-linked CACHEDIR.TAGs (aka CACHE_TAG_NAME), similar to hardlink_masters:
        cachedir_masters = {}

        if self.exclude_caches:
            # sadly, due to how CACHEDIR.TAG works (filename AND file [header] contents) and
            # how borg deals with hardlinks (slave hardlinks referring back to master hardlinks),
            # we need to pass over the archive collecting hardlink master paths.
            # as seen in issue #4911, the master paths can have an arbitrary filenames,
            # not just CACHEDIR.TAG.
            for item in archive.iter_items(filter=lambda item: os.path.basename(item.path) == CACHE_TAG_NAME):
                if stat.S_ISREG(item.mode) and 'chunks' not in item and 'source' in item:
                    # this is a hardlink slave, referring back to its hardlink master (via item.source)
                    cachedir_masters[item.source] = None  # we know the key (path), but not the value (item) yet

        for item in archive.iter_items(
                filter=lambda item: os.path.basename(item.path) == CACHE_TAG_NAME or matcher.match(item.path)):
            if self.exclude_caches and item.path in cachedir_masters:
                cachedir_masters[item.path] = item
            dir, tag_file = os.path.split(item.path)
            if tag_file in self.exclude_if_present:
                exclude(dir, item)
            elif self.exclude_caches and tag_file == CACHE_TAG_NAME and stat.S_ISREG(item.mode):
                content_item = item if 'chunks' in item else cachedir_masters[item.source]
                file = open_item(archive, content_item)
                if file.read(len(CACHE_TAG_CONTENTS)) == CACHE_TAG_CONTENTS:
                    exclude(dir, item)
        matcher.add(tag_files, IECommand.Include)
        matcher.add(tagged_dirs, IECommand.ExcludeNoRecurse)

    def create_target(self, archive, target_name=None):
        """Create target archive."""
        target_name = target_name or archive.name + '.recreate'
        target = self.create_target_archive(target_name)
        # If the archives use the same chunker params, then don't rechunkify
        source_chunker_params = tuple(archive.metadata.get('chunker_params', []))
        if len(source_chunker_params) == 4 and isinstance(source_chunker_params[0], int):
            # this is a borg < 1.2 chunker_params tuple, no chunker algo specified, but we only had buzhash:
            source_chunker_params = (CH_BUZHASH, ) + source_chunker_params
        target.recreate_rechunkify = self.rechunkify and source_chunker_params != target.chunker_params
        if target.recreate_rechunkify:
            logger.debug('Rechunking archive from %s to %s', source_chunker_params or '(unknown)', target.chunker_params)
        target.process_file_chunks = ChunksProcessor(
            cache=self.cache, key=self.key,
            add_item=target.add_item, write_checkpoint=target.write_checkpoint,
            checkpoint_interval=self.checkpoint_interval, rechunkify=target.recreate_rechunkify).process_file_chunks
        target.chunker = get_chunker(*target.chunker_params, seed=self.key.chunk_seed)
        return target

    def create_target_archive(self, name):
        target = Archive(self.repository, self.key, self.manifest, name, create=True,
                          progress=self.progress, chunker_params=self.chunker_params, cache=self.cache,
                          checkpoint_interval=self.checkpoint_interval)
        return target

    def open_archive(self, name, **kwargs):
        return Archive(self.repository, self.key, self.manifest, name, cache=self.cache, **kwargs)

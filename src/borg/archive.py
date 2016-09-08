import errno
import os
import socket
import stat
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from getpass import getuser
from io import BytesIO
from itertools import groupby
from shutil import get_terminal_size

import msgpack

from .logger import create_logger
logger = create_logger()

from . import xattr
from .cache import ChunkListEntry
from .chunker import Chunker
from .constants import *  # NOQA
from .hashindex import ChunkIndex, ChunkIndexEntry
from .helpers import Manifest
from .helpers import Chunk, ChunkIteratorFileWrapper, open_item
from .helpers import Error, IntegrityError
from .helpers import uid2user, user2uid, gid2group, group2gid
from .helpers import parse_timestamp, to_localtime
from .helpers import format_time, format_timedelta, format_file_size, file_status
from .helpers import safe_encode, safe_decode, make_path_safe, remove_surrogates
from .helpers import decode_dict, StableDict
from .helpers import int_to_bigint, bigint_to_int, bin_to_hex
from .helpers import ProgressIndicatorPercent, log_multi
from .helpers import PathPrefixPattern, FnmatchPattern
from .helpers import consume
from .helpers import CompressionDecider1, CompressionDecider2, CompressionSpec
from .item import Item
from .key import key_factory
from .platform import acl_get, acl_set, set_flags, get_flags, swidth
from .remote import cache_if_remote
from .repository import Repository

has_lchmod = hasattr(os, 'lchmod')

flags_normal = os.O_RDONLY | getattr(os, 'O_BINARY', 0)
flags_noatime = flags_normal | getattr(os, 'O_NOATIME', 0)


class Statistics:

    def __init__(self):
        self.osize = self.csize = self.usize = self.nfiles = 0
        self.last_progress = 0  # timestamp when last progress was shown

    def update(self, size, csize, unique):
        self.osize += size
        self.csize += csize
        if unique:
            self.usize += csize

    summary = """\
                       Original size      Compressed size    Deduplicated size
{label:15} {stats.osize_fmt:>20s} {stats.csize_fmt:>20s} {stats.usize_fmt:>20s}"""

    def __str__(self):
        return self.summary.format(stats=self, label='This archive:')

    def __repr__(self):
        return "<{cls} object at {hash:#x} ({self.osize}, {self.csize}, {self.usize})>".format(
            cls=type(self).__name__, hash=id(self), self=self)

    @property
    def osize_fmt(self):
        return format_file_size(self.osize)

    @property
    def usize_fmt(self):
        return format_file_size(self.usize)

    @property
    def csize_fmt(self):
        return format_file_size(self.csize)

    def show_progress(self, item=None, final=False, stream=None, dt=None):
        now = time.time()
        if dt is None or now - self.last_progress > dt:
            self.last_progress = now
            columns, lines = get_terminal_size()
            if not final:
                msg = '{0.osize_fmt} O {0.csize_fmt} C {0.usize_fmt} D {0.nfiles} N '.format(self)
                path = remove_surrogates(item.path) if item else ''
                space = columns - swidth(msg)
                if space < swidth('...') + swidth(path):
                    path = '%s...%s' % (path[:(space // 2) - swidth('...')], path[-space // 2:])
                msg += "{0:<{space}}".format(path, space=space)
            else:
                msg = ' ' * columns
            print(msg, file=stream or sys.stderr, end="\r", flush=True)


def is_special(mode):
    # file types that get special treatment in --read-special mode
    return stat.S_ISBLK(mode) or stat.S_ISCHR(mode) or stat.S_ISFIFO(mode)


class BackupOSError(Exception):
    """
    Wrapper for OSError raised while accessing backup files.

    Borg does different kinds of IO, and IO failures have different consequences.
    This wrapper represents failures of input file or extraction IO.
    These are non-critical and are only reported (exit code = 1, warning).

    Any unwrapped IO error is critical and aborts execution (for example repository IO failure).
    """
    def __init__(self, os_error):
        self.os_error = os_error
        self.errno = os_error.errno
        self.strerror = os_error.strerror
        self.filename = os_error.filename

    def __str__(self):
        return str(self.os_error)


@contextmanager
def backup_io():
    """Context manager changing OSError to BackupOSError."""
    try:
        yield
    except OSError as os_error:
        raise BackupOSError(os_error) from os_error


def backup_io_iter(iterator):
    while True:
        try:
            with backup_io():
                item = next(iterator)
        except StopIteration:
            return
        yield item


class DownloadPipeline:

    def __init__(self, repository, key):
        self.repository = repository
        self.key = key

    def unpack_many(self, ids, filter=None, preload=False):
        unpacker = msgpack.Unpacker(use_list=False)
        for _, data in self.fetch_many(ids):
            unpacker.feed(data)
            items = [Item(internal_dict=item) for item in unpacker]
            if filter:
                items = [item for item in items if filter(item)]
            for item in items:
                if 'chunks' in item:
                    item.chunks = [ChunkListEntry(*e) for e in item.chunks]
            if preload:
                for item in items:
                    if 'chunks' in item:
                        self.repository.preload([c.id for c in item.chunks])
            for item in items:
                yield item

    def fetch_many(self, ids, is_preloaded=False):
        for id_, data in zip(ids, self.repository.get_many(ids, is_preloaded=is_preloaded)):
            yield self.key.decrypt(id_, data)


class ChunkBuffer:
    BUFFER_SIZE = 1 * 1024 * 1024

    def __init__(self, key, chunker_params=ITEMS_CHUNKER_PARAMS):
        self.buffer = BytesIO()
        self.packer = msgpack.Packer(unicode_errors='surrogateescape')
        self.chunks = []
        self.key = key
        self.chunker = Chunker(self.key.chunk_seed, *chunker_params)

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
        chunks = list(Chunk(bytes(s)) for s in self.chunker.chunkify(self.buffer))
        self.buffer.seek(0)
        self.buffer.truncate(0)
        # Leave the last partial chunk in the buffer unless flush is True
        end = None if flush or len(chunks) == 1 else -1
        for chunk in chunks[:end]:
            self.chunks.append(self.write_chunk(chunk))
        if end == -1:
            self.buffer.write(chunks[-1].data)

    def is_full(self):
        return self.buffer.tell() > self.BUFFER_SIZE


class CacheChunkBuffer(ChunkBuffer):

    def __init__(self, cache, key, stats, chunker_params=ITEMS_CHUNKER_PARAMS):
        super().__init__(key, chunker_params)
        self.cache = cache
        self.stats = stats

    def write_chunk(self, chunk):
        id_, _, _ = self.cache.add_chunk(self.key.id_hash(chunk.data), chunk, self.stats)
        return id_


class Archive:

    class DoesNotExist(Error):
        """Archive {} does not exist"""

    class AlreadyExists(Error):
        """Archive {} already exists"""

    class IncompatibleFilesystemEncodingError(Error):
        """Failed to encode filename "{}" into file system encoding "{}". Consider configuring the LANG environment variable."""

    def __init__(self, repository, key, manifest, name, cache=None, create=False,
                 checkpoint_interval=300, numeric_owner=False, progress=False,
                 chunker_params=CHUNKER_PARAMS, start=None, end=None, compression=None, compression_files=None):
        self.cwd = os.getcwd()
        self.key = key
        self.repository = repository
        self.cache = cache
        self.manifest = manifest
        self.hard_links = {}
        self.stats = Statistics()
        self.show_progress = progress
        self.name = name
        self.checkpoint_interval = checkpoint_interval
        self.numeric_owner = numeric_owner
        if start is None:
            start = datetime.utcnow()
        self.chunker_params = chunker_params
        self.start = start
        if end is None:
            end = datetime.utcnow()
        self.end = end
        self.pipeline = DownloadPipeline(self.repository, self.key)
        if create:
            self.items_buffer = CacheChunkBuffer(self.cache, self.key, self.stats)
            self.chunker = Chunker(self.key.chunk_seed, *chunker_params)
            self.compression_decider1 = CompressionDecider1(compression or CompressionSpec('none'),
                                                            compression_files or [])
            key.compression_decider2 = CompressionDecider2(compression or CompressionSpec('none'))
            if name in manifest.archives:
                raise self.AlreadyExists(name)
            self.last_checkpoint = time.time()
            i = 0
            while True:
                self.checkpoint_name = '%s.checkpoint%s' % (name, i and ('.%d' % i) or '')
                if self.checkpoint_name not in manifest.archives:
                    break
                i += 1
        else:
            if name not in self.manifest.archives:
                raise self.DoesNotExist(name)
            info = self.manifest.archives[name]
            self.load(info[b'id'])
            self.zeros = b'\0' * (1 << chunker_params[1])

    def _load_meta(self, id):
        _, data = self.key.decrypt(id, self.repository.get(id))
        metadata = msgpack.unpackb(data)
        if metadata[b'version'] != 1:
            raise Exception('Unknown archive metadata version')
        return metadata

    def load(self, id):
        self.id = id
        self.metadata = self._load_meta(self.id)
        decode_dict(self.metadata, ARCHIVE_TEXT_KEYS)
        self.metadata[b'cmdline'] = [safe_decode(arg) for arg in self.metadata[b'cmdline']]
        self.name = self.metadata[b'name']

    @property
    def ts(self):
        """Timestamp of archive creation (start) in UTC"""
        ts = self.metadata[b'time']
        return parse_timestamp(ts)

    @property
    def ts_end(self):
        """Timestamp of archive creation (end) in UTC"""
        # fall back to time if there is no time_end present in metadata
        ts = self.metadata.get(b'time_end') or self.metadata[b'time']
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

    def __str__(self):
        return '''\
Archive name: {0.name}
Archive fingerprint: {0.fpr}
Time (start): {start}
Time (end):   {end}
Duration: {0.duration}
Number of files: {0.stats.nfiles}'''.format(
            self,
            start=format_time(to_localtime(self.start.replace(tzinfo=timezone.utc))),
            end=format_time(to_localtime(self.end.replace(tzinfo=timezone.utc))))

    def __repr__(self):
        return 'Archive(%r)' % self.name

    def iter_items(self, filter=None, preload=False):
        for item in self.pipeline.unpack_many(self.metadata[b'items'], filter=filter, preload=preload):
            yield item

    def add_item(self, item):
        if self.show_progress:
            self.stats.show_progress(item=item, dt=0.2)
        self.items_buffer.add(item)
        if self.checkpoint_interval and time.time() - self.last_checkpoint > self.checkpoint_interval:
            self.write_checkpoint()
            self.last_checkpoint = time.time()

    def write_checkpoint(self):
        self.save(self.checkpoint_name)
        del self.manifest.archives[self.checkpoint_name]
        self.cache.chunk_decref(self.id, self.stats)

    def save(self, name=None, comment=None, timestamp=None, additional_metadata=None):
        name = name or self.name
        if name in self.manifest.archives:
            raise self.AlreadyExists(name)
        self.items_buffer.flush(flush=True)
        if timestamp is None:
            self.end = datetime.utcnow()
            start = self.start
            end = self.end
        else:
            self.end = timestamp
            start = timestamp
            end = timestamp  # we only have 1 value
        metadata = {
            'version': 1,
            'name': name,
            'comment': comment,
            'items': self.items_buffer.chunks,
            'cmdline': sys.argv,
            'hostname': socket.gethostname(),
            'username': getuser(),
            'time': start.isoformat(),
            'time_end': end.isoformat(),
            'chunker_params': self.chunker_params,
        }
        metadata.update(additional_metadata or {})
        data = msgpack.packb(StableDict(metadata), unicode_errors='surrogateescape')
        self.id = self.key.id_hash(data)
        self.cache.add_chunk(self.id, Chunk(data), self.stats)
        self.manifest.archives[name] = {'id': self.id, 'time': metadata['time']}
        self.manifest.write()
        self.repository.commit()
        self.cache.commit()

    def calc_stats(self, cache):
        def add(id):
            count, size, csize = cache.chunks[id]
            stats.update(size, csize, count == 1)
            cache.chunks[id] = count - 1, size, csize

        def add_file_chunks(chunks):
            for id, _, _ in chunks:
                add(id)

        # This function is a bit evil since it abuses the cache to calculate
        # the stats. The cache transaction must be rolled back afterwards
        unpacker = msgpack.Unpacker(use_list=False)
        cache.begin_txn()
        stats = Statistics()
        add(self.id)
        for id, chunk in zip(self.metadata[b'items'], self.repository.get_many(self.metadata[b'items'])):
            add(id)
            _, data = self.key.decrypt(id, chunk)
            unpacker.feed(data)
            for item in unpacker:
                item = Item(internal_dict=item)
                if 'chunks' in item:
                    stats.nfiles += 1
                    add_file_chunks(item.chunks)
        cache.rollback()
        return stats

    def extract_item(self, item, restore_attrs=True, dry_run=False, stdout=False, sparse=False,
                     hardlink_masters=None, original_path=None):
        """
        Extract archive item.

        :param item: the item to extract
        :param restore_attrs: restore file attributes
        :param dry_run: do not write any data
        :param stdout: write extracted data to stdout
        :param sparse: write sparse files (chunk-granularity, independent of the original being sparse)
        :param hardlink_masters: maps paths to (chunks, link_target) for extracting subtrees with hardlinks correctly
        :param original_path: 'path' key as stored in archive
        """
        has_damaged_chunks = 'chunks_healthy' in item
        if dry_run or stdout:
            if 'chunks' in item:
                for _, data in self.pipeline.fetch_many([c.id for c in item.chunks], is_preloaded=True):
                    if stdout:
                        sys.stdout.buffer.write(data)
                if stdout:
                    sys.stdout.buffer.flush()
            if has_damaged_chunks:
                logger.warning('File %s has damaged (all-zero) chunks. Try running borg check --repair.' %
                               remove_surrogates(item.path))
            return

        original_path = original_path or item.path
        dest = self.cwd
        if item.path.startswith(('/', '..')):
            raise Exception('Path should be relative and local')
        path = os.path.join(dest, item.path)
        # Attempt to remove existing files, ignore errors on failure
        try:
            st = os.lstat(path)
            if stat.S_ISDIR(st.st_mode):
                os.rmdir(path)
            else:
                os.unlink(path)
        except UnicodeEncodeError:
            raise self.IncompatibleFilesystemEncodingError(path, sys.getfilesystemencoding()) from None
        except OSError:
            pass
        mode = item.mode
        if stat.S_ISREG(mode):
            with backup_io():
                if not os.path.exists(os.path.dirname(path)):
                    os.makedirs(os.path.dirname(path))
            # Hard link?
            if 'source' in item:
                source = os.path.join(dest, item.source)
                with backup_io():
                    if os.path.exists(path):
                        os.unlink(path)
                    if not hardlink_masters:
                        os.link(source, path)
                        return
                item.chunks, link_target = hardlink_masters[item.source]
                if link_target:
                    # Hard link was extracted previously, just link
                    with backup_io():
                        os.link(link_target, path)
                    return
                # Extract chunks, since the item which had the chunks was not extracted
            with backup_io():
                fd = open(path, 'wb')
            with fd:
                ids = [c.id for c in item.chunks]
                for _, data in self.pipeline.fetch_many(ids, is_preloaded=True):
                    with backup_io():
                        if sparse and self.zeros.startswith(data):
                            # all-zero chunk: create a hole in a sparse file
                            fd.seek(len(data), 1)
                        else:
                            fd.write(data)
                with backup_io():
                    pos = fd.tell()
                    fd.truncate(pos)
                    fd.flush()
                    self.restore_attrs(path, item, fd=fd.fileno())
            if has_damaged_chunks:
                logger.warning('File %s has damaged (all-zero) chunks. Try running borg check --repair.' %
                               remove_surrogates(item.path))
            if hardlink_masters:
                # Update master entry with extracted file path, so that following hardlinks don't extract twice.
                hardlink_masters[item.get('source') or original_path] = (None, path)
            return
        with backup_io():
            # No repository access beyond this point.
            if stat.S_ISDIR(mode):
                if not os.path.exists(path):
                    os.makedirs(path)
                if restore_attrs:
                    self.restore_attrs(path, item)
            elif stat.S_ISLNK(mode):
                if not os.path.exists(os.path.dirname(path)):
                    os.makedirs(os.path.dirname(path))
                source = item.source
                if os.path.exists(path):
                    os.unlink(path)
                try:
                    os.symlink(source, path)
                except UnicodeEncodeError:
                    raise self.IncompatibleFilesystemEncodingError(source, sys.getfilesystemencoding()) from None
                self.restore_attrs(path, item, symlink=True)
            elif stat.S_ISFIFO(mode):
                if not os.path.exists(os.path.dirname(path)):
                    os.makedirs(os.path.dirname(path))
                os.mkfifo(path)
                self.restore_attrs(path, item)
            elif stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
                os.mknod(path, item.mode, item.rdev)
                self.restore_attrs(path, item)
            else:
                raise Exception('Unknown archive item type %r' % item.mode)

    def restore_attrs(self, path, item, symlink=False, fd=None):
        """
        Restore filesystem attributes on *path* (*fd*) from *item*.

        Does not access the repository.
        """
        uid = gid = None
        if not self.numeric_owner:
            uid = user2uid(item.user)
            gid = group2gid(item.group)
        uid = item.uid if uid is None else uid
        gid = item.gid if gid is None else gid
        # This code is a bit of a mess due to os specific differences
        try:
            if fd:
                os.fchown(fd, uid, gid)
            else:
                os.lchown(path, uid, gid)
        except OSError:
            pass
        if fd:
            os.fchmod(fd, item.mode)
        elif not symlink:
            os.chmod(path, item.mode)
        elif has_lchmod:  # Not available on Linux
            os.lchmod(path, item.mode)
        mtime = item.mtime
        if 'atime' in item:
            atime = item.atime
        else:
            # old archives only had mtime in item metadata
            atime = mtime
        if fd:
            os.utime(fd, None, ns=(atime, mtime))
        else:
            os.utime(path, None, ns=(atime, mtime), follow_symlinks=False)
        acl_set(path, item, self.numeric_owner)
        if 'bsdflags' in item:
            try:
                set_flags(path, item.bsdflags, fd=fd)
            except OSError:
                pass
        # chown removes Linux capabilities, so set the extended attributes at the end, after chown, since they include
        # the Linux capabilities in the "security.capability" attribute.
        xattrs = item.get('xattrs', {})
        for k, v in xattrs.items():
            try:
                xattr.setxattr(fd or path, k, v, follow_symlinks=False)
            except OSError as e:
                if e.errno not in (errno.ENOTSUP, errno.EACCES):
                    # only raise if the errno is not on our ignore list:
                    # ENOTSUP == xattrs not supported here
                    # EACCES == permission denied to set this specific xattr
                    #           (this may happen related to security.* keys)
                    raise

    def set_meta(self, key, value):
        metadata = StableDict(self._load_meta(self.id))
        metadata[key] = value
        data = msgpack.packb(metadata, unicode_errors='surrogateescape')
        new_id = self.key.id_hash(data)
        self.cache.add_chunk(new_id, Chunk(data), self.stats)
        self.manifest.archives[self.name] = {'id': new_id, 'time': metadata[b'time']}
        self.cache.chunk_decref(self.id, self.stats)
        self.id = new_id

    def rename(self, name):
        if name in self.manifest.archives:
            raise self.AlreadyExists(name)
        oldname = self.name
        self.name = name
        self.set_meta(b'name', name)
        del self.manifest.archives[oldname]

    def delete(self, stats, progress=False, forced=False):
        class ChunksIndexError(Error):
            """Chunk ID {} missing from chunks index, corrupted chunks index - aborting transaction."""

        def chunk_decref(id, stats):
            nonlocal error
            try:
                self.cache.chunk_decref(id, stats)
            except KeyError:
                cid = bin_to_hex(id)
                raise ChunksIndexError(cid)
            except Repository.ObjectNotFound as e:
                # object not in repo - strange, but we wanted to delete it anyway.
                if not forced:
                    raise
                error = True

        error = False
        try:
            unpacker = msgpack.Unpacker(use_list=False)
            items_ids = self.metadata[b'items']
            pi = ProgressIndicatorPercent(total=len(items_ids), msg="Decrementing references %3.0f%%", same_line=True)
            for (i, (items_id, data)) in enumerate(zip(items_ids, self.repository.get_many(items_ids))):
                if progress:
                    pi.show(i)
                _, data = self.key.decrypt(items_id, data)
                unpacker.feed(data)
                chunk_decref(items_id, stats)
                try:
                    for item in unpacker:
                        item = Item(internal_dict=item)
                        if 'chunks' in item:
                            for chunk_id, size, csize in item.chunks:
                                chunk_decref(chunk_id, stats)
                except (TypeError, ValueError):
                    # if items metadata spans multiple chunks and one chunk got dropped somehow,
                    # it could be that unpacker yields bad types
                    if not forced:
                        raise
                    error = True
            if progress:
                pi.finish()
        except (msgpack.UnpackException, Repository.ObjectNotFound):
            # items metadata corrupted
            if not forced:
                raise
            error = True
        # in forced delete mode, we try hard to delete at least the manifest entry,
        # if possible also the archive superblock, even if processing the items raises
        # some harmless exception.
        chunk_decref(self.id, stats)
        del self.manifest.archives[self.name]
        if error:
            logger.warning('forced deletion succeeded, but the deleted archive was corrupted.')
            logger.warning('borg check --repair is required to free all space.')

    def stat_attrs(self, st, path):
        attrs = dict(
            mode=st.st_mode,
            uid=st.st_uid, user=uid2user(st.st_uid),
            gid=st.st_gid, group=gid2group(st.st_gid),
            atime=st.st_atime_ns,
            ctime=st.st_ctime_ns,
            mtime=st.st_mtime_ns,
        )
        if self.numeric_owner:
            attrs['user'] = attrs['group'] = None
        with backup_io():
            xattrs = xattr.get_all(path, follow_symlinks=False)
            bsdflags = get_flags(path, st)
            acl_get(path, attrs, st, self.numeric_owner)
        if xattrs:
            attrs['xattrs'] = StableDict(xattrs)
        if bsdflags:
            attrs['bsdflags'] = bsdflags
        return attrs

    def process_dir(self, path, st):
        item = Item(path=make_path_safe(path))
        item.update(self.stat_attrs(st, path))
        self.add_item(item)
        return 'd'  # directory

    def process_fifo(self, path, st):
        item = Item(path=make_path_safe(path))
        item.update(self.stat_attrs(st, path))
        self.add_item(item)
        return 'f'  # fifo

    def process_dev(self, path, st):
        item = Item(path=make_path_safe(path), rdev=st.st_rdev)
        item.update(self.stat_attrs(st, path))
        self.add_item(item)
        if stat.S_ISCHR(st.st_mode):
            return 'c'  # char device
        elif stat.S_ISBLK(st.st_mode):
            return 'b'  # block device

    def process_symlink(self, path, st):
        source = os.readlink(path)
        item = Item(path=make_path_safe(path), source=source)
        item.update(self.stat_attrs(st, path))
        self.add_item(item)
        return 's'  # symlink

    def process_stdin(self, path, cache):
        uid, gid = 0, 0
        fd = sys.stdin.buffer  # binary
        chunks = []
        for data in backup_io_iter(self.chunker.chunkify(fd)):
            chunks.append(cache.add_chunk(self.key.id_hash(data), Chunk(data), self.stats))
        self.stats.nfiles += 1
        t = int(time.time()) * 1000000000
        item = Item(
            path=path,
            chunks=chunks,
            mode=0o100660,  # regular file, ug=rw
            uid=uid, user=uid2user(uid),
            gid=gid, group=gid2group(gid),
            mtime=t, atime=t, ctime=t,
        )
        self.add_item(item)
        return 'i'  # stdin

    def process_file(self, path, st, cache, ignore_inode=False):
        status = None
        safe_path = make_path_safe(path)
        # Is it a hard link?
        if st.st_nlink > 1:
            source = self.hard_links.get((st.st_ino, st.st_dev))
            if (st.st_ino, st.st_dev) in self.hard_links:
                item = Item(path=safe_path, source=source)
                item.update(self.stat_attrs(st, path))
                self.add_item(item)
                status = 'h'  # regular file, hardlink (to already seen inodes)
                return status
            else:
                self.hard_links[st.st_ino, st.st_dev] = safe_path
        is_special_file = is_special(st.st_mode)
        if not is_special_file:
            path_hash = self.key.id_hash(safe_encode(os.path.join(self.cwd, path)))
            ids = cache.file_known_and_unchanged(path_hash, st, ignore_inode)
        else:
            # in --read-special mode, we may be called for special files.
            # there should be no information in the cache about special files processed in
            # read-special mode, but we better play safe as this was wrong in the past:
            path_hash = ids = None
        first_run = not cache.files
        if first_run:
            logger.debug('Processing files ...')
        chunks = None
        if ids is not None:
            # Make sure all ids are available
            for id_ in ids:
                if not cache.seen_chunk(id_):
                    break
            else:
                chunks = [cache.chunk_incref(id_, self.stats) for id_ in ids]
                status = 'U'  # regular file, unchanged
        else:
            status = 'A'  # regular file, added
        item = Item(
            path=safe_path,
            hardlink_master=st.st_nlink > 1,  # item is a hard link and has the chunks
        )
        # Only chunkify the file if needed
        if chunks is None:
            compress = self.compression_decider1.decide(path)
            logger.debug('%s -> compression %s', path, compress['name'])
            with backup_io():
                fh = Archive._open_rb(path)
            with os.fdopen(fh, 'rb') as fd:
                chunks = []
                for data in backup_io_iter(self.chunker.chunkify(fd, fh)):
                    chunks.append(cache.add_chunk(self.key.id_hash(data),
                                                  Chunk(data, compress=compress),
                                                  self.stats))
                    if self.show_progress:
                        self.stats.show_progress(item=item, dt=0.2)
            if not is_special_file:
                # we must not memorize special files, because the contents of e.g. a
                # block or char device will change without its mtime/size/inode changing.
                cache.memorize_file(path_hash, st, [c.id for c in chunks])
            status = status or 'M'  # regular file, modified (if not 'A' already)
        item.chunks = chunks
        item.update(self.stat_attrs(st, path))
        if is_special_file:
            # we processed a special file like a regular file. reflect that in mode,
            # so it can be extracted / accessed in FUSE mount like a regular file:
            item.mode = stat.S_IFREG | stat.S_IMODE(item.mode)
        self.stats.nfiles += 1
        self.add_item(item)
        return status

    @staticmethod
    def list_archives(repository, key, manifest, cache=None):
        # expensive! see also Manifest.list_archive_infos.
        for name, info in manifest.archives.items():
            yield Archive(repository, key, manifest, name, cache=cache)

    @staticmethod
    def _open_rb(path):
        try:
            # if we have O_NOATIME, this likely will succeed if we are root or owner of file:
            return os.open(path, flags_noatime)
        except PermissionError:
            if flags_noatime == flags_normal:
                # we do not have O_NOATIME, no need to try again:
                raise
            # Was this EPERM due to the O_NOATIME flag? Try again without it:
            return os.open(path, flags_normal)


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
                    if self.validator(item):
                        self._resync = False
                        return item
                # Ignore exceptions that might be raised when feeding
                # msgpack with invalid data
                except (TypeError, ValueError, StopIteration):
                    pass
                data = data[1:]
        else:
            return next(self._unpacker)


class ArchiveChecker:

    def __init__(self):
        self.error_found = False
        self.possibly_superseded = set()

    def check(self, repository, repair=False, archive=None, last=None, prefix=None, verify_data=False,
              save_space=False):
        """Perform a set of checks on 'repository'

        :param repair: enable repair mode, write updated or corrected data into repository
        :param archive: only check this archive
        :param last: only check this number of recent archives
        :param prefix: only check archives with this prefix
        :param verify_data: integrity verification of data referenced by archives
        :param save_space: Repository.commit(save_space)
        """
        logger.info('Starting archive consistency check...')
        self.check_all = archive is None and last is None and prefix is None
        self.repair = repair
        self.repository = repository
        self.init_chunks()
        self.key = self.identify_key(repository)
        if Manifest.MANIFEST_ID not in self.chunks:
            logger.error("Repository manifest not found!")
            self.error_found = True
            self.manifest = self.rebuild_manifest()
        else:
            self.manifest, _ = Manifest.load(repository, key=self.key)
        self.rebuild_refcounts(archive=archive, last=last, prefix=prefix)
        if verify_data:
            self.verify_data()
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
        # Explicitly set the initial hash table capacity to avoid performance issues
        # due to hash table "resonance"
        capacity = int(len(self.repository) * (1/0.93) + 1)  # > len * 1.0 / HASH_MAX_LOAD (see _hashindex.c)
        self.chunks = ChunkIndex(capacity)
        marker = None
        while True:
            result = self.repository.list(limit=10000, marker=marker)
            if not result:
                break
            marker = result[-1]
            init_entry = ChunkIndexEntry(refcount=0, size=0, csize=0)
            for id_ in result:
                self.chunks[id_] = init_entry

    def identify_key(self, repository):
        try:
            some_chunkid, _ = next(self.chunks.iteritems())
        except StopIteration:
            # repo is completely empty, no chunks
            return None
        cdata = repository.get(some_chunkid)
        return key_factory(repository, cdata)

    def verify_data(self):
        logger.info('Starting cryptographic data integrity verification...')
        pi = ProgressIndicatorPercent(total=len(self.chunks), msg="Verifying data %6.2f%%", step=0.01, same_line=True)
        count = errors = 0
        for chunk_id, (refcount, *_) in self.chunks.iteritems():
            pi.show()
            if not refcount:
                continue
            encrypted_data = self.repository.get(chunk_id)
            try:
                _, data = self.key.decrypt(chunk_id, encrypted_data)
            except IntegrityError as integrity_error:
                self.error_found = True
                errors += 1
                logger.error('chunk %s, integrity error: %s', bin_to_hex(chunk_id), integrity_error)
            count += 1
        pi.finish()
        log = logger.error if errors else logger.info
        log('Finished cryptographic data integrity verification, verified %d chunks with %d integrity errors.', count, errors)

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
        for chunk_id, _ in self.chunks.iteritems():
            cdata = self.repository.get(chunk_id)
            _, data = self.key.decrypt(chunk_id, cdata)
            if not valid_msgpacked_dict(data, archive_keys_serialized):
                continue
            if b'cmdline' not in data or b'\xa7version\x01' not in data:
                continue
            try:
                archive = msgpack.unpackb(data)
            # Ignore exceptions that might be raised when feeding
            # msgpack with invalid data
            except (TypeError, ValueError, StopIteration):
                continue
            if valid_archive(archive):
                logger.info('Found archive %s', archive[b'name'].decode('utf-8'))
                manifest.archives[archive[b'name'].decode('utf-8')] = {b'id': chunk_id, b'time': archive[b'time']}
        logger.info('Manifest rebuild complete.')
        return manifest

    def rebuild_refcounts(self, archive=None, last=None, prefix=None):
        """Rebuild object reference counts by walking the metadata

        Missing and/or incorrect data is repaired when detected
        """
        # Exclude the manifest from chunks
        del self.chunks[Manifest.MANIFEST_ID]

        def mark_as_possibly_superseded(id_):
            if self.chunks.get(id_, ChunkIndexEntry(0, 0, 0)).refcount == 0:
                self.possibly_superseded.add(id_)

        def add_callback(chunk):
            id_ = self.key.id_hash(chunk.data)
            cdata = self.key.encrypt(chunk)
            add_reference(id_, len(chunk.data), len(cdata), cdata)
            return id_

        def add_reference(id_, size, csize, cdata=None):
            try:
                self.chunks.incref(id_)
            except KeyError:
                assert cdata is not None
                self.chunks[id_] = ChunkIndexEntry(refcount=1, size=size, csize=csize)
                if self.repair:
                    self.repository.put(id_, cdata)

        def verify_file_chunks(item):
            """Verifies that all file chunks are present.

            Missing file chunks will be replaced with new chunks of the same length containing all zeros.
            If a previously missing file chunk re-appears, the replacement chunk is replaced by the correct one.
            """
            offset = 0
            chunk_list = []
            chunks_replaced = False
            has_chunks_healthy = 'chunks_healthy' in item
            chunks_current = item.chunks
            chunks_healthy = item.chunks_healthy if has_chunks_healthy else chunks_current
            assert len(chunks_current) == len(chunks_healthy)
            for chunk_current, chunk_healthy in zip(chunks_current, chunks_healthy):
                chunk_id, size, csize = chunk_healthy
                if chunk_id not in self.chunks:
                    # a chunk of the healthy list is missing
                    if chunk_current == chunk_healthy:
                        logger.error('{}: New missing file chunk detected (Byte {}-{}). '
                                     'Replacing with all-zero chunk.'.format(item.path, offset, offset + size))
                        self.error_found = chunks_replaced = True
                        data = bytes(size)
                        chunk_id = self.key.id_hash(data)
                        cdata = self.key.encrypt(Chunk(data))
                        csize = len(cdata)
                        add_reference(chunk_id, size, csize, cdata)
                    else:
                        logger.info('{}: Previously missing file chunk is still missing (Byte {}-{}). It has a '
                                    'all-zero replacement chunk already.'.format(item.path, offset, offset + size))
                        chunk_id, size, csize = chunk_current
                        add_reference(chunk_id, size, csize)
                else:
                    if chunk_current == chunk_healthy:
                        # normal case, all fine.
                        add_reference(chunk_id, size, csize)
                    else:
                        logger.info('{}: Healed previously missing file chunk! '
                                    '(Byte {}-{}).'.format(item.path, offset, offset + size))
                        add_reference(chunk_id, size, csize)
                        mark_as_possibly_superseded(chunk_current[0])  # maybe orphaned the all-zero replacement chunk
                chunk_list.append([chunk_id, size, csize])  # list-typed element as chunks_healthy is list-of-lists
                offset += size
            if chunks_replaced and not has_chunks_healthy:
                # if this is first repair, remember the correct chunk IDs, so we can maybe heal the file later
                item.chunks_healthy = item.chunks
            if has_chunks_healthy and chunk_list == chunks_healthy:
                logger.info('{}: Completely healed previously damaged file!'.format(item.path))
                del item.chunks_healthy
            item.chunks = chunk_list

        def robust_iterator(archive):
            """Iterates through all archive items

            Missing item chunks will be skipped and the msgpack stream will be restarted
            """
            item_keys = frozenset(key.encode() for key in self.manifest.item_keys)
            required_item_keys = frozenset(key.encode() for key in REQUIRED_ITEM_KEYS)
            unpacker = RobustUnpacker(lambda item: isinstance(item, dict) and 'path' in item,
                                      self.manifest.item_keys)
            _state = 0

            def missing_chunk_detector(chunk_id):
                nonlocal _state
                if _state % 2 != int(chunk_id not in self.chunks):
                    _state += 1
                return _state

            def report(msg, chunk_id, chunk_no):
                cid = bin_to_hex(chunk_id)
                msg += ' [chunk: %06d_%s]' % (chunk_no, cid)  # see debug-dump-archive-items
                self.error_found = True
                logger.error(msg)

            def valid_item(obj):
                if not isinstance(obj, StableDict):
                    return False
                keys = set(obj)
                return required_item_keys.issubset(keys) and keys.issubset(item_keys)

            i = 0
            for state, items in groupby(archive[b'items'], missing_chunk_detector):
                items = list(items)
                if state % 2:
                    for chunk_id in items:
                        report('item metadata chunk missing', chunk_id, i)
                        i += 1
                    continue
                if state > 0:
                    unpacker.resync()
                for chunk_id, cdata in zip(items, repository.get_many(items)):
                    _, data = self.key.decrypt(chunk_id, cdata)
                    unpacker.feed(data)
                    try:
                        for item in unpacker:
                            if valid_item(item):
                                yield Item(internal_dict=item)
                            else:
                                report('Did not get expected metadata dict when unpacking item metadata', chunk_id, i)
                    except Exception:
                        report('Exception while unpacking item metadata', chunk_id, i)
                        raise
                    i += 1

        if archive is None:
            # we need last N or all archives
            archive_items = sorted(self.manifest.archives.items(), reverse=True,
                                   key=lambda name_info: name_info[1][b'time'])
            if prefix is not None:
                archive_items = [item for item in archive_items if item[0].startswith(prefix)]
            num_archives = len(archive_items)
            end = None if last is None else min(num_archives, last)
        else:
            # we only want one specific archive
            archive_items = [item for item in self.manifest.archives.items() if item[0] == archive]
            if not archive_items:
                logger.error("Archive '%s' not found.", archive)
            num_archives = 1
            end = 1

        with cache_if_remote(self.repository) as repository:
            for i, (name, info) in enumerate(archive_items[:end]):
                logger.info('Analyzing archive {} ({}/{})'.format(name, num_archives - i, num_archives))
                archive_id = info[b'id']
                if archive_id not in self.chunks:
                    logger.error('Archive metadata block is missing!')
                    self.error_found = True
                    del self.manifest.archives[name]
                    continue
                mark_as_possibly_superseded(archive_id)
                cdata = self.repository.get(archive_id)
                _, data = self.key.decrypt(archive_id, cdata)
                archive = StableDict(msgpack.unpackb(data))
                if archive[b'version'] != 1:
                    raise Exception('Unknown archive metadata version')
                decode_dict(archive, ARCHIVE_TEXT_KEYS)
                archive[b'cmdline'] = [safe_decode(arg) for arg in archive[b'cmdline']]
                items_buffer = ChunkBuffer(self.key)
                items_buffer.write_chunk = add_callback
                for item in robust_iterator(archive):
                    if 'chunks' in item:
                        verify_file_chunks(item)
                    items_buffer.add(item)
                items_buffer.flush(flush=True)
                for previous_item_id in archive[b'items']:
                    mark_as_possibly_superseded(previous_item_id)
                archive[b'items'] = items_buffer.chunks
                data = msgpack.packb(archive, unicode_errors='surrogateescape')
                new_archive_id = self.key.id_hash(data)
                cdata = self.key.encrypt(Chunk(data))
                add_reference(new_archive_id, len(data), len(cdata), cdata)
                info[b'id'] = new_archive_id

    def orphan_chunks_check(self):
        if self.check_all:
            unused = {id_ for id_, entry in self.chunks.iteritems() if entry.refcount == 0}
            orphaned = unused - self.possibly_superseded
            if orphaned:
                logger.error('{} orphaned objects found!'.format(len(orphaned)))
                self.error_found = True
            if self.repair:
                for id_ in unused:
                    self.repository.delete(id_)
        else:
            logger.info('Orphaned objects check skipped (needs all archives checked).')

    def finish(self, save_space=False):
        if self.repair:
            self.manifest.write()
            self.repository.commit(save_space=save_space)


class ArchiveRecreater:
    AUTOCOMMIT_THRESHOLD = 512 * 1024 * 1024
    """Commit (compact segments) after this many (or 1 % of repository size, whichever is greater) bytes."""

    class FakeTargetArchive:
        def __init__(self):
            self.stats = Statistics()

    class Interrupted(Exception):
        def __init__(self, metadata=None):
            self.metadata = metadata or {}

    @staticmethod
    def is_temporary_archive(archive_name):
        return archive_name.endswith('.recreate')

    def __init__(self, repository, manifest, key, cache, matcher,
                 exclude_caches=False, exclude_if_present=None, keep_tag_files=False,
                 chunker_params=None, compression=None, compression_files=None,
                 dry_run=False, stats=False, progress=False, file_status_printer=None):
        self.repository = repository
        self.key = key
        self.manifest = manifest
        self.cache = cache

        self.matcher = matcher
        self.exclude_caches = exclude_caches
        self.exclude_if_present = exclude_if_present or []
        self.keep_tag_files = keep_tag_files

        self.chunker_params = chunker_params or CHUNKER_PARAMS
        self.recompress = bool(compression)
        self.compression = compression or CompressionSpec('none')
        self.seen_chunks = set()
        self.compression_decider1 = CompressionDecider1(compression or CompressionSpec('none'),
                                                            compression_files or [])
        key.compression_decider2 = CompressionDecider2(compression or CompressionSpec('none'))

        self.autocommit_threshold = max(self.AUTOCOMMIT_THRESHOLD, self.cache.chunks_stored_size() / 100)
        logger.debug("Autocommit threshold: %s", format_file_size(self.autocommit_threshold))

        self.dry_run = dry_run
        self.stats = stats
        self.progress = progress
        self.print_file_status = file_status_printer or (lambda *args: None)

        self.interrupt = False
        self.errors = False

    def recreate(self, archive_name, comment=None):
        assert not self.is_temporary_archive(archive_name)
        archive = self.open_archive(archive_name)
        target, resume_from = self.create_target_or_resume(archive)
        if self.exclude_if_present or self.exclude_caches:
            self.matcher_add_tagged_dirs(archive)
        if self.matcher.empty() and not self.recompress and not target.recreate_rechunkify and comment is None:
            logger.info("Skipping archive %s, nothing to do", archive_name)
            return True
        try:
            self.process_items(archive, target, resume_from)
        except self.Interrupted as e:
            return self.save(archive, target, completed=False, metadata=e.metadata)
        return self.save(archive, target, comment)

    def process_items(self, archive, target, resume_from=None):
        matcher = self.matcher
        target_is_subset = not matcher.empty()
        hardlink_masters = {} if target_is_subset else None

        def item_is_hardlink_master(item):
            return (target_is_subset and
                    stat.S_ISREG(item.mode) and
                    item.get('hardlink_master', True) and
                    'source' not in item and
                    not matcher.match(item.path))

        for item in archive.iter_items():
            if item_is_hardlink_master(item):
                # Re-visit all of these items in the archive even when fast-forwarding to rebuild hardlink_masters
                hardlink_masters[item.path] = (item.get('chunks'), None)
                continue
            if resume_from:
                # Fast forward to after the last processed file
                if item.path == resume_from:
                    logger.info('Fast-forwarded to %s', remove_surrogates(item.path))
                    resume_from = None
                continue
            if not matcher.match(item.path):
                self.print_file_status('x', item.path)
                continue
            if target_is_subset and stat.S_ISREG(item.mode) and item.get('source') in hardlink_masters:
                # master of this hard link is outside the target subset
                chunks, new_source = hardlink_masters[item.source]
                if new_source is None:
                    # First item to use this master, move the chunks
                    item.chunks = chunks
                    hardlink_masters[item.source] = (None, item.path)
                    del item.source
                else:
                    # Master was already moved, only update this item's source
                    item.source = new_source
            if self.dry_run:
                self.print_file_status('-', item.path)
            else:
                try:
                    self.process_item(archive, target, item)
                except self.Interrupted:
                    if self.progress:
                        target.stats.show_progress(final=True)
                    raise
        if self.progress:
            target.stats.show_progress(final=True)

    def process_item(self, archive, target, item):
        if 'chunks' in item:
            item.chunks = self.process_chunks(archive, target, item)
            target.stats.nfiles += 1
        target.add_item(item)
        self.print_file_status(file_status(item.mode), item.path)
        if self.interrupt:
            raise self.Interrupted

    def process_chunks(self, archive, target, item):
        """Return new chunk ID list for 'item'."""
        # TODO: support --compression-from
        if not self.recompress and not target.recreate_rechunkify:
            for chunk_id, size, csize in item.chunks:
                self.cache.chunk_incref(chunk_id, target.stats)
            return item.chunks
        new_chunks = self.process_partial_chunks(target)
        chunk_iterator = self.create_chunk_iterator(archive, target, item)
        consume(chunk_iterator, len(new_chunks))
        for chunk in chunk_iterator:
            chunk_id = self.key.id_hash(chunk.data)
            if chunk_id in self.seen_chunks:
                new_chunks.append(self.cache.chunk_incref(chunk_id, target.stats))
            else:
                # TODO: detect / skip / --always-recompress
                chunk_id, size, csize = self.cache.add_chunk(chunk_id, chunk, target.stats, overwrite=self.recompress)
                new_chunks.append((chunk_id, size, csize))
                self.seen_chunks.add(chunk_id)
                if self.recompress:
                    # This tracks how many bytes are uncommitted but compactable, since we are recompressing
                    # existing chunks.
                    target.recreate_uncomitted_bytes += csize
                    if target.recreate_uncomitted_bytes >= self.autocommit_threshold:
                        # Issue commits to limit additional space usage when recompressing chunks
                        target.recreate_uncomitted_bytes = 0
                        self.repository.commit()
            if self.progress:
                target.stats.show_progress(item=item, dt=0.2)
            if self.interrupt:
                raise self.Interrupted({
                    'recreate_partial_chunks': new_chunks,
                })
        return new_chunks

    def create_chunk_iterator(self, archive, target, item):
        """Return iterator of chunks to store for 'item' from 'archive' in 'target'."""
        chunk_iterator = archive.pipeline.fetch_many([chunk_id for chunk_id, _, _ in item.chunks])
        if target.recreate_rechunkify:
            # The target.chunker will read the file contents through ChunkIteratorFileWrapper chunk-by-chunk
            # (does not load the entire file into memory)
            file = ChunkIteratorFileWrapper(chunk_iterator)

            def _chunk_iterator():
                for data in target.chunker.chunkify(file):
                    yield Chunk(data)

            chunk_iterator = _chunk_iterator()
        return chunk_iterator

    def process_partial_chunks(self, target):
        """Return chunks from a previous run for archive 'target' (if any) or an empty list."""
        if not target.recreate_partial_chunks:
            return []
        # No incref, create_target_or_resume already did that before to deleting the old target archive
        # So just copy these over
        partial_chunks = target.recreate_partial_chunks
        target.recreate_partial_chunks = None
        for chunk_id, size, csize in partial_chunks:
            self.seen_chunks.add(chunk_id)
        logger.debug('Copied %d chunks from a partially processed item', len(partial_chunks))
        return partial_chunks

    def save(self, archive, target, comment=None, completed=True, metadata=None):
        """Save target archive. If completed, replace source. If not, save temporary with additional 'metadata' dict."""
        if self.dry_run:
            return completed
        if completed:
            timestamp = archive.ts.replace(tzinfo=None)
            if comment is None:
                comment = archive.metadata.get(b'comment', '')
            target.save(timestamp=timestamp, comment=comment, additional_metadata={
                'cmdline': archive.metadata[b'cmdline'],
                'recreate_cmdline': sys.argv,
            })
            archive.delete(Statistics(), progress=self.progress)
            target.rename(archive.name)
            if self.stats:
                target.end = datetime.utcnow()
                log_multi(DASHES,
                          str(target),
                          DASHES,
                          str(target.stats),
                          str(self.cache),
                          DASHES)
        else:
            additional_metadata = metadata or {}
            additional_metadata.update({
                'recreate_source_id': archive.id,
                'recreate_args': sys.argv[1:],
            })
            target.save(name=archive.name + '.recreate', additional_metadata=additional_metadata)
            logger.info('Run the same command again to resume.')
        return completed

    def matcher_add_tagged_dirs(self, archive):
        """Add excludes to the matcher created by exclude_cache and exclude_if_present."""
        def exclude(dir, tag_item):
            if self.keep_tag_files:
                tag_files.append(PathPrefixPattern(tag_item.path))
                tagged_dirs.append(FnmatchPattern(dir + '/'))
            else:
                tagged_dirs.append(PathPrefixPattern(dir))

        matcher = self.matcher
        tag_files = []
        tagged_dirs = []
        # build hardlink masters, but only for paths ending in CACHE_TAG_NAME, so we can read hard-linked TAGs
        cachedir_masters = {}

        for item in archive.iter_items(
                filter=lambda item: item.path.endswith(CACHE_TAG_NAME) or matcher.match(item.path)):
            if item.path.endswith(CACHE_TAG_NAME):
                cachedir_masters[item.path] = item
            if stat.S_ISREG(item.mode):
                dir, tag_file = os.path.split(item.path)
                if tag_file in self.exclude_if_present:
                    exclude(dir, item)
                if self.exclude_caches and tag_file == CACHE_TAG_NAME:
                    if 'chunks' in item:
                        file = open_item(archive, item)
                    else:
                        file = open_item(archive, cachedir_masters[item.source])
                    if file.read(len(CACHE_TAG_CONTENTS)).startswith(CACHE_TAG_CONTENTS):
                        exclude(dir, item)
        matcher.add(tag_files, True)
        matcher.add(tagged_dirs, False)

    def create_target_or_resume(self, archive):
        """Create new target archive or resume from temporary archive, if it exists. Return archive, resume from path"""
        if self.dry_run:
            return self.FakeTargetArchive(), None
        target_name = archive.name + '.recreate'
        resume = target_name in self.manifest.archives
        target, resume_from = None, None
        if resume:
            target, resume_from = self.try_resume(archive, target_name)
        if not target:
            target = self.create_target_archive(target_name)
        # If the archives use the same chunker params, then don't rechunkify
        target.recreate_rechunkify = tuple(archive.metadata.get(b'chunker_params')) != self.chunker_params
        return target, resume_from

    def try_resume(self, archive, target_name):
        """Try to resume from temporary archive. Return (target archive, resume from path) if successful."""
        logger.info('Found %s, will resume interrupted operation', target_name)
        old_target = self.open_archive(target_name)
        resume_id = old_target.metadata[b'recreate_source_id']
        resume_args = [safe_decode(arg) for arg in old_target.metadata[b'recreate_args']]
        if resume_id != archive.id:
            logger.warning('Source archive changed, will discard %s and start over', target_name)
            logger.warning('Saved fingerprint:   %s', bin_to_hex(resume_id))
            logger.warning('Current fingerprint: %s', archive.fpr)
            old_target.delete(Statistics(), progress=self.progress)
            return None, None  # can't resume
        if resume_args != sys.argv[1:]:
            logger.warning('Command line changed, this might lead to inconsistencies')
            logger.warning('Saved:   %s', repr(resume_args))
            logger.warning('Current: %s', repr(sys.argv[1:]))
        target = self.create_target_archive(target_name + '.temp')
        logger.info('Replaying items from interrupted operation...')
        item = None
        for item in old_target.iter_items():
            if 'chunks' in item:
                for chunk in item.chunks:
                    self.cache.chunk_incref(chunk.id, target.stats)
                target.stats.nfiles += 1
            target.add_item(item)
        if item:
            resume_from = item.path
        else:
            resume_from = None
        if self.progress:
            old_target.stats.show_progress(final=True)
        target.recreate_partial_chunks = old_target.metadata.get(b'recreate_partial_chunks', [])
        for chunk_id, size, csize in target.recreate_partial_chunks:
            if not self.cache.seen_chunk(chunk_id):
                try:
                    # Repository has __contains__, RemoteRepository doesn't
                    self.repository.get(chunk_id)
                except Repository.ObjectNotFound:
                    # delete/prune/check between invocations: these chunks are gone.
                    target.recreate_partial_chunks = None
                    break
                # fast-lane insert into chunks cache
                self.cache.chunks[chunk_id] = (1, size, csize)
                target.stats.update(size, csize, True)
                continue
            # incref now, otherwise old_target.delete() might delete these chunks
            self.cache.chunk_incref(chunk_id, target.stats)
        old_target.delete(Statistics(), progress=self.progress)
        logger.info('Done replaying items')
        return target, resume_from

    def create_target_archive(self, name):
        target = Archive(self.repository, self.key, self.manifest, name, create=True,
                          progress=self.progress, chunker_params=self.chunker_params, cache=self.cache,
                          checkpoint_interval=0, compression=self.compression)
        target.recreate_partial_chunks = None
        target.recreate_uncomitted_bytes = 0
        return target

    def open_archive(self, name, **kwargs):
        return Archive(self.repository, self.key, self.manifest, name, cache=self.cache, **kwargs)

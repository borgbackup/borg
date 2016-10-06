from contextlib import contextmanager
from datetime import datetime, timezone
from getpass import getuser
from itertools import groupby
import errno

from .logger import create_logger
logger = create_logger()
from .key import key_factory
from .remote import cache_if_remote

import os
import socket
import stat
import sys
import time
from io import BytesIO
from . import xattr
from .helpers import Error, uid2user, user2uid, gid2group, group2gid, bin_to_hex, \
    parse_timestamp, to_localtime, format_time, format_timedelta, remove_surrogates, \
    Manifest, Statistics, decode_dict, make_path_safe, StableDict, int_to_bigint, bigint_to_int, \
    ProgressIndicatorPercent
from .platform import acl_get, acl_set
from .chunker import Chunker
from .hashindex import ChunkIndex
from .repository import Repository

import msgpack

ITEMS_BUFFER = 1024 * 1024

CHUNK_MIN_EXP = 19  # 2**19 == 512kiB
CHUNK_MAX_EXP = 23  # 2**23 == 8MiB
HASH_WINDOW_SIZE = 0xfff  # 4095B
HASH_MASK_BITS = 21  # results in ~2MiB chunks statistically

# defaults, use --chunker-params to override
CHUNKER_PARAMS = (CHUNK_MIN_EXP, CHUNK_MAX_EXP, HASH_MASK_BITS, HASH_WINDOW_SIZE)

# chunker params for the items metadata stream, finer granularity
ITEMS_CHUNKER_PARAMS = (15, 19, 17, HASH_WINDOW_SIZE)

has_lchmod = hasattr(os, 'lchmod')
has_lchflags = hasattr(os, 'lchflags')

flags_normal = os.O_RDONLY | getattr(os, 'O_BINARY', 0)
flags_noatime = flags_normal | getattr(os, 'O_NOATIME', 0)


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
        """
        Return iterator of items.

        *ids* is a chunk ID list of an item stream. *filter* is a callable
        to decide whether an item will be yielded. *preload* preloads the data chunks of every yielded item.

        Warning: if *preload* is True then all data chunks of every yielded item have to be retrieved,
        otherwise preloaded chunks will accumulate in RemoteRepository and create a memory leak.
        """
        unpacker = msgpack.Unpacker(use_list=False)
        for data in self.fetch_many(ids):
            unpacker.feed(data)
            items = [decode_dict(item, (b'path', b'source', b'user', b'group')) for item in unpacker]
            if filter:
                items = [item for item in items if filter(item)]
            if preload:
                for item in items:
                    if b'chunks' in item:
                        self.repository.preload([c[0] for c in item[b'chunks']])
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
        self.buffer.write(self.packer.pack(StableDict(item)))
        if self.is_full():
            self.flush()

    def write_chunk(self, chunk):
        raise NotImplementedError

    def flush(self, flush=False):
        if self.buffer.tell() == 0:
            return
        self.buffer.seek(0)
        chunks = list(bytes(s) for s in self.chunker.chunkify(self.buffer))
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
        id_, _, _ = self.cache.add_chunk(self.key.id_hash(chunk), chunk, self.stats)
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
                 chunker_params=CHUNKER_PARAMS, start=None, end=None):
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
        self.start = start
        if end is None:
            end = datetime.utcnow()
        self.end = end
        self.pipeline = DownloadPipeline(self.repository, self.key)
        if create:
            self.items_buffer = CacheChunkBuffer(self.cache, self.key, self.stats)
            self.chunker = Chunker(self.key.chunk_seed, *chunker_params)
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
        data = self.key.decrypt(id, self.repository.get(id))
        metadata = msgpack.unpackb(data)
        if metadata[b'version'] != 1:
            raise Exception('Unknown archive metadata version')
        return metadata

    def load(self, id):
        self.id = id
        self.metadata = self._load_meta(self.id)
        decode_dict(self.metadata, (b'name', b'hostname', b'username', b'time', b'time_end'))
        self.metadata[b'cmdline'] = [arg.decode('utf-8', 'surrogateescape') for arg in self.metadata[b'cmdline']]
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
        unknown_keys = set(item) - self.manifest.item_keys
        assert not unknown_keys, ('unknown item metadata keys detected, please update ITEM_KEYS: %s',
                                  ','.join(k.decode('ascii') for k in unknown_keys))
        if self.show_progress:
            self.stats.show_progress(item=item, dt=0.2)
        self.items_buffer.add(item)
        if time.time() - self.last_checkpoint > self.checkpoint_interval:
            self.write_checkpoint()
            self.last_checkpoint = time.time()

    def write_checkpoint(self):
        self.save(self.checkpoint_name)
        del self.manifest.archives[self.checkpoint_name]
        self.cache.chunk_decref(self.id, self.stats)

    def save(self, name=None, timestamp=None):
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
        metadata = StableDict({
            'version': 1,
            'name': name,
            'items': self.items_buffer.chunks,
            'cmdline': sys.argv,
            'hostname': socket.gethostname(),
            'username': getuser(),
            'time': start.isoformat(),
            'time_end': end.isoformat(),
        })
        data = msgpack.packb(metadata, unicode_errors='surrogateescape')
        self.id = self.key.id_hash(data)
        self.cache.add_chunk(self.id, data, self.stats)
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
            unpacker.feed(self.key.decrypt(id, chunk))
            for item in unpacker:
                if b'chunks' in item:
                    stats.nfiles += 1
                    add_file_chunks(item[b'chunks'])
        cache.rollback()
        return stats

    def extract_item(self, item, restore_attrs=True, dry_run=False, stdout=False, sparse=False):
        has_damaged_chunks = b'chunks_healthy' in item

        if dry_run or stdout:
            if b'chunks' in item:
                for data in self.pipeline.fetch_many([c[0] for c in item[b'chunks']], is_preloaded=True):
                    if stdout:
                        sys.stdout.buffer.write(data)
                if stdout:
                    sys.stdout.buffer.flush()
            if has_damaged_chunks:
                logger.warning('File %s has damaged (all-zero) chunks. Try running borg check --repair.' %
                               remove_surrogates(item[b'path']))
            return

        dest = self.cwd
        if item[b'path'].startswith('/') or item[b'path'].startswith('..'):
            raise Exception('Path should be relative and local')
        path = os.path.join(dest, item[b'path'])
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
        mode = item[b'mode']
        if stat.S_ISREG(mode):
            if not os.path.exists(os.path.dirname(path)):
                with backup_io():
                    os.makedirs(os.path.dirname(path))
            # Hard link?
            if b'source' in item:
                source = os.path.join(dest, item[b'source'])
                with backup_io():
                    if os.path.exists(path):
                        os.unlink(path)
                    os.link(source, path)
            else:
                with backup_io():
                    fd = open(path, 'wb')
                with fd:
                    ids = [c[0] for c in item[b'chunks']]
                    for data in self.pipeline.fetch_many(ids, is_preloaded=True):
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
                                   remove_surrogates(item[b'path']))
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
                source = item[b'source']
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
                os.mknod(path, item[b'mode'], item[b'rdev'])
                self.restore_attrs(path, item)
            else:
                raise Exception('Unknown archive item type %r' % item[b'mode'])

    def restore_attrs(self, path, item, symlink=False, fd=None):
        """
        Restore filesystem attributes on *path* (*fd*) from *item*.

        Does not access the repository.
        """
        uid = gid = None
        if not self.numeric_owner:
            uid = user2uid(item[b'user'])
            gid = group2gid(item[b'group'])
        uid = item[b'uid'] if uid is None else uid
        gid = item[b'gid'] if gid is None else gid
        # This code is a bit of a mess due to os specific differences
        try:
            if fd:
                os.fchown(fd, uid, gid)
            else:
                os.lchown(path, uid, gid)
        except OSError:
            pass
        if fd:
            os.fchmod(fd, item[b'mode'])
        elif not symlink:
            os.chmod(path, item[b'mode'])
        elif has_lchmod:  # Not available on Linux
            os.lchmod(path, item[b'mode'])
        mtime = bigint_to_int(item[b'mtime'])
        if b'atime' in item:
            atime = bigint_to_int(item[b'atime'])
        else:
            # old archives only had mtime in item metadata
            atime = mtime
        if fd:
            os.utime(fd, None, ns=(atime, mtime))
        else:
            os.utime(path, None, ns=(atime, mtime), follow_symlinks=False)
        acl_set(path, item, self.numeric_owner)
        # Only available on OS X and FreeBSD
        if has_lchflags and b'bsdflags' in item:
            try:
                os.lchflags(path, item[b'bsdflags'])
            except OSError:
                pass
        # chown removes Linux capabilities, so set the extended attributes at the end, after chown, since they include
        # the Linux capabilities in the "security.capability" attribute.
        xattrs = item.get(b'xattrs', {})
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

    def rename(self, name):
        if name in self.manifest.archives:
            raise self.AlreadyExists(name)
        metadata = StableDict(self._load_meta(self.id))
        metadata[b'name'] = name
        data = msgpack.packb(metadata, unicode_errors='surrogateescape')
        new_id = self.key.id_hash(data)
        self.cache.add_chunk(new_id, data, self.stats)
        self.manifest.archives[name] = {'id': new_id, 'time': metadata[b'time']}
        self.cache.chunk_decref(self.id, self.stats)
        del self.manifest.archives[self.name]

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
                unpacker.feed(self.key.decrypt(items_id, data))
                chunk_decref(items_id, stats)
                try:
                    for item in unpacker:
                        if b'chunks' in item:
                            for chunk_id, size, csize in item[b'chunks']:
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
        item = {
            b'mode': st.st_mode,
            b'uid': st.st_uid, b'user': uid2user(st.st_uid),
            b'gid': st.st_gid, b'group': gid2group(st.st_gid),
            b'atime': int_to_bigint(st.st_atime_ns),
            b'ctime': int_to_bigint(st.st_ctime_ns),
            b'mtime': int_to_bigint(st.st_mtime_ns),
        }
        if self.numeric_owner:
            item[b'user'] = item[b'group'] = None
        with backup_io():
            xattrs = xattr.get_all(path, follow_symlinks=False)
        if xattrs:
            item[b'xattrs'] = StableDict(xattrs)
        if has_lchflags and st.st_flags:
            item[b'bsdflags'] = st.st_flags
        with backup_io():
            acl_get(path, item, st, self.numeric_owner)
        return item

    def process_dir(self, path, st):
        item = {b'path': make_path_safe(path)}
        item.update(self.stat_attrs(st, path))
        self.add_item(item)
        return 'd'  # directory

    def process_fifo(self, path, st):
        item = {b'path': make_path_safe(path)}
        item.update(self.stat_attrs(st, path))
        self.add_item(item)
        return 'f'  # fifo

    def process_dev(self, path, st):
        item = {b'path': make_path_safe(path), b'rdev': st.st_rdev}
        item.update(self.stat_attrs(st, path))
        self.add_item(item)
        if stat.S_ISCHR(st.st_mode):
            return 'c'  # char device
        elif stat.S_ISBLK(st.st_mode):
            return 'b'  # block device

    def process_symlink(self, path, st):
        with backup_io():
            source = os.readlink(path)
        item = {b'path': make_path_safe(path), b'source': source}
        item.update(self.stat_attrs(st, path))
        self.add_item(item)
        return 's'  # symlink

    def process_stdin(self, path, cache):
        uid, gid = 0, 0
        fd = sys.stdin.buffer  # binary
        chunks = []
        for chunk in backup_io_iter(self.chunker.chunkify(fd)):
            chunks.append(cache.add_chunk(self.key.id_hash(chunk), chunk, self.stats))
        self.stats.nfiles += 1
        t = int_to_bigint(int(time.time()) * 1000000000)
        item = {
            b'path': path,
            b'chunks': chunks,
            b'mode': 0o100660,  # regular file, ug=rw
            b'uid': uid, b'user': uid2user(uid),
            b'gid': gid, b'group': gid2group(gid),
            b'mtime': t, b'atime': t, b'ctime': t,
        }
        self.add_item(item)
        return 'i'  # stdin

    def process_file(self, path, st, cache, ignore_inode=False):
        status = None
        safe_path = make_path_safe(path)
        # Is it a hard link?
        if st.st_nlink > 1:
            source = self.hard_links.get((st.st_ino, st.st_dev))
            if source is not None:
                item = self.stat_attrs(st, path)
                item.update({b'path': safe_path, b'source': source})
                self.add_item(item)
                status = 'h'  # regular file, hardlink (to already seen inodes)
                return status
            else:
                self.hard_links[st.st_ino, st.st_dev] = safe_path
        is_special_file = is_special(st.st_mode)
        if not is_special_file:
            path_hash = self.key.id_hash(os.path.join(self.cwd, path).encode('utf-8', 'surrogateescape'))
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
        item = {b'path': safe_path}
        # Only chunkify the file if needed
        if chunks is None:
            with backup_io():
                fh = Archive._open_rb(path)
            with os.fdopen(fh, 'rb') as fd:
                chunks = []
                for chunk in backup_io_iter(self.chunker.chunkify(fd, fh)):
                    chunks.append(cache.add_chunk(self.key.id_hash(chunk), chunk, self.stats))
                    if self.show_progress:
                        self.stats.show_progress(item=item, dt=0.2)
            if not is_special_file:
                # we must not memorize special files, because the contents of e.g. a
                # block or char device will change without its mtime/size/inode changing.
                cache.memorize_file(path_hash, st, [c[0] for c in chunks])
            status = status or 'M'  # regular file, modified (if not 'A' already)
        item[b'chunks'] = chunks
        item.update(self.stat_attrs(st, path))
        if is_special_file:
            # we processed a special file like a regular file. reflect that in mode,
            # so it can be extracted / accessed in FUSE mount like a regular file:
            item[b'mode'] = stat.S_IFREG | stat.S_IMODE(item[b'mode'])
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


# this set must be kept complete, otherwise the RobustUnpacker might malfunction:
ITEM_KEYS = frozenset([b'path', b'source', b'rdev', b'chunks', b'chunks_healthy',
                       b'mode', b'user', b'group', b'uid', b'gid', b'mtime', b'atime', b'ctime',
                       b'xattrs', b'bsdflags', b'acl_nfs4', b'acl_access', b'acl_default', b'acl_extended', ])

# this is the set of keys that are always present in items:
REQUIRED_ITEM_KEYS = frozenset([b'path', b'mtime', ])

# this set must be kept complete, otherwise rebuild_manifest might malfunction:
ARCHIVE_KEYS = frozenset([b'version', b'name', b'items', b'cmdline', b'hostname', b'username', b'time', b'time_end', ])

# this is the set of keys that are always present in archives:
REQUIRED_ARCHIVE_KEYS = frozenset([b'version', b'name', b'items', b'cmdline', b'time', ])


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
    class UnpackerCrashed(Exception):
        """raise if unpacker crashed"""

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
        def unpack_next():
            try:
                return next(self._unpacker)
            except (TypeError, ValueError) as err:
                # transform exceptions that might be raised when feeding
                # msgpack with invalid data to a more specific exception
                raise self.UnpackerCrashed(str(err))

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
                    item = unpack_next()
                except (self.UnpackerCrashed, StopIteration):
                    # as long as we are resyncing, we also ignore StopIteration
                    pass
                else:
                    if self.validator(item):
                        self._resync = False
                        return item
                data = data[1:]
        else:
            return unpack_next()


class ArchiveChecker:

    def __init__(self):
        self.error_found = False
        self.possibly_superseded = set()

    def check(self, repository, repair=False, archive=None, last=None, prefix=None, save_space=False):
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
        # due to hash table "resonance".
        # Since reconstruction of archive items can add some new chunks, add 10 % headroom
        capacity = int(len(self.repository) / ChunkIndex.MAX_LOAD_FACTOR * 1.1)
        self.chunks = ChunkIndex(capacity)
        marker = None
        while True:
            result = self.repository.list(limit=10000, marker=marker)
            if not result:
                break
            marker = result[-1]
            for id_ in result:
                self.chunks[id_] = (0, 0, 0)

    def identify_key(self, repository):
        try:
            some_chunkid, _ = next(self.chunks.iteritems())
        except StopIteration:
            # repo is completely empty, no chunks
            return None
        cdata = repository.get(some_chunkid)
        return key_factory(repository, cdata)

    def rebuild_manifest(self):
        """Rebuild the manifest object if it is missing

        Iterates through all objects in the repository looking for archive metadata blocks.
        """
        def valid_archive(obj):
            if not isinstance(obj, dict):
                return False
            keys = set(obj)
            return REQUIRED_ARCHIVE_KEYS.issubset(keys)

        logger.info('Rebuilding missing manifest, this might take some time...')
        # as we have lost the manifest, we do not know any more what valid item keys we had.
        # collecting any key we encounter in a damaged repo seems unwise, thus we just use
        # the hardcoded list from the source code. thus, it is not recommended to rebuild a
        # lost manifest on a older borg version than the most recent one that was ever used
        # within this repository (assuming that newer borg versions support more item keys).
        manifest = Manifest(self.key, self.repository)
        archive_keys_serialized = [msgpack.packb(name) for name in ARCHIVE_KEYS]
        for chunk_id, _ in self.chunks.iteritems():
            cdata = self.repository.get(chunk_id)
            data = self.key.decrypt(chunk_id, cdata)
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
            if self.chunks.get(id_, (0,))[0] == 0:
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
                self.chunks[id_] = 1, size, csize
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
            has_chunks_healthy = b'chunks_healthy' in item
            chunks_current = item[b'chunks']
            chunks_healthy = item[b'chunks_healthy'] if has_chunks_healthy else chunks_current
            assert len(chunks_current) == len(chunks_healthy)
            for chunk_current, chunk_healthy in zip(chunks_current, chunks_healthy):
                chunk_id, size, csize = chunk_healthy
                if chunk_id not in self.chunks:
                    # a chunk of the healthy list is missing
                    if chunk_current == chunk_healthy:
                        logger.error('{}: New missing file chunk detected (Byte {}-{}). '
                                     'Replacing with all-zero chunk.'.format(
                                     item[b'path'].decode('utf-8', 'surrogateescape'), offset, offset + size))
                        self.error_found = chunks_replaced = True
                        data = bytes(size)
                        chunk_id = self.key.id_hash(data)
                        cdata = self.key.encrypt(data)
                        csize = len(cdata)
                        add_reference(chunk_id, size, csize, cdata)
                    else:
                        logger.info('{}: Previously missing file chunk is still missing (Byte {}-{}). '
                                    'It has a all-zero replacement chunk already.'.format(
                                    item[b'path'].decode('utf-8', 'surrogateescape'), offset, offset + size))
                        chunk_id, size, csize = chunk_current
                        add_reference(chunk_id, size, csize)
                else:
                    if chunk_current == chunk_healthy:
                        # normal case, all fine.
                        add_reference(chunk_id, size, csize)
                    else:
                        logger.info('{}: Healed previously missing file chunk! (Byte {}-{}).'.format(
                            item[b'path'].decode('utf-8', 'surrogateescape'), offset, offset + size))
                        add_reference(chunk_id, size, csize)
                        mark_as_possibly_superseded(chunk_current[0])  # maybe orphaned the all-zero replacement chunk
                chunk_list.append([chunk_id, size, csize])  # list-typed element as chunks_healthy is list-of-lists
                offset += size
            if chunks_replaced and not has_chunks_healthy:
                # if this is first repair, remember the correct chunk IDs, so we can maybe heal the file later
                item[b'chunks_healthy'] = item[b'chunks']
            if has_chunks_healthy and chunk_list == chunks_healthy:
                logger.info('{}: Completely healed previously damaged file!'.format(
                            item[b'path'].decode('utf-8', 'surrogateescape')))
                del item[b'chunks_healthy']
            item[b'chunks'] = chunk_list

        def robust_iterator(archive):
            """Iterates through all archive items

            Missing item chunks will be skipped and the msgpack stream will be restarted
            """
            item_keys = self.manifest.item_keys
            unpacker = RobustUnpacker(lambda item: isinstance(item, dict) and b'path' in item, item_keys)
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
                return REQUIRED_ITEM_KEYS.issubset(keys) and keys.issubset(item_keys)

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
                    unpacker.feed(self.key.decrypt(chunk_id, cdata))
                    try:
                        for item in unpacker:
                            if valid_item(item):
                                yield item
                            else:
                                report('Did not get expected metadata dict when unpacking item metadata', chunk_id, i)
                    except RobustUnpacker.UnpackerCrashed as err:
                        report('Unpacker crashed while unpacking item metadata, trying to resync...', chunk_id, i)
                        unpacker.resync()
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
                data = self.key.decrypt(archive_id, cdata)
                archive = StableDict(msgpack.unpackb(data))
                if archive[b'version'] != 1:
                    raise Exception('Unknown archive metadata version')
                decode_dict(archive, (b'name', b'hostname', b'username', b'time', b'time_end'))
                archive[b'cmdline'] = [arg.decode('utf-8', 'surrogateescape') for arg in archive[b'cmdline']]
                items_buffer = ChunkBuffer(self.key)
                items_buffer.write_chunk = add_callback
                for item in robust_iterator(archive):
                    if b'chunks' in item:
                        verify_file_chunks(item)
                    items_buffer.add(item)
                items_buffer.flush(flush=True)
                for previous_item_id in archive[b'items']:
                    mark_as_possibly_superseded(previous_item_id)
                archive[b'items'] = items_buffer.chunks
                data = msgpack.packb(archive, unicode_errors='surrogateescape')
                new_archive_id = self.key.id_hash(data)
                cdata = self.key.encrypt(data)
                add_reference(new_archive_id, len(data), len(cdata), cdata)
                info[b'id'] = new_archive_id

    def orphan_chunks_check(self):
        if self.check_all:
            unused = set()
            for id_, (count, size, csize) in self.chunks.iteritems():
                if count == 0:
                    unused.add(id_)
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

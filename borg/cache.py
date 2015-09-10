from configparser import RawConfigParser
from .remote import cache_if_remote
import errno
import msgpack
import os
import stat
import sys
from binascii import hexlify
import shutil
import tarfile
import tempfile

from .key import PlaintextKey
from .helpers import Error, get_cache_dir, decode_dict, st_mtime_ns, unhexlify, int_to_bigint, \
    bigint_to_int
from .locking import UpgradableLock
from .hashindex import ChunkIndex


class Cache:
    """Client Side cache
    """
    class RepositoryReplay(Error):
        """Cache is newer than repository, refusing to continue"""

    class CacheInitAbortedError(Error):
        """Cache initialization aborted"""

    class RepositoryAccessAborted(Error):
        """Repository access aborted"""

    class EncryptionMethodMismatch(Error):
        """Repository encryption method changed since last acccess, refusing to continue
        """

    def __init__(self, repository, key, manifest, path=None, sync=True, do_files=False, warn_if_unencrypted=True):
        self.lock = None
        self.timestamp = None
        self.lock = None
        self.txn_active = False
        self.repository = repository
        self.key = key
        self.manifest = manifest
        self.path = path or os.path.join(get_cache_dir(), hexlify(repository.id).decode('ascii'))
        self.do_files = do_files
        # Warn user before sending data to a never seen before unencrypted repository
        if not os.path.exists(self.path):
            if warn_if_unencrypted and isinstance(key, PlaintextKey):
                if not self._confirm('Warning: Attempting to access a previously unknown unencrypted repository',
                                     'BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK'):
                    raise self.CacheInitAbortedError()
            self.create()
        self.open()
        # Warn user before sending data to a relocated repository
        if self.previous_location and self.previous_location != repository._location.canonical_path():
            msg = 'Warning: The repository at location {} was previously located at {}'.format(repository._location.canonical_path(), self.previous_location)
            if not self._confirm(msg, 'BORG_RELOCATED_REPO_ACCESS_IS_OK'):
                raise self.RepositoryAccessAborted()

        if sync and self.manifest.id != self.manifest_id:
            # If repository is older than the cache something fishy is going on
            if self.timestamp and self.timestamp > manifest.timestamp:
                raise self.RepositoryReplay()
            # Make sure an encrypted repository has not been swapped for an unencrypted repository
            if self.key_type is not None and self.key_type != str(key.TYPE):
                raise self.EncryptionMethodMismatch()
            self.sync()
            self.commit()

    def __del__(self):
        self.close()

    def _confirm(self, message, env_var_override=None):
        print(message, file=sys.stderr)
        if env_var_override and os.environ.get(env_var_override):
            print("Yes (From {})".format(env_var_override))
            return True
        if not sys.stdin.isatty():
            return False
        try:
            answer = input('Do you want to continue? [yN] ')
        except EOFError:
            return False
        return answer and answer in 'Yy'

    def create(self):
        """Create a new empty cache at `self.path`
        """
        os.makedirs(self.path)
        with open(os.path.join(self.path, 'README'), 'w') as fd:
            fd.write('This is a Borg cache')
        config = RawConfigParser()
        config.add_section('cache')
        config.set('cache', 'version', '1')
        config.set('cache', 'repository', hexlify(self.repository.id).decode('ascii'))
        config.set('cache', 'manifest', '')
        with open(os.path.join(self.path, 'config'), 'w') as fd:
            config.write(fd)
        ChunkIndex().write(os.path.join(self.path, 'chunks').encode('utf-8'))
        os.makedirs(os.path.join(self.path, 'chunks.archive.d'))
        with open(os.path.join(self.path, 'files'), 'wb') as fd:
            pass  # empty file

    def destroy(self):
        """destroy the cache at `self.path`
        """
        self.close()
        os.remove(os.path.join(self.path, 'config'))  # kill config first
        shutil.rmtree(self.path)

    def _do_open(self):
        self.config = RawConfigParser()
        self.config.read(os.path.join(self.path, 'config'))
        if self.config.getint('cache', 'version') != 1:
            raise Exception('%s Does not look like a Borg cache')
        self.id = self.config.get('cache', 'repository')
        self.manifest_id = unhexlify(self.config.get('cache', 'manifest'))
        self.timestamp = self.config.get('cache', 'timestamp', fallback=None)
        self.key_type = self.config.get('cache', 'key_type', fallback=None)
        self.previous_location = self.config.get('cache', 'previous_location', fallback=None)
        self.chunks = ChunkIndex.read(os.path.join(self.path, 'chunks').encode('utf-8'))
        self.files = None

    def open(self):
        if not os.path.isdir(self.path):
            raise Exception('%s Does not look like a Borg cache' % self.path)
        self.lock = UpgradableLock(os.path.join(self.path, 'lock'), exclusive=True).acquire()
        self.rollback()

    def close(self):
        if self.lock:
            self.lock.release()
            self.lock = None

    def _read_files(self):
        self.files = {}
        self._newest_mtime = 0
        with open(os.path.join(self.path, 'files'), 'rb') as fd:
            u = msgpack.Unpacker(use_list=True)
            while True:
                data = fd.read(64 * 1024)
                if not data:
                    break
                u.feed(data)
                for path_hash, item in u:
                    item[0] += 1
                    # in the end, this takes about 240 Bytes per file
                    self.files[path_hash] = msgpack.packb(item)

    def begin_txn(self):
        # Initialize transaction snapshot
        txn_dir = os.path.join(self.path, 'txn.tmp')
        os.mkdir(txn_dir)
        shutil.copy(os.path.join(self.path, 'config'), txn_dir)
        shutil.copy(os.path.join(self.path, 'chunks'), txn_dir)
        shutil.copy(os.path.join(self.path, 'files'), txn_dir)
        os.rename(os.path.join(self.path, 'txn.tmp'),
                  os.path.join(self.path, 'txn.active'))
        self.txn_active = True

    def commit(self):
        """Commit transaction
        """
        if not self.txn_active:
            return
        if self.files is not None:
            with open(os.path.join(self.path, 'files'), 'wb') as fd:
                for path_hash, item in self.files.items():
                    # Discard cached files with the newest mtime to avoid
                    # issues with filesystem snapshots and mtime precision
                    item = msgpack.unpackb(item)
                    if item[0] < 10 and bigint_to_int(item[3]) < self._newest_mtime:
                        msgpack.pack((path_hash, item), fd)
        self.config.set('cache', 'manifest', hexlify(self.manifest.id).decode('ascii'))
        self.config.set('cache', 'timestamp', self.manifest.timestamp)
        self.config.set('cache', 'key_type', str(self.key.TYPE))
        self.config.set('cache', 'previous_location', self.repository._location.canonical_path())
        with open(os.path.join(self.path, 'config'), 'w') as fd:
            self.config.write(fd)
        self.chunks.write(os.path.join(self.path, 'chunks').encode('utf-8'))
        os.rename(os.path.join(self.path, 'txn.active'),
                  os.path.join(self.path, 'txn.tmp'))
        shutil.rmtree(os.path.join(self.path, 'txn.tmp'))
        self.txn_active = False

    def rollback(self):
        """Roll back partial and aborted transactions
        """
        # Remove partial transaction
        if os.path.exists(os.path.join(self.path, 'txn.tmp')):
            shutil.rmtree(os.path.join(self.path, 'txn.tmp'))
        # Roll back active transaction
        txn_dir = os.path.join(self.path, 'txn.active')
        if os.path.exists(txn_dir):
            shutil.copy(os.path.join(txn_dir, 'config'), self.path)
            shutil.copy(os.path.join(txn_dir, 'chunks'), self.path)
            shutil.copy(os.path.join(txn_dir, 'files'), self.path)
            os.rename(txn_dir, os.path.join(self.path, 'txn.tmp'))
            if os.path.exists(os.path.join(self.path, 'txn.tmp')):
                shutil.rmtree(os.path.join(self.path, 'txn.tmp'))
        self.txn_active = False
        self._do_open()

    def sync(self):
        """Re-synchronize chunks cache with repository.

        Maintains a directory with known backup archive indexes, so it only
        needs to fetch infos from repo and build a chunk index once per backup
        archive.
        If out of sync, missing archive indexes get added, outdated indexes
        get removed and a new master chunks index is built by merging all
        archive indexes.
        """
        archive_path = os.path.join(self.path, 'chunks.archive.d')

        def mkpath(id, suffix=''):
            id_hex = hexlify(id).decode('ascii')
            path = os.path.join(archive_path, id_hex + suffix)
            return path.encode('utf-8')

        def cached_archives():
            fns = os.listdir(archive_path)
            # filenames with 64 hex digits == 256bit
            return set(unhexlify(fn) for fn in fns if len(fn) == 64)

        def repo_archives():
            return set(info[b'id'] for info in self.manifest.archives.values())

        def cleanup_outdated(ids):
            for id in ids:
                os.unlink(mkpath(id))

        def add(chunk_idx, id, size, csize, incr=1):
            try:
                count, size, csize = chunk_idx[id]
                chunk_idx[id] = count + incr, size, csize
            except KeyError:
                chunk_idx[id] = incr, size, csize

        def fetch_and_build_idx(archive_id, repository, key):
            chunk_idx = ChunkIndex()
            cdata = repository.get(archive_id)
            data = key.decrypt(archive_id, cdata)
            add(chunk_idx, archive_id, len(data), len(cdata))
            archive = msgpack.unpackb(data)
            if archive[b'version'] != 1:
                raise Exception('Unknown archive metadata version')
            decode_dict(archive, (b'name',))
            unpacker = msgpack.Unpacker()
            for item_id, chunk in zip(archive[b'items'], repository.get_many(archive[b'items'])):
                data = key.decrypt(item_id, chunk)
                add(chunk_idx, item_id, len(data), len(chunk))
                unpacker.feed(data)
                for item in unpacker:
                    if not isinstance(item, dict):
                        print('Error: Did not get expected metadata dict - archive corrupted!')
                        continue
                    if b'chunks' in item:
                        for chunk_id, size, csize in item[b'chunks']:
                            add(chunk_idx, chunk_id, size, csize)
            fn = mkpath(archive_id)
            fn_tmp = mkpath(archive_id, suffix='.tmp')
            try:
                chunk_idx.write(fn_tmp)
            except Exception:
                os.unlink(fn_tmp)
            else:
                os.rename(fn_tmp, fn)
            return chunk_idx

        def lookup_name(archive_id):
            for name, info in self.manifest.archives.items():
                if info[b'id'] == archive_id:
                    return name

        def create_master_idx(chunk_idx):
            print('Synchronizing chunks cache...')
            cached_ids = cached_archives()
            archive_ids = repo_archives()
            print('Archives: %d, w/ cached Idx: %d, w/ outdated Idx: %d, w/o cached Idx: %d.' % (
                len(archive_ids), len(cached_ids),
                len(cached_ids - archive_ids), len(archive_ids - cached_ids), ))
            # deallocates old hashindex, creates empty hashindex:
            chunk_idx.clear()
            cleanup_outdated(cached_ids - archive_ids)
            if archive_ids:
                chunk_idx = None
                for archive_id in archive_ids:
                    archive_name = lookup_name(archive_id)
                    if archive_id in cached_ids:
                        archive_chunk_idx_path = mkpath(archive_id)
                        print("Reading cached archive chunk index for %s ..." % archive_name)
                        archive_chunk_idx = ChunkIndex.read(archive_chunk_idx_path)
                    else:
                        print('Fetching and building archive index for %s ...' % archive_name)
                        archive_chunk_idx = fetch_and_build_idx(archive_id, repository, self.key)
                    print("Merging into master chunks index ...")
                    if chunk_idx is None:
                        # we just use the first archive's idx as starting point,
                        # to avoid growing the hash table from 0 size and also
                        # to save 1 merge call.
                        chunk_idx = archive_chunk_idx
                    else:
                        chunk_idx.merge(archive_chunk_idx)
            print('Done.')
            return chunk_idx

        def legacy_cleanup():
            """bring old cache dirs into the desired state (cleanup and adapt)"""
            try:
                os.unlink(os.path.join(self.path, 'chunks.archive'))
            except:
                pass
            try:
                os.unlink(os.path.join(self.path, 'chunks.archive.tmp'))
            except:
                pass
            try:
                os.mkdir(archive_path)
            except:
                pass

        self.begin_txn()
        repository = cache_if_remote(self.repository)
        legacy_cleanup()
        self.chunks = create_master_idx(self.chunks)

    def add_chunk(self, id, data, stats):
        if not self.txn_active:
            self.begin_txn()
        size = len(data)
        if self.seen_chunk(id, size):
            return self.chunk_incref(id, stats)
        data = self.key.encrypt(data)
        csize = len(data)
        self.repository.put(id, data, wait=False)
        self.chunks[id] = (1, size, csize)
        stats.update(size, csize, True)
        return id, size, csize

    def seen_chunk(self, id, size=None):
        refcount, stored_size, _ = self.chunks.get(id, (0, None, None))
        if size is not None and stored_size is not None and size != stored_size:
            # we already have a chunk with that id, but different size.
            # this is either a hash collision (unlikely) or corruption or a bug.
            raise Exception("chunk has same id [%r], but different size (stored: %d new: %d)!" % (
                            id, stored_size, size))
        return refcount

    def chunk_incref(self, id, stats):
        if not self.txn_active:
            self.begin_txn()
        count, size, csize = self.chunks[id]
        self.chunks[id] = (count + 1, size, csize)
        stats.update(size, csize, False)
        return id, size, csize

    def chunk_decref(self, id, stats):
        if not self.txn_active:
            self.begin_txn()
        count, size, csize = self.chunks[id]
        if count == 1:
            del self.chunks[id]
            self.repository.delete(id, wait=False)
            stats.update(-size, -csize, True)
        else:
            self.chunks[id] = (count - 1, size, csize)
            stats.update(-size, -csize, False)

    def file_known_and_unchanged(self, path_hash, st):
        if not (self.do_files and stat.S_ISREG(st.st_mode)):
            return None
        if self.files is None:
            self._read_files()
        entry = self.files.get(path_hash)
        if not entry:
            return None
        entry = msgpack.unpackb(entry)
        if entry[2] == st.st_size and bigint_to_int(entry[3]) == st_mtime_ns(st) and entry[1] == st.st_ino:
            # reset entry age
            entry[0] = 0
            self.files[path_hash] = msgpack.packb(entry)
            return entry[4]
        else:
            return None

    def memorize_file(self, path_hash, st, ids):
        if not (self.do_files and stat.S_ISREG(st.st_mode)):
            return
        # Entry: Age, inode, size, mtime, chunk ids
        mtime_ns = st_mtime_ns(st)
        self.files[path_hash] = msgpack.packb((0, st.st_ino, st.st_size, int_to_bigint(mtime_ns), ids))
        self._newest_mtime = max(self._newest_mtime, mtime_ns)

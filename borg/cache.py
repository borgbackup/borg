import configparser
from .remote import cache_if_remote
from collections import namedtuple
import os
import stat
from binascii import unhexlify
import shutil

from .key import PlaintextKey
from .logger import create_logger
logger = create_logger()
from .helpers import Error, get_cache_dir, decode_dict, int_to_bigint, \
    bigint_to_int, format_file_size, yes, bin_to_hex
from .locking import Lock
from .hashindex import ChunkIndex

import msgpack


class Cache:
    """Client Side cache
    """
    class RepositoryIDNotUnique(Error):
        """Cache is newer than repository - do you have multiple, independently updated repos with same ID?"""

    class RepositoryReplay(Error):
        """Cache is newer than repository - this is either an attack or unsafe (multiple repos with same ID)"""

    class CacheInitAbortedError(Error):
        """Cache initialization aborted"""

    class RepositoryAccessAborted(Error):
        """Repository access aborted"""

    class EncryptionMethodMismatch(Error):
        """Repository encryption method changed since last access, refusing to continue"""

    @staticmethod
    def break_lock(repository, path=None):
        path = path or os.path.join(get_cache_dir(), bin_to_hex(repository.id))
        Lock(os.path.join(path, 'lock'), exclusive=True).break_lock()

    @staticmethod
    def destroy(repository, path=None):
        """destroy the cache for ``repository`` or at ``path``"""
        path = path or os.path.join(get_cache_dir(), bin_to_hex(repository.id))
        config = os.path.join(path, 'config')
        if os.path.exists(config):
            os.remove(config)  # kill config first
            shutil.rmtree(path)

    def __init__(self, repository, key, manifest, path=None, sync=True, do_files=False, warn_if_unencrypted=True,
                 lock_wait=None):
        self.lock = None
        self.timestamp = None
        self.lock = None
        self.txn_active = False
        self.repository = repository
        self.key = key
        self.manifest = manifest
        self.path = path or os.path.join(get_cache_dir(), bin_to_hex(repository.id))
        self.do_files = do_files
        # Warn user before sending data to a never seen before unencrypted repository
        if not os.path.exists(self.path):
            if warn_if_unencrypted and isinstance(key, PlaintextKey):
                msg = ("Warning: Attempting to access a previously unknown unencrypted repository!" +
                       "\n" +
                       "Do you want to continue? [yN] ")
                if not yes(msg, false_msg="Aborting.", invalid_msg="Invalid answer, aborting.",
                           retry=False, env_var_override='BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK'):
                    raise self.CacheInitAbortedError()
            self.create()
        self.open(lock_wait=lock_wait)
        try:
            # Warn user before sending data to a relocated repository
            if self.previous_location and self.previous_location != repository._location.canonical_path():
                msg = ("Warning: The repository at location {} was previously located at {}".format(repository._location.canonical_path(), self.previous_location) +
                       "\n" +
                       "Do you want to continue? [yN] ")
                if not yes(msg, false_msg="Aborting.", invalid_msg="Invalid answer, aborting.",
                           retry=False, env_var_override='BORG_RELOCATED_REPO_ACCESS_IS_OK'):
                    raise self.RepositoryAccessAborted()
                # adapt on-disk config immediately if the new location was accepted
                self.begin_txn()
                self.commit()

            if sync and self.manifest.id != self.manifest_id:
                # If repository is older than the cache something fishy is going on
                if self.timestamp and self.timestamp > manifest.timestamp:
                    if isinstance(key, PlaintextKey):
                        raise self.RepositoryIDNotUnique()
                    else:
                        raise self.RepositoryReplay()
                # Make sure an encrypted repository has not been swapped for an unencrypted repository
                if self.key_type is not None and self.key_type != str(key.TYPE):
                    raise self.EncryptionMethodMismatch()
                self.sync()
                self.commit()
        except:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __str__(self):
        fmt = """\
All archives:   {0.total_size:>20s} {0.total_csize:>20s} {0.unique_csize:>20s}

                       Unique chunks         Total chunks
Chunk index:    {0.total_unique_chunks:20d} {0.total_chunks:20d}"""
        return fmt.format(self.format_tuple())

    def format_tuple(self):
        # XXX: this should really be moved down to `hashindex.pyx`
        Summary = namedtuple('Summary', ['total_size', 'total_csize', 'unique_size', 'unique_csize', 'total_unique_chunks', 'total_chunks'])
        stats = Summary(*self.chunks.summarize())._asdict()
        for field in ['total_size', 'total_csize', 'unique_csize']:
            stats[field] = format_file_size(stats[field])
        return Summary(**stats)

    def create(self):
        """Create a new empty cache at `self.path`
        """
        os.makedirs(self.path)
        with open(os.path.join(self.path, 'README'), 'w') as fd:
            fd.write('This is a Borg cache')
        config = configparser.ConfigParser(interpolation=None)
        config.add_section('cache')
        config.set('cache', 'version', '1')
        config.set('cache', 'repository', bin_to_hex(self.repository.id))
        config.set('cache', 'manifest', '')
        with open(os.path.join(self.path, 'config'), 'w') as fd:
            config.write(fd)
        ChunkIndex().write(os.path.join(self.path, 'chunks').encode('utf-8'))
        os.makedirs(os.path.join(self.path, 'chunks.archive.d'))
        with open(os.path.join(self.path, 'files'), 'wb') as fd:
            pass  # empty file

    def _do_open(self):
        self.config = configparser.ConfigParser(interpolation=None)
        config_path = os.path.join(self.path, 'config')
        self.config.read(config_path)
        try:
            cache_version = self.config.getint('cache', 'version')
            wanted_version = 1
            if cache_version != wanted_version:
                self.close()
                raise Exception('%s has unexpected cache version %d (wanted: %d).' % (
                    config_path, cache_version, wanted_version))
        except configparser.NoSectionError:
            self.close()
            raise Exception('%s does not look like a Borg cache.' % config_path) from None
        self.id = self.config.get('cache', 'repository')
        self.manifest_id = unhexlify(self.config.get('cache', 'manifest'))
        self.timestamp = self.config.get('cache', 'timestamp', fallback=None)
        self.key_type = self.config.get('cache', 'key_type', fallback=None)
        self.previous_location = self.config.get('cache', 'previous_location', fallback=None)
        self.chunks = ChunkIndex.read(os.path.join(self.path, 'chunks').encode('utf-8'))
        self.files = None

    def open(self, lock_wait=None):
        if not os.path.isdir(self.path):
            raise Exception('%s Does not look like a Borg cache' % self.path)
        self.lock = Lock(os.path.join(self.path, 'lock'), exclusive=True, timeout=lock_wait).acquire()
        self.rollback()

    def close(self):
        if self.lock is not None:
            self.lock.release()
            self.lock = None

    def _read_files(self):
        self.files = {}
        self._newest_mtime = 0
        logger.debug('Reading files cache ...')
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
            ttl = int(os.environ.get('BORG_FILES_CACHE_TTL', 20))
            with open(os.path.join(self.path, 'files'), 'wb') as fd:
                for path_hash, item in self.files.items():
                    # Only keep files seen in this backup that are older than newest mtime seen in this backup -
                    # this is to avoid issues with filesystem snapshots and mtime granularity.
                    # Also keep files from older backups that have not reached BORG_FILES_CACHE_TTL yet.
                    item = msgpack.unpackb(item)
                    age = item[0]
                    if age == 0 and bigint_to_int(item[3]) < self._newest_mtime or \
                       age > 0 and age < ttl:
                        msgpack.pack((path_hash, item), fd)
        self.config.set('cache', 'manifest', bin_to_hex(self.manifest.id))
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
            id_hex = bin_to_hex(id)
            path = os.path.join(archive_path, id_hex + suffix)
            return path.encode('utf-8')

        def cached_archives():
            if self.do_cache:
                fns = os.listdir(archive_path)
                # filenames with 64 hex digits == 256bit
                return set(unhexlify(fn) for fn in fns if len(fn) == 64)
            else:
                return set()

        def repo_archives():
            return set(info[b'id'] for info in self.manifest.archives.values())

        def cleanup_outdated(ids):
            for id in ids:
                os.unlink(mkpath(id))

        def fetch_and_build_idx(archive_id, repository, key):
            chunk_idx = ChunkIndex()
            cdata = repository.get(archive_id)
            data = key.decrypt(archive_id, cdata)
            chunk_idx.add(archive_id, 1, len(data), len(cdata))
            archive = msgpack.unpackb(data)
            if archive[b'version'] != 1:
                raise Exception('Unknown archive metadata version')
            decode_dict(archive, (b'name',))
            unpacker = msgpack.Unpacker()
            for item_id, chunk in zip(archive[b'items'], repository.get_many(archive[b'items'])):
                data = key.decrypt(item_id, chunk)
                chunk_idx.add(item_id, 1, len(data), len(chunk))
                unpacker.feed(data)
                for item in unpacker:
                    if not isinstance(item, dict):
                        logger.error('Error: Did not get expected metadata dict - archive corrupted!')
                        continue
                    if b'chunks' in item:
                        for chunk_id, size, csize in item[b'chunks']:
                            chunk_idx.add(chunk_id, 1, size, csize)
            if self.do_cache:
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
            logger.info('Synchronizing chunks cache...')
            cached_ids = cached_archives()
            archive_ids = repo_archives()
            logger.info('Archives: %d, w/ cached Idx: %d, w/ outdated Idx: %d, w/o cached Idx: %d.' % (
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
                        logger.info("Reading cached archive chunk index for %s ..." % archive_name)
                        archive_chunk_idx = ChunkIndex.read(archive_chunk_idx_path)
                    else:
                        logger.info('Fetching and building archive index for %s ...' % archive_name)
                        archive_chunk_idx = fetch_and_build_idx(archive_id, repository, self.key)
                    logger.info("Merging into master chunks index ...")
                    if chunk_idx is None:
                        # we just use the first archive's idx as starting point,
                        # to avoid growing the hash table from 0 size and also
                        # to save 1 merge call.
                        chunk_idx = archive_chunk_idx
                    else:
                        chunk_idx.merge(archive_chunk_idx)
            logger.info('Done.')
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
        with cache_if_remote(self.repository) as repository:
            legacy_cleanup()
            # TEMPORARY HACK: to avoid archive index caching, create a FILE named ~/.cache/borg/REPOID/chunks.archive.d -
            # this is only recommended if you have a fast, low latency connection to your repo (e.g. if repo is local disk)
            self.do_cache = os.path.isdir(archive_path)
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
        count, size, csize = self.chunks.incref(id)
        stats.update(size, csize, False)
        return id, size, csize

    def chunk_decref(self, id, stats):
        if not self.txn_active:
            self.begin_txn()
        count, size, csize = self.chunks.decref(id)
        if count == 0:
            del self.chunks[id]
            self.repository.delete(id, wait=False)
            stats.update(-size, -csize, True)
        else:
            stats.update(-size, -csize, False)

    def file_known_and_unchanged(self, path_hash, st, ignore_inode=False):
        if not (self.do_files and stat.S_ISREG(st.st_mode)):
            return None
        if self.files is None:
            self._read_files()
        entry = self.files.get(path_hash)
        if not entry:
            return None
        entry = msgpack.unpackb(entry)
        if (entry[2] == st.st_size and bigint_to_int(entry[3]) == st.st_mtime_ns and
                (ignore_inode or entry[1] == st.st_ino)):
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
        mtime_ns = st.st_mtime_ns
        self.files[path_hash] = msgpack.packb((0, st.st_ino, st.st_size, int_to_bigint(mtime_ns), ids))
        self._newest_mtime = max(self._newest_mtime, mtime_ns)

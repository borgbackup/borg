import configparser
import os
import stat
import shutil
from binascii import unhexlify
from collections import namedtuple

import msgpack

from .logger import create_logger
logger = create_logger()

from .constants import CACHE_README
from .hashindex import ChunkIndex, ChunkIndexEntry
from .helpers import Location
from .helpers import Error
from .helpers import get_cache_dir, get_security_dir
from .helpers import bin_to_hex
from .helpers import format_file_size
from .helpers import yes
from .helpers import remove_surrogates
from .helpers import ProgressIndicatorPercent, ProgressIndicatorMessage
from .item import Item, ArchiveItem
from .key import PlaintextKey
from .locking import Lock
from .platform import SaveFile
from .remote import cache_if_remote

ChunkListEntry = namedtuple('ChunkListEntry', 'id size csize')
FileCacheEntry = namedtuple('FileCacheEntry', 'age inode size mtime chunk_ids')


class SecurityManager:
    def __init__(self, repository):
        self.repository = repository
        self.dir = get_security_dir(repository.id_str)
        self.key_type_file = os.path.join(self.dir, 'key-type')
        self.location_file = os.path.join(self.dir, 'location')
        self.manifest_ts_file = os.path.join(self.dir, 'manifest-timestamp')

    def known(self):
        return os.path.exists(self.key_type_file)

    def key_matches(self, key):
        if not self.known():
            return False
        try:
            with open(self.key_type_file, 'r') as fd:
                type = fd.read()
                return type == str(key.TYPE)
        except OSError as exc:
            logger.warning('Could not read/parse key type file: %s', exc)

    def save(self, manifest, key, cache):
        logger.debug('security: saving state for %s to %s', self.repository.id_str, self.dir)
        current_location = cache.repository._location.canonical_path()
        logger.debug('security: current location   %s', current_location)
        logger.debug('security: key type           %s', str(key.TYPE))
        logger.debug('security: manifest timestamp %s', manifest.timestamp)
        with open(self.location_file, 'w') as fd:
            fd.write(current_location)
        with open(self.key_type_file, 'w') as fd:
            fd.write(str(key.TYPE))
        with open(self.manifest_ts_file, 'w') as fd:
            fd.write(manifest.timestamp)

    def assert_location_matches(self, cache):
        # Warn user before sending data to a relocated repository
        try:
            with open(self.location_file) as fd:
                previous_location = fd.read()
            logger.debug('security: read previous_location %r', previous_location)
        except FileNotFoundError:
            logger.debug('security: previous_location file %s not found', self.location_file)
            previous_location = None
        except OSError as exc:
            logger.warning('Could not read previous location file: %s', exc)
            previous_location = None
        if cache.previous_location and previous_location != cache.previous_location:
            # Reconcile cache and security dir; we take the cache location.
            previous_location = cache.previous_location
            logger.debug('security: using previous_location of cache: %r', previous_location)
        if previous_location and previous_location != self.repository._location.canonical_path():
            msg = ("Warning: The repository at location {} was previously located at {}\n".format(
                self.repository._location.canonical_path(), previous_location) +
                "Do you want to continue? [yN] ")
            if not yes(msg, false_msg="Aborting.", invalid_msg="Invalid answer, aborting.",
                       retry=False, env_var_override='BORG_RELOCATED_REPO_ACCESS_IS_OK'):
                raise Cache.RepositoryAccessAborted()
            # adapt on-disk config immediately if the new location was accepted
            logger.debug('security: updating location stored in cache and security dir')
            with open(self.location_file, 'w') as fd:
                fd.write(cache.repository._location.canonical_path())
            cache.begin_txn()
            cache.commit()

    def assert_no_manifest_replay(self, manifest, key, cache):
        try:
            with open(self.manifest_ts_file) as fd:
                timestamp = fd.read()
            logger.debug('security: read manifest timestamp %r', timestamp)
        except FileNotFoundError:
            logger.debug('security: manifest timestamp file %s not found', self.manifest_ts_file)
            timestamp = ''
        except OSError as exc:
            logger.warning('Could not read previous location file: %s', exc)
            timestamp = ''
        timestamp = max(timestamp, cache.timestamp or '')
        logger.debug('security: determined newest manifest timestamp as %s', timestamp)
        # If repository is older than the cache or security dir something fishy is going on
        if timestamp and timestamp > manifest.timestamp:
            if isinstance(key, PlaintextKey):
                raise Cache.RepositoryIDNotUnique()
            else:
                raise Cache.RepositoryReplay()

    def assert_key_type(self, key, cache):
        # Make sure an encrypted repository has not been swapped for an unencrypted repository
        if cache.key_type is not None and cache.key_type != str(key.TYPE):
            raise Cache.EncryptionMethodMismatch()
        if self.known() and not self.key_matches(key):
            raise Cache.EncryptionMethodMismatch()

    def assert_secure(self, manifest, key, cache):
        self.assert_location_matches(cache)
        self.assert_key_type(key, cache)
        self.assert_no_manifest_replay(manifest, key, cache)
        if not self.known():
            self.save(manifest, key, cache)

    def assert_access_unknown(self, warn_if_unencrypted, key):
        if warn_if_unencrypted and isinstance(key, PlaintextKey) and not self.known():
            msg = ("Warning: Attempting to access a previously unknown unencrypted repository!\n" +
                   "Do you want to continue? [yN] ")
            if not yes(msg, false_msg="Aborting.", invalid_msg="Invalid answer, aborting.",
                       retry=False, env_var_override='BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK'):
                raise Cache.CacheInitAbortedError()


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
        path = path or os.path.join(get_cache_dir(), repository.id_str)
        Lock(os.path.join(path, 'lock'), exclusive=True).break_lock()

    @staticmethod
    def destroy(repository, path=None):
        """destroy the cache for ``repository`` or at ``path``"""
        path = path or os.path.join(get_cache_dir(), repository.id_str)
        config = os.path.join(path, 'config')
        if os.path.exists(config):
            os.remove(config)  # kill config first
            shutil.rmtree(path)

    def __init__(self, repository, key, manifest, path=None, sync=True, do_files=False, warn_if_unencrypted=True,
                 progress=False, lock_wait=None):
        """
        :param do_files: use file metadata cache
        :param warn_if_unencrypted: print warning if accessing unknown unencrypted repository
        :param lock_wait: timeout for lock acquisition (None: return immediately if lock unavailable)
        :param sync: do :meth:`.sync`
        """
        self.lock = None
        self.timestamp = None
        self.lock = None
        self.txn_active = False
        self.repository = repository
        self.key = key
        self.manifest = manifest
        self.progress = progress
        self.path = path or os.path.join(get_cache_dir(), repository.id_str)
        self.security_manager = SecurityManager(repository)
        self.hostname_is_unique = yes(env_var_override='BORG_HOSTNAME_IS_UNIQUE', prompt=False, env_msg=None)
        if self.hostname_is_unique:
            logger.info('Enabled removal of stale cache locks')
        self.do_files = do_files
        # Warn user before sending data to a never seen before unencrypted repository
        if not os.path.exists(self.path):
            self.security_manager.assert_access_unknown(warn_if_unencrypted, key)
            self.create()
        self.open(lock_wait=lock_wait)
        try:
            self.security_manager.assert_secure(manifest, key, self)
            if sync and self.manifest.id != self.manifest_id:
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

    def chunks_stored_size(self):
        Summary = namedtuple('Summary', ['total_size', 'total_csize', 'unique_size', 'unique_csize', 'total_unique_chunks', 'total_chunks'])
        stats = Summary(*self.chunks.summarize())
        return stats.unique_csize

    def create(self):
        """Create a new empty cache at `self.path`
        """
        os.makedirs(self.path)
        with open(os.path.join(self.path, 'README'), 'w') as fd:
            fd.write(CACHE_README)
        config = configparser.ConfigParser(interpolation=None)
        config.add_section('cache')
        config.set('cache', 'version', '1')
        config.set('cache', 'repository', self.repository.id_str)
        config.set('cache', 'manifest', '')
        with SaveFile(os.path.join(self.path, 'config')) as fd:
            config.write(fd)
        ChunkIndex().write(os.path.join(self.path, 'chunks').encode('utf-8'))
        os.makedirs(os.path.join(self.path, 'chunks.archive.d'))
        with SaveFile(os.path.join(self.path, 'files'), binary=True) as fd:
            pass  # empty file

    def _check_upgrade(self, config_path):
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
        # borg < 1.0.8rc1 had different canonicalization for the repo location (see #1655 and #1741).
        cache_loc = self.config.get('cache', 'previous_location', fallback=None)
        if cache_loc:
            repo_loc = self.repository._location.canonical_path()
            rl = Location(repo_loc)
            cl = Location(cache_loc)
            if cl.proto == rl.proto and cl.user == rl.user and cl.host == rl.host and cl.port == rl.port \
                    and \
                    cl.path and rl.path and \
                    cl.path.startswith('/~/') and rl.path.startswith('/./') and cl.path[3:] == rl.path[3:]:
                # everything is same except the expected change in relative path canonicalization,
                # update previous_location to avoid warning / user query about changed location:
                self.config.set('cache', 'previous_location', repo_loc)

    def _do_open(self):
        self.config = configparser.ConfigParser(interpolation=None)
        config_path = os.path.join(self.path, 'config')
        self.config.read(config_path)
        self._check_upgrade(config_path)
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
        self.lock = Lock(os.path.join(self.path, 'lock'), exclusive=True, timeout=lock_wait, kill_stale_locks=self.hostname_is_unique).acquire()
        self.rollback()

    def close(self):
        if self.lock is not None:
            self.lock.release()
            self.lock = None

    def _read_files(self):
        self.files = {}
        self._newest_mtime = None
        logger.debug('Reading files cache ...')
        with open(os.path.join(self.path, 'files'), 'rb') as fd:
            u = msgpack.Unpacker(use_list=True)
            while True:
                data = fd.read(64 * 1024)
                if not data:
                    break
                u.feed(data)
                for path_hash, item in u:
                    entry = FileCacheEntry(*item)
                    # in the end, this takes about 240 Bytes per file
                    self.files[path_hash] = msgpack.packb(entry._replace(age=entry.age + 1))

    def begin_txn(self):
        # Initialize transaction snapshot
        pi = ProgressIndicatorMessage()
        txn_dir = os.path.join(self.path, 'txn.tmp')
        os.mkdir(txn_dir)
        pi.output('Initializing cache transaction: Reading config')
        shutil.copy(os.path.join(self.path, 'config'), txn_dir)
        pi.output('Initializing cache transaction: Reading chunks')
        shutil.copy(os.path.join(self.path, 'chunks'), txn_dir)
        pi.output('Initializing cache transaction: Reading files')
        shutil.copy(os.path.join(self.path, 'files'), txn_dir)
        os.rename(os.path.join(self.path, 'txn.tmp'),
                  os.path.join(self.path, 'txn.active'))
        self.txn_active = True
        pi.finish()

    def commit(self):
        """Commit transaction
        """
        if not self.txn_active:
            return
        self.security_manager.save(self.manifest, self.key, self)
        pi = ProgressIndicatorMessage()
        if self.files is not None:
            if self._newest_mtime is None:
                # was never set because no files were modified/added
                self._newest_mtime = 2 ** 63 - 1  # nanoseconds, good until y2262
            ttl = int(os.environ.get('BORG_FILES_CACHE_TTL', 20))
            pi.output('Saving files cache')
            with SaveFile(os.path.join(self.path, 'files'), binary=True) as fd:
                for path_hash, item in self.files.items():
                    # Only keep files seen in this backup that are older than newest mtime seen in this backup -
                    # this is to avoid issues with filesystem snapshots and mtime granularity.
                    # Also keep files from older backups that have not reached BORG_FILES_CACHE_TTL yet.
                    entry = FileCacheEntry(*msgpack.unpackb(item))
                    if entry.age == 0 and entry.mtime < self._newest_mtime or \
                       entry.age > 0 and entry.age < ttl:
                        msgpack.pack((path_hash, entry), fd)
        pi.output('Saving cache config')
        self.config.set('cache', 'manifest', self.manifest.id_str)
        self.config.set('cache', 'timestamp', self.manifest.timestamp)
        self.config.set('cache', 'key_type', str(self.key.TYPE))
        self.config.set('cache', 'previous_location', self.repository._location.canonical_path())
        with SaveFile(os.path.join(self.path, 'config')) as fd:
            self.config.write(fd)
        pi.output('Saving chunks cache')
        self.chunks.write(os.path.join(self.path, 'chunks').encode('utf-8'))
        os.rename(os.path.join(self.path, 'txn.active'),
                  os.path.join(self.path, 'txn.tmp'))
        shutil.rmtree(os.path.join(self.path, 'txn.tmp'))
        self.txn_active = False
        pi.finish()

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
            return set(info.id for info in self.manifest.archives.list())

        def cleanup_outdated(ids):
            for id in ids:
                os.unlink(mkpath(id))

        def fetch_and_build_idx(archive_id, repository, key, chunk_idx):
            cdata = repository.get(archive_id)
            _, data = key.decrypt(archive_id, cdata)
            chunk_idx.add(archive_id, 1, len(data), len(cdata))
            archive = ArchiveItem(internal_dict=msgpack.unpackb(data))
            if archive.version != 1:
                raise Exception('Unknown archive metadata version')
            unpacker = msgpack.Unpacker()
            for item_id, chunk in zip(archive.items, repository.get_many(archive.items)):
                _, data = key.decrypt(item_id, chunk)
                chunk_idx.add(item_id, 1, len(data), len(chunk))
                unpacker.feed(data)
                for item in unpacker:
                    if not isinstance(item, dict):
                        logger.error('Error: Did not get expected metadata dict - archive corrupted!')
                        continue
                    for chunk_id, size, csize in item.get(b'chunks', []):
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

        def lookup_name(archive_id):
            for info in self.manifest.archives.list():
                if info.id == archive_id:
                    return info.name

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
                if self.progress:
                    pi = ProgressIndicatorPercent(total=len(archive_ids), step=0.1,
                                                  msg='%3.0f%% Syncing chunks cache. Processing archive %s')
                for archive_id in archive_ids:
                    archive_name = lookup_name(archive_id)
                    if self.progress:
                        pi.show(info=[remove_surrogates(archive_name)])
                    if self.do_cache:
                        if archive_id in cached_ids:
                            archive_chunk_idx_path = mkpath(archive_id)
                            logger.info("Reading cached archive chunk index for %s ..." % archive_name)
                            archive_chunk_idx = ChunkIndex.read(archive_chunk_idx_path)
                        else:
                            logger.info('Fetching and building archive index for %s ...' % archive_name)
                            archive_chunk_idx = ChunkIndex()
                            fetch_and_build_idx(archive_id, repository, self.key, archive_chunk_idx)
                        logger.info("Merging into master chunks index ...")
                        if chunk_idx is None:
                            # we just use the first archive's idx as starting point,
                            # to avoid growing the hash table from 0 size and also
                            # to save 1 merge call.
                            chunk_idx = archive_chunk_idx
                        else:
                            chunk_idx.merge(archive_chunk_idx)
                    else:
                        chunk_idx = chunk_idx or ChunkIndex()
                        logger.info('Fetching archive index for %s ...' % archive_name)
                        fetch_and_build_idx(archive_id, repository, self.key, chunk_idx)
                if self.progress:
                    pi.finish()
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

    def add_chunk(self, id, chunk, stats, overwrite=False):
        if not self.txn_active:
            self.begin_txn()
        size = len(chunk.data)
        refcount = self.seen_chunk(id, size)
        if refcount and not overwrite:
            return self.chunk_incref(id, stats)
        data = self.key.encrypt(chunk)
        csize = len(data)
        self.repository.put(id, data, wait=False)
        self.chunks.add(id, 1, size, csize)
        stats.update(size, csize, not refcount)
        return ChunkListEntry(id, size, csize)

    def seen_chunk(self, id, size=None):
        refcount, stored_size, _ = self.chunks.get(id, ChunkIndexEntry(0, None, None))
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
        return ChunkListEntry(id, size, csize)

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
        entry = FileCacheEntry(*msgpack.unpackb(entry))
        if (entry.size == st.st_size and entry.mtime == st.st_mtime_ns and
                (ignore_inode or entry.inode == st.st_ino)):
            self.files[path_hash] = msgpack.packb(entry._replace(age=0))
            return entry.chunk_ids
        else:
            return None

    def memorize_file(self, path_hash, st, ids):
        if not (self.do_files and stat.S_ISREG(st.st_mode)):
            return
        entry = FileCacheEntry(age=0, inode=st.st_ino, size=st.st_size, mtime=st.st_mtime_ns, chunk_ids=ids)
        self.files[path_hash] = msgpack.packb(entry)
        self._newest_mtime = max(self._newest_mtime or 0, st.st_mtime_ns)

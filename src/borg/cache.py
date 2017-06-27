import configparser
import os
import shutil
import stat
from binascii import unhexlify
from collections import namedtuple
from time import perf_counter

import msgpack

from .logger import create_logger

logger = create_logger()

from .constants import CACHE_README
from .hashindex import ChunkIndex, ChunkIndexEntry, CacheSynchronizer
from .helpers import Location
from .helpers import Error
from .helpers import Manifest
from .helpers import get_cache_dir, get_security_dir
from .helpers import int_to_bigint, bigint_to_int, bin_to_hex, parse_stringified_list
from .helpers import format_file_size
from .helpers import safe_ns
from .helpers import yes, hostname_is_unique
from .helpers import remove_surrogates
from .helpers import ProgressIndicatorPercent, ProgressIndicatorMessage
from .helpers import set_ec, EXIT_WARNING
from .item import ArchiveItem, ChunkListEntry
from .crypto.key import PlaintextKey
from .crypto.file_integrity import IntegrityCheckedFile, DetachedIntegrityCheckedFile, FileIntegrityError
from .locking import Lock
from .platform import SaveFile
from .remote import cache_if_remote
from .repository import LIST_SCAN_LIMIT

FileCacheEntry = namedtuple('FileCacheEntry', 'age inode size mtime chunk_ids')


class SecurityManager:
    """
    Tracks repositories. Ensures that nothing bad happens (repository swaps,
    replay attacks, unknown repositories etc.).

    This is complicated by the Cache being initially used for this, while
    only some commands actually use the Cache, which meant that other commands
    did not perform these checks.

    Further complications were created by the Cache being a cache, so it
    could be legitimately deleted, which is annoying because Borg didn't
    recognize repositories after that.

    Therefore a second location, the security database (see get_security_dir),
    was introduced which stores this information. However, this means that
    the code has to deal with a cache existing but no security DB entry,
    or inconsistencies between the security DB and the cache which have to
    be reconciled, and also with no cache existing but a security DB entry.
    """

    def __init__(self, repository):
        self.repository = repository
        self.dir = get_security_dir(repository.id_str)
        self.cache_dir = cache_dir(repository)
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

    def save(self, manifest, key):
        logger.debug('security: saving state for %s to %s', self.repository.id_str, self.dir)
        current_location = self.repository._location.canonical_path()
        logger.debug('security: current location   %s', current_location)
        logger.debug('security: key type           %s', str(key.TYPE))
        logger.debug('security: manifest timestamp %s', manifest.timestamp)
        with open(self.location_file, 'w') as fd:
            fd.write(current_location)
        with open(self.key_type_file, 'w') as fd:
            fd.write(str(key.TYPE))
        with open(self.manifest_ts_file, 'w') as fd:
            fd.write(manifest.timestamp)

    def assert_location_matches(self, cache_config=None):
        # Warn user before sending data to a relocated repository
        try:
            with open(self.location_file) as fd:
                previous_location = fd.read()
            logger.debug('security: read previous location %r', previous_location)
        except FileNotFoundError:
            logger.debug('security: previous location file %s not found', self.location_file)
            previous_location = None
        except OSError as exc:
            logger.warning('Could not read previous location file: %s', exc)
            previous_location = None
        if cache_config and cache_config.previous_location and previous_location != cache_config.previous_location:
            # Reconcile cache and security dir; we take the cache location.
            previous_location = cache_config.previous_location
            logger.debug('security: using previous_location of cache: %r', previous_location)

        repository_location = self.repository._location.canonical_path()
        if previous_location and previous_location != repository_location:
            msg = ("Warning: The repository at location {} was previously located at {}\n".format(
                repository_location, previous_location) +
                "Do you want to continue? [yN] ")
            if not yes(msg, false_msg="Aborting.", invalid_msg="Invalid answer, aborting.",
                       retry=False, env_var_override='BORG_RELOCATED_REPO_ACCESS_IS_OK'):
                raise Cache.RepositoryAccessAborted()
            # adapt on-disk config immediately if the new location was accepted
            logger.debug('security: updating location stored in cache and security dir')
            with open(self.location_file, 'w') as fd:
                fd.write(repository_location)
            if cache_config:
                cache_config.save()

    def assert_no_manifest_replay(self, manifest, key, cache_config=None):
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
        if cache_config:
            timestamp = max(timestamp, cache_config.timestamp or '')
        logger.debug('security: determined newest manifest timestamp as %s', timestamp)
        # If repository is older than the cache or security dir something fishy is going on
        if timestamp and timestamp > manifest.timestamp:
            if isinstance(key, PlaintextKey):
                raise Cache.RepositoryIDNotUnique()
            else:
                raise Cache.RepositoryReplay()

    def assert_key_type(self, key, cache_config=None):
        # Make sure an encrypted repository has not been swapped for an unencrypted repository
        if cache_config and cache_config.key_type is not None and cache_config.key_type != str(key.TYPE):
            raise Cache.EncryptionMethodMismatch()
        if self.known() and not self.key_matches(key):
            raise Cache.EncryptionMethodMismatch()

    def assert_secure(self, manifest, key, *, cache_config=None, warn_if_unencrypted=True):
        # warn_if_unencrypted=False is only used for initializing a new repository.
        # Thus, avoiding asking about a repository that's currently initializing.
        self.assert_access_unknown(warn_if_unencrypted, manifest, key)
        if cache_config:
            self._assert_secure(manifest, key, cache_config)
        else:
            cache_config = CacheConfig(self.repository)
            if cache_config.exists():
                with cache_config:
                    self._assert_secure(manifest, key, cache_config)
            else:
                self._assert_secure(manifest, key)
        logger.debug('security: repository checks ok, allowing access')

    def _assert_secure(self, manifest, key, cache_config=None):
        self.assert_location_matches(cache_config)
        self.assert_key_type(key, cache_config)
        self.assert_no_manifest_replay(manifest, key, cache_config)
        if not self.known():
            logger.debug('security: remembering previously unknown repository')
            self.save(manifest, key)

    def assert_access_unknown(self, warn_if_unencrypted, manifest, key):
        # warn_if_unencrypted=False is only used for initializing a new repository.
        # Thus, avoiding asking about a repository that's currently initializing.
        if not key.logically_encrypted and not self.known():
            msg = ("Warning: Attempting to access a previously unknown unencrypted repository!\n" +
                   "Do you want to continue? [yN] ")
            allow_access = not warn_if_unencrypted or yes(msg, false_msg="Aborting.",
                invalid_msg="Invalid answer, aborting.",
                retry=False, env_var_override='BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK')
            if allow_access:
                if warn_if_unencrypted:
                    logger.debug('security: remembering unknown unencrypted repository (explicitly allowed)')
                else:
                    logger.debug('security: initializing unencrypted repository')
                self.save(manifest, key)
            else:
                raise Cache.CacheInitAbortedError()


def assert_secure(repository, manifest):
    sm = SecurityManager(repository)
    sm.assert_secure(manifest, manifest.key)


def recanonicalize_relative_location(cache_location, repository):
    # borg < 1.0.8rc1 had different canonicalization for the repo location (see #1655 and #1741).
    repo_location = repository._location.canonical_path()
    rl = Location(repo_location)
    cl = Location(cache_location)
    if cl.proto == rl.proto and cl.user == rl.user and cl.host == rl.host and cl.port == rl.port \
            and \
            cl.path and rl.path and \
            cl.path.startswith('/~/') and rl.path.startswith('/./') and cl.path[3:] == rl.path[3:]:
        # everything is same except the expected change in relative path canonicalization,
        # update previous_location to avoid warning / user query about changed location:
        return repo_location
    else:
        return cache_location


def cache_dir(repository, path=None):
    return path or os.path.join(get_cache_dir(), repository.id_str)


class CacheConfig:
    def __init__(self, repository, path=None, lock_wait=None):
        self.repository = repository
        self.path = cache_dir(repository, path)
        self.config_path = os.path.join(self.path, 'config')
        self.lock = None
        self.lock_wait = lock_wait

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def exists(self):
        return os.path.exists(self.config_path)

    def create(self):
        assert not self.exists()
        config = configparser.ConfigParser(interpolation=None)
        config.add_section('cache')
        config.set('cache', 'version', '1')
        config.set('cache', 'repository', self.repository.id_str)
        config.set('cache', 'manifest', '')
        config.add_section('integrity')
        config.set('integrity', 'manifest', '')
        with SaveFile(self.config_path) as fd:
            config.write(fd)

    def open(self):
        self.lock = Lock(os.path.join(self.path, 'lock'), exclusive=True, timeout=self.lock_wait,
                         kill_stale_locks=hostname_is_unique()).acquire()
        self.load()

    def load(self):
        self._config = configparser.ConfigParser(interpolation=None)
        self._config.read(self.config_path)
        self._check_upgrade(self.config_path)
        self.id = self._config.get('cache', 'repository')
        self.manifest_id = unhexlify(self._config.get('cache', 'manifest'))
        self.timestamp = self._config.get('cache', 'timestamp', fallback=None)
        self.key_type = self._config.get('cache', 'key_type', fallback=None)
        self.ignored_features = set(parse_stringified_list(self._config.get('cache', 'ignored_features', fallback='')))
        self.mandatory_features = set(parse_stringified_list(self._config.get('cache', 'mandatory_features', fallback='')))
        try:
            self.integrity = dict(self._config.items('integrity'))
            if self._config.get('cache', 'manifest') != self.integrity.pop('manifest'):
                # The cache config file is updated (parsed with ConfigParser, the state of the ConfigParser
                # is modified and then written out.), not re-created.
                # Thus, older versions will leave our [integrity] section alone, making the section's data invalid.
                # Therefore, we also add the manifest ID to this section and
                # can discern whether an older version interfered by comparing the manifest IDs of this section
                # and the main [cache] section.
                self.integrity = {}
                logger.warning('Cache integrity data not available: old Borg version modified the cache.')
        except configparser.NoSectionError:
            logger.debug('Cache integrity: No integrity data found (files, chunks). Cache is from old version.')
            self.integrity = {}
        previous_location = self._config.get('cache', 'previous_location', fallback=None)
        if previous_location:
            self.previous_location = recanonicalize_relative_location(previous_location, self.repository)
        else:
            self.previous_location = None

    def save(self, manifest=None, key=None):
        if manifest:
            self._config.set('cache', 'manifest', manifest.id_str)
            self._config.set('cache', 'timestamp', manifest.timestamp)
            self._config.set('cache', 'ignored_features', ','.join(self.ignored_features))
            self._config.set('cache', 'mandatory_features', ','.join(self.mandatory_features))
            if not self._config.has_section('integrity'):
                self._config.add_section('integrity')
            for file, integrity_data in self.integrity.items():
                self._config.set('integrity', file, integrity_data)
            self._config.set('integrity', 'manifest', manifest.id_str)
        if key:
            self._config.set('cache', 'key_type', str(key.TYPE))
        self._config.set('cache', 'previous_location', self.repository._location.canonical_path())
        with SaveFile(self.config_path) as fd:
            self._config.write(fd)

    def close(self):
        if self.lock is not None:
            self.lock.release()
            self.lock = None

    def _check_upgrade(self, config_path):
        try:
            cache_version = self._config.getint('cache', 'version')
            wanted_version = 1
            if cache_version != wanted_version:
                self.close()
                raise Exception('%s has unexpected cache version %d (wanted: %d).' %
                                (config_path, cache_version, wanted_version))
        except configparser.NoSectionError:
            self.close()
            raise Exception('%s does not look like a Borg cache.' % config_path) from None


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
        path = cache_dir(repository, path)
        Lock(os.path.join(path, 'lock'), exclusive=True).break_lock()

    @staticmethod
    def destroy(repository, path=None):
        """destroy the cache for ``repository`` or at ``path``"""
        path = path or os.path.join(get_cache_dir(), repository.id_str)
        config = os.path.join(path, 'config')
        if os.path.exists(config):
            os.remove(config)  # kill config first
            shutil.rmtree(path)

    def __new__(cls, repository, key, manifest, path=None, sync=True, do_files=False, warn_if_unencrypted=True,
                progress=False, lock_wait=None, permit_adhoc_cache=False):
        def local():
            return LocalCache(repository=repository, key=key, manifest=manifest, path=path, sync=sync,
                              do_files=do_files, warn_if_unencrypted=warn_if_unencrypted, progress=progress,
                              lock_wait=lock_wait)

        def adhoc():
            return AdHocCache(repository=repository, key=key, manifest=manifest)

        if not permit_adhoc_cache:
            return local()

        # ad-hoc cache may be permitted, but if the local cache is in sync it'd be stupid to invalidate
        # it by needlessly using the ad-hoc cache.
        # Check if the local cache exists and is in sync.

        cache_config = CacheConfig(repository, path, lock_wait)
        if cache_config.exists():
            with cache_config:
                cache_in_sync = cache_config.manifest_id == manifest.id
            # Don't nest cache locks
            if cache_in_sync:
                # Local cache is in sync, use it
                logger.debug('Cache: choosing local cache (in sync)')
                return local()
        logger.debug('Cache: choosing ad-hoc cache (local cache does not exist or is not in sync)')
        return adhoc()


class CacheStatsMixin:
    str_format = """\
All archives:   {0.total_size:>20s} {0.total_csize:>20s} {0.unique_csize:>20s}

                       Unique chunks         Total chunks
Chunk index:    {0.total_unique_chunks:20d} {0.total_chunks:20d}"""

    def __str__(self):
        return self.str_format.format(self.format_tuple())

    Summary = namedtuple('Summary', ['total_size', 'total_csize', 'unique_size', 'unique_csize', 'total_unique_chunks',
                                     'total_chunks'])

    def stats(self):
        # XXX: this should really be moved down to `hashindex.pyx`
        stats = self.Summary(*self.chunks.summarize())._asdict()
        return stats

    def format_tuple(self):
        stats = self.stats()
        for field in ['total_size', 'total_csize', 'unique_csize']:
            stats[field] = format_file_size(stats[field])
        return self.Summary(**stats)

    def chunks_stored_size(self):
        return self.stats()['unique_csize']


class LocalCache(CacheStatsMixin):
    """
    Persistent, local (client-side) cache.
    """

    def __init__(self, repository, key, manifest, path=None, sync=True, do_files=False, warn_if_unencrypted=True,
                 progress=False, lock_wait=None):
        """
        :param do_files: use file metadata cache
        :param warn_if_unencrypted: print warning if accessing unknown unencrypted repository
        :param lock_wait: timeout for lock acquisition (None: return immediately if lock unavailable)
        :param sync: do :meth:`.sync`
        """
        self.repository = repository
        self.key = key
        self.manifest = manifest
        self.progress = progress
        self.do_files = do_files
        self.timestamp = None
        self.txn_active = False

        self.path = cache_dir(repository, path)
        self.security_manager = SecurityManager(repository)
        self.chunks_archive_manager = self.ChunksArchiveManager(self)
        self.cache_config = CacheConfig(self.repository, self.path, lock_wait)

        # Warn user before sending data to a never seen before unencrypted repository
        if not os.path.exists(self.path):
            self.security_manager.assert_access_unknown(warn_if_unencrypted, manifest, key)
            self.create()

        self.open()
        try:
            self.security_manager.assert_secure(manifest, key, cache_config=self.cache_config)

            if not self.check_cache_compatibility():
                self.wipe_cache()

            self.update_compatibility()

            if sync and self.manifest.id != self.cache_config.manifest_id:
                self.chunks = self.chunks_archive_manager.sync(self.chunks)
                self.commit()
        except:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def create(self):
        """Create a new empty cache at `self.path`
        """
        os.makedirs(self.path)
        with open(os.path.join(self.path, 'README'), 'w') as fd:
            fd.write(CACHE_README)
        self.cache_config.create()
        ChunkIndex().write(os.path.join(self.path, 'chunks'))
        os.makedirs(os.path.join(self.path, 'chunks.archive.d'))
        with SaveFile(os.path.join(self.path, 'files'), binary=True) as fd:
            pass  # empty file

    def _do_open(self):
        self.cache_config.load()
        with IntegrityCheckedFile(path=os.path.join(self.path, 'chunks'), write=False,
                                  integrity_data=self.cache_config.integrity.get('chunks')) as fd:
            self.chunks = ChunkIndex.read(fd)
        self.files = None

    def open(self):
        if not os.path.isdir(self.path):
            raise Exception('%s Does not look like a Borg cache' % self.path)
        self.cache_config.open()
        self.rollback()

    def close(self):
        if self.cache_config is not None:
            self.cache_config.close()
            self.cache_config = None

    def _read_files(self):
        self.files = {}
        self._newest_mtime = None
        logger.debug('Reading files cache ...')

        with IntegrityCheckedFile(path=os.path.join(self.path, 'files'), write=False,
                                  integrity_data=self.cache_config.integrity.get('files')) as fd:
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
        pi = ProgressIndicatorMessage(msgid='cache.begin_transaction')
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
        self.security_manager.save(self.manifest, self.key)
        pi = ProgressIndicatorMessage(msgid='cache.commit')
        if self.files is not None:
            if self._newest_mtime is None:
                # was never set because no files were modified/added
                self._newest_mtime = 2 ** 63 - 1  # nanoseconds, good until y2262
            ttl = int(os.environ.get('BORG_FILES_CACHE_TTL', 20))
            pi.output('Saving files cache')
            with IntegrityCheckedFile(path=os.path.join(self.path, 'files'), write=True) as fd:
                for path_hash, item in self.files.items():
                    # Only keep files seen in this backup that are older than newest mtime seen in this backup -
                    # this is to avoid issues with filesystem snapshots and mtime granularity.
                    # Also keep files from older backups that have not reached BORG_FILES_CACHE_TTL yet.
                    entry = FileCacheEntry(*msgpack.unpackb(item))
                    if entry.age == 0 and bigint_to_int(entry.mtime) < self._newest_mtime or \
                       entry.age > 0 and entry.age < ttl:
                        msgpack.pack((path_hash, entry), fd)
            self.cache_config.integrity['files'] = fd.integrity_data
        pi.output('Saving chunks cache')
        with IntegrityCheckedFile(path=os.path.join(self.path, 'chunks'), write=True) as fd:
            self.chunks.write(fd)
        self.cache_config.integrity['chunks'] = fd.integrity_data
        pi.output('Saving cache config')
        self.cache_config.save(self.manifest, self.key)
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

    class ChunksArchiveManager:
        """
        Maintains a directory with known backup archive indexes, so it only
        needs to fetch infos from repo and build a chunk index once per backup
        archive.

        If out of sync, missing archive indexes get added, outdated indexes
        get removed and a new master chunks index is built by merging all
        archive indexes.
        """

        def __init__(self, cache):
            self.cache = cache
            self.archive_path = os.path.join(cache.path, 'chunks.archive.d')
            # TEMPORARY HACK: to avoid archive index caching, create a FILE named ~/.cache/borg/REPOID/chunks.archive.d -
            # this is only recommended if you have a fast, low latency connection to your repo (e.g. if repo is local disk)
            self.chunks_archive_enabled = not os.path.isdir(self.archive_path)
            # An index of chunks whose size had to be fetched
            self.chunks_fetched_size_index = ChunkIndex()

        def sync(self, chunks):
            # The cache can be used by a command that e.g. only checks against Manifest.Operation.WRITE,
            # which does not have to include all flags from Manifest.Operation.READ.
            # Since the sync will attempt to read archives, check compatibility with Manifest.Operation.READ.
            self.cache.manifest.check_repository_compatibility((Manifest.Operation.READ,))

            self.cache.begin_txn()
            with cache_if_remote(self.cache.repository, decrypted_cache=self.cache.key) as decrypted_repository:
                self.legacy_cleanup()
                return self.create_master_idx(decrypted_repository, chunks)

        def create_master_idx(self, decrypted_repository, chunk_idx):
            logger.info('Synchronizing chunks cache...')
            cache_sync_stats = LocalCache.CacheSyncStats()
            cached_ids = self.cached_archives()
            archive_ids = self.repo_archives()
            logger.info('Archives: %d, w/ cached Idx: %d, w/ outdated Idx: %d, w/o cached Idx: %d.',
                len(archive_ids), len(cached_ids),
                len(cached_ids - archive_ids), len(archive_ids - cached_ids))
            # deallocates old hashindex, creates empty hashindex:
            chunk_idx.clear()
            self.cleanup_outdated(cached_ids - archive_ids)
            # Explicitly set the initial hash table capacity to avoid performance issues
            # due to hash table "resonance".
            master_index_capacity = int(len(self.cache.repository) / ChunkIndex.MAX_LOAD_FACTOR)
            if archive_ids:
                chunk_idx = ChunkIndex(master_index_capacity)
                pi = ProgressIndicatorPercent(total=len(archive_ids), step=0.1,
                                              msg='%3.0f%% Syncing chunks cache. Processing archive %s',
                                              msgid='cache.sync')
                chunks_archives = self.get_chunks_archives(archive_ids)
                for chunks_archive in chunks_archives:
                    pi.show(info=[remove_surrogates(chunks_archive.name)])
                    archive_chunk_idx = chunks_archive.procure_index(decrypted_repository, cache_sync_stats)
                    if self.chunks_archive_enabled:
                        self.fetch_missing_csize(decrypted_repository, archive_chunk_idx, cache_sync_stats)
                        chunks_archive.write_index(archive_chunk_idx, cache_sync_stats)
                    chunk_idx.merge(archive_chunk_idx)
                if not self.chunks_archive_enabled:
                    self.fetch_missing_csize(decrypted_repository, chunk_idx, cache_sync_stats)
                pi.finish()
                logger.debug('Cache sync: had to fetch %s (%d chunks) because no archive had a csize set for them '
                             '(due to --no-cache-sync)',
                             format_file_size(cache_sync_stats.fetched_bytes_for_csize),
                             cache_sync_stats.fetched_chunks_for_csize)
                logger.debug('Cache sync: processed %s (%d chunks) of metadata',
                             format_file_size(cache_sync_stats.processed_item_metadata_bytes),
                             cache_sync_stats.processed_item_metadata_chunks)
                logger.debug('Cache sync: compact chunks.archive.d storage saved %s bytes',
                             format_file_size(cache_sync_stats.compact_chunks_archive_saved_space))
            return chunk_idx

        def legacy_cleanup(self):
            """bring old cache dirs into the desired state (cleanup and adapt)"""
            try:
                os.unlink(os.path.join(self.cache.path, 'chunks.archive'))
            except:
                pass
            try:
                os.unlink(os.path.join(self.cache.path, 'chunks.archive.tmp'))
            except:
                pass
            try:
                os.mkdir(self.archive_path)
            except:
                pass

        def cleanup_outdated(self, ids):
            for id in ids:
                self.cleanup_cached_archive(id)

        def cleanup_cached_archive(self, id, cleanup_compact=True):
            try:
                os.unlink(self.mkpath(id))
                os.unlink(self.mkpath(id) + '.integrity')
            except FileNotFoundError:
                pass
            if not cleanup_compact:
                return
            try:
                os.unlink(self.mkpath(id, suffix='.compact'))
                os.unlink(self.mkpath(id, suffix='.compact') + '.integrity')
            except FileNotFoundError:
                pass

        def mkpath(self, id, suffix=''):
            """Return path for *id* (bytes)."""
            id_hex = bin_to_hex(id)
            path = os.path.join(self.archive_path, id_hex + suffix)
            return path

        def get_chunks_archives(self, archive_ids):
            # Pass once over all archives and build a mapping from ids to names.
            # The easier approach, doing a similar loop for each archive, has
            # square complexity and does about a dozen million functions calls
            # with 1100 archives (which takes 30s CPU seconds _alone_).
            chunks_archives = []
            for info in self.cache.manifest.archives.list():
                if info.id in archive_ids:
                    chunks_archives.append(LocalCache.ChunksArchive(self, info.id, info.name))
            assert len(chunks_archives) == len(archive_ids)
            return chunks_archives

        def get_chunks_archive(self, archive):
            return LocalCache.ChunksArchive(self, archive.id, archive.name)

        def cached_archives(self):
            if self.chunks_archive_enabled:
                fns = os.listdir(self.archive_path)
                # filenames with 64 hex digits == 256bit,
                # or compact indices which are 64 hex digits + ".compact"
                return set(unhexlify(fn) for fn in fns if len(fn) == 64) | \
                       set(unhexlify(fn[:64]) for fn in fns if len(fn) == 72 and fn.endswith('.compact'))
            else:
                return set()

        def repo_archives(self):
            return set(info.id for info in self.cache.manifest.archives.list())

        def fetch_missing_csize(self, decrypted_repository, chunk_idx, cache_sync_stats):
            """
            Archives created with AdHocCache will have csize=0 in all chunk list entries whose
            chunks were already in the repository.

            Scan *chunk_idx* for entries where csize=0 and fill in the correct information.
            """
            all_missing_ids = chunk_idx.zero_csize_ids()
            fetch_ids = []
            if len(self.chunks_fetched_size_index):
                for id_ in all_missing_ids:
                    already_fetched_entry = self.chunks_fetched_size_index.get(id_)
                    if already_fetched_entry:
                        entry = chunk_idx[id_]._replace(csize=already_fetched_entry.csize)
                        assert entry.size == already_fetched_entry.size, 'Chunk size mismatch'
                        chunk_idx[id_] = entry
                    else:
                        fetch_ids.append(id_)
            else:
                fetch_ids = all_missing_ids

            # This is potentially a rather expensive operation, but it's hard to tell at this point
            # if it's a problem in practice (hence the experimental status of --no-cache-sync).
            for id_, data in zip(fetch_ids, decrypted_repository.repository.get_many(fetch_ids)):
                entry = chunk_idx[id_]._replace(csize=len(data))
                chunk_idx[id_] = entry
                self.chunks_fetched_size_index[id_] = entry
                cache_sync_stats.fetched_chunks_for_csize += 1
                cache_sync_stats.fetched_bytes_for_csize += len(data)

    class CacheSyncStats:
        processed_item_metadata_bytes = 0
        processed_item_metadata_chunks = 0
        compact_chunks_archive_saved_space = 0
        fetched_chunks_for_csize = 0
        fetched_bytes_for_csize = 0

    class ChunksArchive:
        def __init__(self, manager, id, name):
            self.manager = manager
            self.id = id
            self.name = name

        def mkpath(self, *, suffix=''):
            """Return path for *id* (bytes)."""
            id_hex = bin_to_hex(self.id)
            path = os.path.join(self.manager.archive_path, id_hex + suffix)
            return path

        def cleanup(self, *, cleanup_compact=True):
            """Delete cached index, if any."""
            try:
                os.unlink(self.mkpath())
                os.unlink(self.mkpath(suffix='.integrity'))
            except FileNotFoundError:
                pass
            if not cleanup_compact:
                return
            try:
                os.unlink(self.mkpath(suffix='.compact'))
                os.unlink(self.mkpath(suffix='.compact.integrity'))
            except FileNotFoundError:
                pass

        def build_index(self, decrypted_repository, chunk_idx, cache_sync_stats=None, detailed_pi=None):
            processed_item_metadata_bytes = 0
            processed_item_metadata_chunks = 0
            csize, data = decrypted_repository.get(self.id)
            chunk_idx.add(self.id, 1, len(data), csize)
            archive = ArchiveItem(internal_dict=msgpack.unpackb(data))
            if archive.version != 1:
                raise Exception('Unknown archive metadata version')
            sync = CacheSynchronizer(chunk_idx)
            if detailed_pi:
                detailed_pi.total = len(archive.items)
            for item_id, (csize, data) in zip(archive.items, decrypted_repository.get_many(archive.items)):
                chunk_idx.add(item_id, 1, len(data), csize)
                processed_item_metadata_bytes += len(data)
                processed_item_metadata_chunks += 1
                sync.feed(data)
                if detailed_pi:
                    detailed_pi.show(increase=1)
            if detailed_pi:
                detailed_pi.finish()
            if cache_sync_stats:
                cache_sync_stats.processed_item_metadata_bytes += processed_item_metadata_bytes
                cache_sync_stats.processed_item_metadata_chunks += processed_item_metadata_chunks
            return sync

        def write_index(self, chunk_idx, cache_sync_stats):
            assert len(chunk_idx)
            cache_sync_stats.compact_chunks_archive_saved_space += chunk_idx.compact()
            fn = self.mkpath(suffix='.compact')
            fn_tmp = self.mkpath(suffix='.tmp')
            try:
                with DetachedIntegrityCheckedFile(path=fn_tmp, write=True,
                                                  filename=bin_to_hex(self.id) + '.compact') as fd:
                    chunk_idx.write(fd)
            except Exception:
                os.unlink(fn_tmp)
            else:
                os.rename(fn_tmp, fn)

        def read_index(self, cache_sync_stats):
            archive_chunk_idx_path = self.mkpath()
            try:
                try:
                    # Attempt to load compact index first
                    with DetachedIntegrityCheckedFile(path=archive_chunk_idx_path + '.compact', write=False) as fd:
                        archive_chunk_idx = ChunkIndex.read(fd, permit_compact=True)
                    # In case a non-compact index exists, delete it.
                    self.cleanup(cleanup_compact=False)
                    # Compact index read - return index, no conversion necessary (below).
                    return archive_chunk_idx
                except FileNotFoundError:
                    # No compact index found, load non-compact index, and convert below.
                    with DetachedIntegrityCheckedFile(path=archive_chunk_idx_path, write=False) as fd:
                        archive_chunk_idx = ChunkIndex.read(fd)
            except FileIntegrityError as fie:
                logger.error('Cached archive chunk index of %s is corrupted: %s', self.name, fie)
                # Delete corrupted index, set warning. A new index must be build.
                self.cleanup()
                set_ec(EXIT_WARNING)
                return None

            # Convert to compact index. Delete the existing index first.
            logger.debug('Found non-compact index for %s, converting to compact.', self.name)
            self.cleanup()
            self.write_index(archive_chunk_idx, cache_sync_stats)
            return archive_chunk_idx

        def procure_index(self, decrypted_repository, cache_sync_stats=None, detailed_pi=None):
            cache_sync_stats = cache_sync_stats or LocalCache.CacheSyncStats()
            try:
                index = self.read_index(cache_sync_stats)
            except FileNotFoundError:
                index = None
            if index:
                return index

            index = ChunkIndex()
            self.build_index(decrypted_repository, index, cache_sync_stats, detailed_pi=detailed_pi)
            return index

    def check_cache_compatibility(self):
        my_features = Manifest.SUPPORTED_REPO_FEATURES
        if self.cache_config.ignored_features & my_features:
            # The cache might not contain references of chunks that need a feature that is mandatory for some operation
            # and which this version supports. To avoid corruption while executing that operation force rebuild.
            return False
        if not self.cache_config.mandatory_features <= my_features:
            # The cache was build with consideration to at least one feature that this version does not understand.
            # This client might misinterpret the cache. Thus force a rebuild.
            return False
        return True

    def wipe_cache(self):
        logger.warning("Discarding incompatible cache and forcing a cache rebuild")
        archive_path = os.path.join(self.path, 'chunks.archive.d')
        if os.path.isdir(archive_path):
            shutil.rmtree(os.path.join(self.path, 'chunks.archive.d'))
            os.makedirs(os.path.join(self.path, 'chunks.archive.d'))
        self.chunks = ChunkIndex()
        with open(os.path.join(self.path, 'files'), 'wb'):
            pass  # empty file
        self.cache_config.manifest_id = ''
        self.cache_config._config.set('cache', 'manifest', '')

        self.cache_config.ignored_features = set()
        self.cache_config.mandatory_features = set()

    def update_compatibility(self):
        operation_to_features_map = self.manifest.get_all_mandatory_features()
        my_features = Manifest.SUPPORTED_REPO_FEATURES
        repo_features = set()
        for operation, features in operation_to_features_map.items():
            repo_features.update(features)

        self.cache_config.ignored_features.update(repo_features - my_features)
        self.cache_config.mandatory_features.update(repo_features & my_features)

    def add_chunk(self, id, chunk, stats, overwrite=False, wait=True):
        if not self.txn_active:
            self.begin_txn()
        size = len(chunk)
        refcount = self.seen_chunk(id, size)
        if refcount and not overwrite:
            return self.chunk_incref(id, stats)
        data = self.key.encrypt(chunk)
        csize = len(data)
        self.repository.put(id, data, wait=wait)
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

    def chunk_decref(self, id, stats, wait=True):
        if not self.txn_active:
            self.begin_txn()
        count, size, csize = self.chunks.decref(id)
        if count == 0:
            del self.chunks[id]
            self.repository.delete(id, wait=wait)
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
        if (entry.size == st.st_size and bigint_to_int(entry.mtime) == st.st_mtime_ns and
                (ignore_inode or entry.inode == st.st_ino)):
            # we ignored the inode number in the comparison above or it is still same.
            # if it is still the same, replacing it in the tuple doesn't change it.
            # if we ignored it, a reason for doing that is that files were moved to a new
            # disk / new fs (so a one-time change of inode number is expected) and we wanted
            # to avoid everything getting chunked again. to be able to re-enable the inode
            # number comparison in a future backup run (and avoid chunking everything
            # again at that time), we need to update the inode number in the cache with what
            # we see in the filesystem.
            self.files[path_hash] = msgpack.packb(entry._replace(inode=st.st_ino, age=0))
            return entry.chunk_ids
        else:
            return None

    def memorize_file(self, path_hash, st, ids):
        if not (self.do_files and stat.S_ISREG(st.st_mode)):
            return
        mtime_ns = safe_ns(st.st_mtime_ns)
        entry = FileCacheEntry(age=0, inode=st.st_ino, size=st.st_size, mtime=int_to_bigint(mtime_ns), chunk_ids=ids)
        self.files[path_hash] = msgpack.packb(entry)
        self._newest_mtime = max(self._newest_mtime or 0, mtime_ns)


class AdHocCache(CacheStatsMixin):
    """
    Ad-hoc, non-persistent cache.

    Compared to the standard LocalCache the AdHocCache does not maintain accurate reference count,
    nor does it provide a files cache (which would require persistence). Chunks that were not added
    during the current AdHocCache lifetime won't have correct size/csize set (0 bytes) and will
    have an infinite reference count (MAX_VALUE).
    """

    str_format = """\
All archives:                unknown              unknown              unknown

                       Unique chunks         Total chunks
Chunk index:    {0.total_unique_chunks:20d}             unknown"""

    def __init__(self, repository, key, manifest, warn_if_unencrypted=True):
        self.repository = repository
        self.key = key
        self.manifest = manifest
        self._txn_active = False

        self.security_manager = SecurityManager(repository)
        self.security_manager.assert_secure(manifest, key)

        logger.warning('Note: --no-cache-sync is an experimental feature.')

    # Public API

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    files = None
    do_files = False

    def file_known_and_unchanged(self, path_hash, st, ignore_inode=False):
        return None

    def memorize_file(self, path_hash, st, ids):
        pass

    def add_chunk(self, id, chunk, stats, overwrite=False, wait=True):
        assert not overwrite, 'AdHocCache does not permit overwrites — trying to use it for recreate?'
        if not self._txn_active:
            self._begin_txn()
        size = len(chunk)
        refcount = self.seen_chunk(id, size)
        if refcount:
            return self.chunk_incref(id, stats, size_=size)
        data = self.key.encrypt(chunk)
        csize = len(data)
        self.repository.put(id, data, wait=wait)
        self.chunks.add(id, 1, size, csize)
        stats.update(size, csize, not refcount)
        return ChunkListEntry(id, size, csize)

    def seen_chunk(self, id, size=None):
        if not self._txn_active:
            self._begin_txn()
        entry = self.chunks.get(id, ChunkIndexEntry(0, None, None))
        if entry.refcount and size and not entry.size:
            # The LocalCache has existing size information and uses *size* to make an effort at detecting collisions.
            # This is of course not possible for the AdHocCache.
            # Here *size* is used to update the chunk's size information, which will be zero for existing chunks.
            self.chunks[id] = entry._replace(size=size)
        return entry.refcount

    def chunk_incref(self, id, stats, size_=None):
        if not self._txn_active:
            self._begin_txn()
        count, size, csize = self.chunks.incref(id)
        stats.update(size or size_, csize, False)
        # When size is 0 and size_ is not given, then this chunk has not been locally visited yet (seen_chunk with
        # size or add_chunk); we can't add references to those (size=0 is invalid) and generally don't try to.
        assert size or size_
        return ChunkListEntry(id, size or size_, csize)

    def chunk_decref(self, id, stats, wait=True):
        if not self._txn_active:
            self._begin_txn()
        count, size, csize = self.chunks.decref(id)
        if count == 0:
            del self.chunks[id]
            self.repository.delete(id, wait=wait)
            stats.update(-size, -csize, True)
        else:
            stats.update(-size, -csize, False)

    def commit(self):
        if not self._txn_active:
            return
        self.security_manager.save(self.manifest, self.key)
        self._txn_active = False

    def rollback(self):
        self._txn_active = False
        del self.chunks

    # Private API

    def _begin_txn(self):
        self._txn_active = True
        # Explicitly set the initial hash table capacity to avoid performance issues
        # due to hash table "resonance".
        # Since we're creating an archive, add 10 % from the start.
        num_chunks = len(self.repository)
        capacity = int(num_chunks / ChunkIndex.MAX_LOAD_FACTOR * 1.1)
        self.chunks = ChunkIndex(capacity)
        pi = ProgressIndicatorPercent(total=num_chunks, msg='Downloading chunk list... %3.0f%%',
                                      msgid='cache.download_chunks')
        t0 = perf_counter()
        num_requests = 0
        marker = None
        while True:
            result = self.repository.list(limit=LIST_SCAN_LIMIT, marker=marker)
            num_requests += 1
            if not result:
                break
            pi.show(increase=len(result))
            marker = result[-1]
            # All chunks from the repository have a refcount of MAX_VALUE, which is sticky,
            # therefore we can't/won't delete them. Chunks we added ourselves in this transaction
            # (e.g. checkpoint archives) are tracked correctly.
            init_entry = ChunkIndexEntry(refcount=ChunkIndex.MAX_VALUE, size=0, csize=0)
            for id_ in result:
                self.chunks[id_] = init_entry
        assert len(self.chunks) == num_chunks
        # LocalCache does not contain the manifest, either.
        del self.chunks[self.manifest.MANIFEST_ID]
        duration = perf_counter() - t0 or 0.01
        pi.finish()
        logger.debug('AdHocCache: downloaded %d chunk IDs in %.2f s (%d requests), ~%s/s',
                     num_chunks, duration, num_requests, format_file_size(num_chunks * 34 / duration))
        # Chunk IDs in a list are encoded in 34 bytes: 1 byte msgpack header, 1 byte length, 32 ID bytes.
        # Protocol overhead is neglected in this calculation.

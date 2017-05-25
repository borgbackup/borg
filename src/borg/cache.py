import configparser
import os
import shutil
import stat
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
from .helpers import int_to_bigint, bigint_to_int, bin_to_hex
from .helpers import format_file_size
from .helpers import safe_ns
from .helpers import yes, hostname_is_unique
from .helpers import remove_surrogates
from .helpers import ProgressIndicatorPercent, ProgressIndicatorMessage
from .item import ArchiveItem, ChunkListEntry
from .crypto.key import PlaintextKey
from .crypto.file_integrity import IntegrityCheckedFile, DetachedIntegrityCheckedFile, FileIntegrityError
from .locking import Lock
from .platform import SaveFile
from .remote import cache_if_remote

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
        if not self._config.has_section('integrity'):
            self._config.add_section('integrity')
        try:
            self.integrity = dict(self._config.items('integrity'))
        except configparser.NoSectionError:
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
        if key:
            self._config.set('cache', 'key_type', str(key.TYPE))
        self._config.set('cache', 'previous_location', self.repository._location.canonical_path())
        for file, integrity_data in self.integrity.items():
            self._config.set('integrity', file, integrity_data)
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
        self.cache_config = CacheConfig(self.repository, self.path, lock_wait)

        # Warn user before sending data to a never seen before unencrypted repository
        if not os.path.exists(self.path):
            self.security_manager.assert_access_unknown(warn_if_unencrypted, manifest, key)
            self.create()

        self.open()
        try:
            self.security_manager.assert_secure(manifest, key, cache_config=self.cache_config)
            if sync and self.manifest.id != self.cache_config.manifest_id:
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
            return path

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
                cleanup_cached_archive(id)

        def cleanup_cached_archive(id):
            os.unlink(mkpath(id))
            try:
                os.unlink(mkpath(id) + '.integrity')
            except FileNotFoundError:
                pass

        def fetch_and_build_idx(archive_id, repository, key, chunk_idx):
            cdata = repository.get(archive_id)
            data = key.decrypt(archive_id, cdata)
            chunk_idx.add(archive_id, 1, len(data), len(cdata))
            archive = ArchiveItem(internal_dict=msgpack.unpackb(data))
            if archive.version != 1:
                raise Exception('Unknown archive metadata version')
            unpacker = msgpack.Unpacker()
            for item_id, chunk in zip(archive.items, repository.get_many(archive.items)):
                data = key.decrypt(item_id, chunk)
                chunk_idx.add(item_id, 1, len(data), len(chunk))
                unpacker.feed(data)
                for item in unpacker:
                    if not isinstance(item, dict):
                        logger.error('Error: Did not get expected metadata dict - archive corrupted!')
                        continue   # XXX: continue?!
                    for chunk_id, size, csize in item.get(b'chunks', []):
                        chunk_idx.add(chunk_id, 1, size, csize)
            if self.do_cache:
                fn = mkpath(archive_id)
                fn_tmp = mkpath(archive_id, suffix='.tmp')
                with DetachedIntegrityCheckedFile(path=fn_tmp, write=True, filename=bin_to_hex(archive_id)) as fd:
                    try:
                        chunk_idx.write(fd)
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
            logger.info('Archives: %d, w/ cached Idx: %d, w/ outdated Idx: %d, w/o cached Idx: %d.',
                len(archive_ids), len(cached_ids),
                len(cached_ids - archive_ids), len(archive_ids - cached_ids))
            # deallocates old hashindex, creates empty hashindex:
            chunk_idx.clear()
            cleanup_outdated(cached_ids - archive_ids)
            if archive_ids:
                chunk_idx = None
                if self.progress:
                    pi = ProgressIndicatorPercent(total=len(archive_ids), step=0.1,
                                                  msg='%3.0f%% Syncing chunks cache. Processing archive %s',
                                                  msgid='cache.sync')
                for archive_id in archive_ids:
                    archive_name = lookup_name(archive_id)
                    if self.progress:
                        pi.show(info=[remove_surrogates(archive_name)])
                    if self.do_cache:
                        if archive_id in cached_ids:
                            archive_chunk_idx_path = mkpath(archive_id)
                            logger.info("Reading cached archive chunk index for %s ...", archive_name)
                            try:
                                with DetachedIntegrityCheckedFile(path=archive_chunk_idx_path, write=False) as fd:
                                    archive_chunk_idx = ChunkIndex.read(fd)
                            except FileIntegrityError as fie:
                                logger.error('Cached archive chunk index of %s is corrupted: %s', archive_name, fie)
                                # Delete it and fetch a new index
                                cleanup_cached_archive(archive_id)
                                cached_ids.remove(archive_id)
                        if archive_id not in cached_ids:
                            # Do not make this an else branch; the FileIntegrityError exception handler
                            # above can remove *archive_id* from *cached_ids*.
                            logger.info('Fetching and building archive index for %s ...', archive_name)
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
                        logger.info('Fetching archive index for %s ...', archive_name)
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

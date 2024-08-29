import configparser
import os
import shutil
import stat
from collections import namedtuple
from time import perf_counter

from .logger import create_logger

logger = create_logger()

files_cache_logger = create_logger("borg.debug.files_cache")

from .constants import CACHE_README, FILES_CACHE_MODE_DISABLED, ROBJ_FILE_STREAM
from .hashindex import ChunkIndex, ChunkIndexEntry
from .helpers import Error
from .helpers import get_cache_dir, get_security_dir
from .helpers import hex_to_bin, parse_stringified_list
from .helpers import format_file_size
from .helpers import safe_ns
from .helpers import yes
from .helpers import ProgressIndicatorMessage
from .helpers import msgpack
from .helpers.msgpack import int_to_timestamp, timestamp_to_int
from .item import ChunkListEntry
from .crypto.key import PlaintextKey
from .crypto.file_integrity import IntegrityCheckedFile, FileIntegrityError
from .fslocking import Lock
from .manifest import Manifest
from .platform import SaveFile
from .remote import RemoteRepository
from .repository import LIST_SCAN_LIMIT, Repository

# note: cmtime might be either a ctime or a mtime timestamp, chunks is a list of ChunkListEntry
FileCacheEntry = namedtuple("FileCacheEntry", "age inode size cmtime chunks")


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
        self.dir = get_security_dir(repository.id_str, legacy=(repository.version == 1))
        self.cache_dir = cache_dir(repository)
        self.key_type_file = os.path.join(self.dir, "key-type")
        self.location_file = os.path.join(self.dir, "location")
        self.manifest_ts_file = os.path.join(self.dir, "manifest-timestamp")

    @staticmethod
    def destroy(repository, path=None):
        """destroy the security dir for ``repository`` or at ``path``"""
        path = path or get_security_dir(repository.id_str, legacy=(repository.version == 1))
        if os.path.exists(path):
            shutil.rmtree(path)

    def known(self):
        return all(os.path.exists(f) for f in (self.key_type_file, self.location_file, self.manifest_ts_file))

    def key_matches(self, key):
        if not self.known():
            return False
        try:
            with open(self.key_type_file) as fd:
                type = fd.read()
                return type == str(key.TYPE)
        except OSError as exc:
            logger.warning("Could not read/parse key type file: %s", exc)

    def save(self, manifest, key):
        logger.debug("security: saving state for %s to %s", self.repository.id_str, self.dir)
        current_location = self.repository._location.canonical_path()
        logger.debug("security: current location   %s", current_location)
        logger.debug("security: key type           %s", str(key.TYPE))
        logger.debug("security: manifest timestamp %s", manifest.timestamp)
        with SaveFile(self.location_file) as fd:
            fd.write(current_location)
        with SaveFile(self.key_type_file) as fd:
            fd.write(str(key.TYPE))
        with SaveFile(self.manifest_ts_file) as fd:
            fd.write(manifest.timestamp)

    def assert_location_matches(self):
        # Warn user before sending data to a relocated repository
        try:
            with open(self.location_file) as fd:
                previous_location = fd.read()
            logger.debug("security: read previous location %r", previous_location)
        except FileNotFoundError:
            logger.debug("security: previous location file %s not found", self.location_file)
            previous_location = None
        except OSError as exc:
            logger.warning("Could not read previous location file: %s", exc)
            previous_location = None

        repository_location = self.repository._location.canonical_path()
        if previous_location and previous_location != repository_location:
            msg = (
                "Warning: The repository at location {} was previously located at {}\n".format(
                    repository_location, previous_location
                )
                + "Do you want to continue? [yN] "
            )
            if not yes(
                msg,
                false_msg="Aborting.",
                invalid_msg="Invalid answer, aborting.",
                retry=False,
                env_var_override="BORG_RELOCATED_REPO_ACCESS_IS_OK",
            ):
                raise Cache.RepositoryAccessAborted()
            # adapt on-disk config immediately if the new location was accepted
            logger.debug("security: updating location stored in security dir")
            with SaveFile(self.location_file) as fd:
                fd.write(repository_location)

    def assert_no_manifest_replay(self, manifest, key):
        try:
            with open(self.manifest_ts_file) as fd:
                timestamp = fd.read()
            logger.debug("security: read manifest timestamp %r", timestamp)
        except FileNotFoundError:
            logger.debug("security: manifest timestamp file %s not found", self.manifest_ts_file)
            timestamp = ""
        except OSError as exc:
            logger.warning("Could not read previous location file: %s", exc)
            timestamp = ""
        logger.debug("security: determined newest manifest timestamp as %s", timestamp)
        # If repository is older than the cache or security dir something fishy is going on
        if timestamp and timestamp > manifest.timestamp:
            if isinstance(key, PlaintextKey):
                raise Cache.RepositoryIDNotUnique()
            else:
                raise Cache.RepositoryReplay()

    def assert_key_type(self, key):
        # Make sure an encrypted repository has not been swapped for an unencrypted repository
        if self.known() and not self.key_matches(key):
            raise Cache.EncryptionMethodMismatch()

    def assert_secure(self, manifest, key, *, warn_if_unencrypted=True, lock_wait=None):
        # warn_if_unencrypted=False is only used for initializing a new repository.
        # Thus, avoiding asking about a repository that's currently initializing.
        self.assert_access_unknown(warn_if_unencrypted, manifest, key)
        self._assert_secure(manifest, key)
        logger.debug("security: repository checks ok, allowing access")

    def _assert_secure(self, manifest, key):
        self.assert_location_matches()
        self.assert_key_type(key)
        self.assert_no_manifest_replay(manifest, key)
        if not self.known():
            logger.debug("security: remembering previously unknown repository")
            self.save(manifest, key)

    def assert_access_unknown(self, warn_if_unencrypted, manifest, key):
        # warn_if_unencrypted=False is only used for initializing a new repository.
        # Thus, avoiding asking about a repository that's currently initializing.
        if not key.logically_encrypted and not self.known():
            msg = (
                "Warning: Attempting to access a previously unknown unencrypted repository!\n"
                + "Do you want to continue? [yN] "
            )
            allow_access = not warn_if_unencrypted or yes(
                msg,
                false_msg="Aborting.",
                invalid_msg="Invalid answer, aborting.",
                retry=False,
                env_var_override="BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK",
            )
            if allow_access:
                if warn_if_unencrypted:
                    logger.debug("security: remembering unknown unencrypted repository (explicitly allowed)")
                else:
                    logger.debug("security: initializing unencrypted repository")
                self.save(manifest, key)
            else:
                raise Cache.CacheInitAbortedError()


def assert_secure(repository, manifest, lock_wait):
    sm = SecurityManager(repository)
    sm.assert_secure(manifest, manifest.key, lock_wait=lock_wait)


def cache_dir(repository, path=None):
    return path or os.path.join(get_cache_dir(), repository.id_str)


class CacheConfig:
    def __init__(self, repository, path=None, lock_wait=None):
        self.repository = repository
        self.path = cache_dir(repository, path)
        logger.debug("Using %s as cache", self.path)
        self.config_path = os.path.join(self.path, "config")
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
        config.add_section("cache")
        config.set("cache", "version", "1")
        config.set("cache", "repository", self.repository.id_str)
        config.set("cache", "manifest", "")
        config.add_section("integrity")
        config.set("integrity", "manifest", "")
        with SaveFile(self.config_path) as fd:
            config.write(fd)

    def open(self):
        self.lock = Lock(os.path.join(self.path, "lock"), exclusive=True, timeout=self.lock_wait).acquire()
        self.load()

    def load(self):
        self._config = configparser.ConfigParser(interpolation=None)
        with open(self.config_path) as fd:
            self._config.read_file(fd)
        self._check_upgrade(self.config_path)
        self.id = self._config.get("cache", "repository")
        self.manifest_id = hex_to_bin(self._config.get("cache", "manifest"))
        self.ignored_features = set(parse_stringified_list(self._config.get("cache", "ignored_features", fallback="")))
        self.mandatory_features = set(
            parse_stringified_list(self._config.get("cache", "mandatory_features", fallback=""))
        )
        try:
            self.integrity = dict(self._config.items("integrity"))
            if self._config.get("cache", "manifest") != self.integrity.pop("manifest"):
                # The cache config file is updated (parsed with ConfigParser, the state of the ConfigParser
                # is modified and then written out.), not re-created.
                # Thus, older versions will leave our [integrity] section alone, making the section's data invalid.
                # Therefore, we also add the manifest ID to this section and
                # can discern whether an older version interfered by comparing the manifest IDs of this section
                # and the main [cache] section.
                self.integrity = {}
                logger.warning("Cache integrity data not available: old Borg version modified the cache.")
        except configparser.NoSectionError:
            logger.debug("Cache integrity: No integrity data found (files, chunks). Cache is from old version.")
            self.integrity = {}

    def save(self, manifest=None):
        if manifest:
            self._config.set("cache", "manifest", manifest.id_str)
            self._config.set("cache", "ignored_features", ",".join(self.ignored_features))
            self._config.set("cache", "mandatory_features", ",".join(self.mandatory_features))
            if not self._config.has_section("integrity"):
                self._config.add_section("integrity")
            for file, integrity_data in self.integrity.items():
                self._config.set("integrity", file, integrity_data)
            self._config.set("integrity", "manifest", manifest.id_str)
        with SaveFile(self.config_path) as fd:
            self._config.write(fd)

    def close(self):
        if self.lock is not None:
            self.lock.release()
            self.lock = None

    def _check_upgrade(self, config_path):
        try:
            cache_version = self._config.getint("cache", "version")
            wanted_version = 1
            if cache_version != wanted_version:
                self.close()
                raise Exception(
                    "%s has unexpected cache version %d (wanted: %d)." % (config_path, cache_version, wanted_version)
                )
        except configparser.NoSectionError:
            self.close()
            raise Exception("%s does not look like a Borg cache." % config_path) from None


def get_cache_impl():
    return os.environ.get("BORG_CACHE_IMPL", "adhocwithfiles")


class Cache:
    """Client Side cache"""

    class CacheInitAbortedError(Error):
        """Cache initialization aborted"""

        exit_mcode = 60

    class EncryptionMethodMismatch(Error):
        """Repository encryption method changed since last access, refusing to continue"""

        exit_mcode = 61

    class RepositoryAccessAborted(Error):
        """Repository access aborted"""

        exit_mcode = 62

    class RepositoryIDNotUnique(Error):
        """Cache is newer than repository - do you have multiple, independently updated repos with same ID?"""

        exit_mcode = 63

    class RepositoryReplay(Error):
        """Cache, or information obtained from the security directory is newer than repository - this is either an attack or unsafe (multiple repos with same ID)"""

        exit_mcode = 64

    @staticmethod
    def break_lock(repository, path=None):
        path = cache_dir(repository, path)
        Lock(os.path.join(path, "lock"), exclusive=True).break_lock()

    @staticmethod
    def destroy(repository, path=None):
        """destroy the cache for ``repository`` or at ``path``"""
        path = path or os.path.join(get_cache_dir(), repository.id_str)
        config = os.path.join(path, "config")
        if os.path.exists(config):
            os.remove(config)  # kill config first
            shutil.rmtree(path)

    def __new__(
        cls,
        repository,
        manifest,
        path=None,
        sync=True,
        warn_if_unencrypted=True,
        progress=False,
        lock_wait=None,
        prefer_adhoc_cache=False,
        cache_mode=FILES_CACHE_MODE_DISABLED,
        iec=False,
    ):
        def adhocwithfiles():
            return AdHocWithFilesCache(
                manifest=manifest,
                path=path,
                warn_if_unencrypted=warn_if_unencrypted,
                progress=progress,
                iec=iec,
                lock_wait=lock_wait,
                cache_mode=cache_mode,
            )

        def adhoc():
            return AdHocCache(manifest=manifest, lock_wait=lock_wait, iec=iec)

        impl = get_cache_impl()
        if impl != "cli":
            methods = dict(adhocwithfiles=adhocwithfiles, adhoc=adhoc)
            try:
                method = methods[impl]
            except KeyError:
                raise RuntimeError("Unknown BORG_CACHE_IMPL value: %s" % impl)
            return method()

        return adhoc() if prefer_adhoc_cache else adhocwithfiles()


class FilesCacheMixin:
    """
    Massively accelerate processing of unchanged files by caching their chunks list.
    With that, we can avoid having to read and chunk them to get their chunks list.
    """

    FILES_CACHE_NAME = "files"

    def __init__(self, cache_mode):
        self.cache_mode = cache_mode
        self._files = None
        self._newest_cmtime = None

    @property
    def files(self):
        if self._files is None:
            self._files = self._read_files_cache()
        return self._files

    def files_cache_name(self):
        suffix = os.environ.get("BORG_FILES_CACHE_SUFFIX", "")
        return self.FILES_CACHE_NAME + "." + suffix if suffix else self.FILES_CACHE_NAME

    def discover_files_cache_name(self, path):
        return [
            fn for fn in os.listdir(path) if fn == self.FILES_CACHE_NAME or fn.startswith(self.FILES_CACHE_NAME + ".")
        ][0]

    def _create_empty_files_cache(self, path):
        with IntegrityCheckedFile(path=os.path.join(path, self.files_cache_name()), write=True) as fd:
            pass  # empty file
        return fd.integrity_data

    def _read_files_cache(self):
        if "d" in self.cache_mode:  # d(isabled)
            return

        files = {}
        logger.debug("Reading files cache ...")
        files_cache_logger.debug("FILES-CACHE-LOAD: starting...")
        msg = None
        try:
            with IntegrityCheckedFile(
                path=os.path.join(self.path, self.files_cache_name()),
                write=False,
                integrity_data=self.cache_config.integrity.get(self.files_cache_name()),
            ) as fd:
                u = msgpack.Unpacker(use_list=True)
                while True:
                    data = fd.read(64 * 1024)
                    if not data:
                        break
                    u.feed(data)
                    try:
                        for path_hash, item in u:
                            entry = FileCacheEntry(*item)
                            # in the end, this takes about 240 Bytes per file
                            files[path_hash] = msgpack.packb(entry._replace(age=entry.age + 1))
                    except (TypeError, ValueError) as exc:
                        msg = "The files cache seems invalid. [%s]" % str(exc)
                        break
        except OSError as exc:
            msg = "The files cache can't be read. [%s]" % str(exc)
        except FileIntegrityError as fie:
            msg = "The files cache is corrupted. [%s]" % str(fie)
        if msg is not None:
            logger.warning(msg)
            logger.warning("Continuing without files cache - expect lower performance.")
            files = {}
        files_cache_logger.debug("FILES-CACHE-LOAD: finished, %d entries loaded.", len(files))
        return files

    def _write_files_cache(self, files):
        if self._newest_cmtime is None:
            # was never set because no files were modified/added
            self._newest_cmtime = 2**63 - 1  # nanoseconds, good until y2262
        ttl = int(os.environ.get("BORG_FILES_CACHE_TTL", 20))
        files_cache_logger.debug("FILES-CACHE-SAVE: starting...")
        # TODO: use something like SaveFile here, but that didn't work due to SyncFile missing .seek().
        with IntegrityCheckedFile(path=os.path.join(self.path, self.files_cache_name()), write=True) as fd:
            entry_count = 0
            for path_hash, item in files.items():
                # Only keep files seen in this backup that are older than newest cmtime seen in this backup -
                # this is to avoid issues with filesystem snapshots and cmtime granularity.
                # Also keep files from older backups that have not reached BORG_FILES_CACHE_TTL yet.
                entry = FileCacheEntry(*msgpack.unpackb(item))
                if (
                    entry.age == 0
                    and timestamp_to_int(entry.cmtime) < self._newest_cmtime
                    or entry.age > 0
                    and entry.age < ttl
                ):
                    msgpack.pack((path_hash, entry), fd)
                    entry_count += 1
        files_cache_logger.debug("FILES-CACHE-KILL: removed all old entries with age >= TTL [%d]", ttl)
        files_cache_logger.debug(
            "FILES-CACHE-KILL: removed all current entries with newest cmtime %d", self._newest_cmtime
        )
        files_cache_logger.debug("FILES-CACHE-SAVE: finished, %d remaining entries saved.", entry_count)
        return fd.integrity_data

    def file_known_and_unchanged(self, hashed_path, path_hash, st):
        """
        Check if we know the file that has this path_hash (know == it is in our files cache) and
        whether it is unchanged (the size/inode number/cmtime is same for stuff we check in this cache_mode).

        :param hashed_path: the file's path as we gave it to hash(hashed_path)
        :param path_hash: hash(hashed_path), to save some memory in the files cache
        :param st: the file's stat() result
        :return: known, chunks (known is True if we have infos about this file in the cache,
                               chunks is a list[ChunkListEntry] IF the file has not changed, otherwise None).
        """
        if not stat.S_ISREG(st.st_mode):
            return False, None
        cache_mode = self.cache_mode
        if "d" in cache_mode:  # d(isabled)
            files_cache_logger.debug("UNKNOWN: files cache disabled")
            return False, None
        # note: r(echunk) does not need the files cache in this method, but the files cache will
        # be updated and saved to disk to memorize the files. To preserve previous generations in
        # the cache, this means that it also needs to get loaded from disk first.
        if "r" in cache_mode:  # r(echunk)
            files_cache_logger.debug("UNKNOWN: rechunking enforced")
            return False, None
        entry = self.files.get(path_hash)
        if not entry:
            files_cache_logger.debug("UNKNOWN: no file metadata in cache for: %r", hashed_path)
            return False, None
        # we know the file!
        entry = FileCacheEntry(*msgpack.unpackb(entry))
        if "s" in cache_mode and entry.size != st.st_size:
            files_cache_logger.debug("KNOWN-CHANGED: file size has changed: %r", hashed_path)
            return True, None
        if "i" in cache_mode and entry.inode != st.st_ino:
            files_cache_logger.debug("KNOWN-CHANGED: file inode number has changed: %r", hashed_path)
            return True, None
        if "c" in cache_mode and timestamp_to_int(entry.cmtime) != st.st_ctime_ns:
            files_cache_logger.debug("KNOWN-CHANGED: file ctime has changed: %r", hashed_path)
            return True, None
        elif "m" in cache_mode and timestamp_to_int(entry.cmtime) != st.st_mtime_ns:
            files_cache_logger.debug("KNOWN-CHANGED: file mtime has changed: %r", hashed_path)
            return True, None
        # we ignored the inode number in the comparison above or it is still same.
        # if it is still the same, replacing it in the tuple doesn't change it.
        # if we ignored it, a reason for doing that is that files were moved to a new
        # disk / new fs (so a one-time change of inode number is expected) and we wanted
        # to avoid everything getting chunked again. to be able to re-enable the inode
        # number comparison in a future backup run (and avoid chunking everything
        # again at that time), we need to update the inode number in the cache with what
        # we see in the filesystem.
        self.files[path_hash] = msgpack.packb(entry._replace(inode=st.st_ino, age=0))
        chunks = [ChunkListEntry(*chunk) for chunk in entry.chunks]  # convert to list of namedtuple
        return True, chunks

    def memorize_file(self, hashed_path, path_hash, st, chunks):
        if not stat.S_ISREG(st.st_mode):
            return
        cache_mode = self.cache_mode
        # note: r(echunk) modes will update the files cache, d(isabled) mode won't
        if "d" in cache_mode:
            files_cache_logger.debug("FILES-CACHE-NOUPDATE: files cache disabled")
            return
        if "c" in cache_mode:
            cmtime_type = "ctime"
            cmtime_ns = safe_ns(st.st_ctime_ns)
        elif "m" in cache_mode:
            cmtime_type = "mtime"
            cmtime_ns = safe_ns(st.st_mtime_ns)
        else:  # neither 'c' nor 'm' in cache_mode, avoid UnboundLocalError
            cmtime_type = "ctime"
            cmtime_ns = safe_ns(st.st_ctime_ns)
        entry = FileCacheEntry(
            age=0, inode=st.st_ino, size=st.st_size, cmtime=int_to_timestamp(cmtime_ns), chunks=chunks
        )
        self.files[path_hash] = msgpack.packb(entry)
        self._newest_cmtime = max(self._newest_cmtime or 0, cmtime_ns)
        files_cache_logger.debug(
            "FILES-CACHE-UPDATE: put %r [has %s] <- %r",
            entry._replace(chunks="[%d entries]" % len(entry.chunks)),
            cmtime_type,
            hashed_path,
        )


class ChunksMixin:
    """
    Chunks index related code for misc. Cache implementations.
    """

    def __init__(self):
        self._chunks = None

    @property
    def chunks(self):
        if self._chunks is None:
            self._chunks = self._load_chunks_from_repo()
        return self._chunks

    def chunk_incref(self, id, size, stats):
        assert isinstance(size, int) and size > 0
        count, _size = self.chunks.incref(id)
        stats.update(size, False)
        return ChunkListEntry(id, size)

    def seen_chunk(self, id, size=None):
        entry = self.chunks.get(id, ChunkIndexEntry(0, None))
        if entry.refcount and size is not None:
            assert isinstance(entry.size, int)
            if not entry.size:
                # AdHocWithFilesCache / AdHocCache:
                # Here *size* is used to update the chunk's size information, which will be zero for existing chunks.
                self.chunks[id] = entry._replace(size=size)
        return entry.refcount

    def add_chunk(
        self,
        id,
        meta,
        data,
        *,
        stats,
        wait=True,
        compress=True,
        size=None,
        ctype=None,
        clevel=None,
        ro_type=ROBJ_FILE_STREAM,
    ):
        assert ro_type is not None
        if size is None:
            if compress:
                size = len(data)  # data is still uncompressed
            else:
                raise ValueError("when giving compressed data for a chunk, the uncompressed size must be given also")
        refcount = self.seen_chunk(id, size)
        if refcount:
            return self.chunk_incref(id, size, stats)
        cdata = self.repo_objs.format(
            id, meta, data, compress=compress, size=size, ctype=ctype, clevel=clevel, ro_type=ro_type
        )
        self.repository.put(id, cdata, wait=wait)
        self.chunks.add(id, 1, size)
        stats.update(size, not refcount)
        return ChunkListEntry(id, size)

    def _load_chunks_from_repo(self):
        logger.debug("Cache: querying the chunk IDs list from the repo...")
        chunks = ChunkIndex()
        t0 = perf_counter()
        num_requests = 0
        num_chunks = 0
        marker = None
        while True:
            result = self.repository.list(limit=LIST_SCAN_LIMIT, marker=marker)
            num_requests += 1
            if not result:
                break
            marker = result[-1][0]
            # All chunks from the repository have a refcount of MAX_VALUE, which is sticky,
            # therefore we can't/won't delete them. Chunks we added ourselves in this borg run
            # are tracked correctly.
            init_entry = ChunkIndexEntry(refcount=ChunkIndex.MAX_VALUE, size=0)  # plaintext size
            for id, stored_size in result:
                num_chunks += 1
                chunks[id] = init_entry
        # Cache does not contain the manifest.
        if not isinstance(self.repository, (Repository, RemoteRepository)):
            del chunks[self.manifest.MANIFEST_ID]
        duration = perf_counter() - t0 or 0.01
        logger.debug(
            "Cache: queried %d chunk IDs in %.2f s (%d requests), ~%s/s",
            num_chunks,
            duration,
            num_requests,
            format_file_size(num_chunks * 34 / duration),
        )
        # Chunk IDs in a list are encoded in 34 bytes: 1 byte msgpack header, 1 byte length, 32 ID bytes.
        # Protocol overhead is neglected in this calculation.
        return chunks


class AdHocWithFilesCache(FilesCacheMixin, ChunksMixin):
    """
    Like AdHocCache, but with a files cache.
    """

    def __init__(
        self,
        manifest,
        path=None,
        warn_if_unencrypted=True,
        progress=False,
        lock_wait=None,
        cache_mode=FILES_CACHE_MODE_DISABLED,
        iec=False,
    ):
        """
        :param warn_if_unencrypted: print warning if accessing unknown unencrypted repository
        :param lock_wait: timeout for lock acquisition (int [s] or None [wait forever])
        :param cache_mode: what shall be compared in the file stat infos vs. cached stat infos comparison
        """
        FilesCacheMixin.__init__(self, cache_mode)
        ChunksMixin.__init__(self)
        assert isinstance(manifest, Manifest)
        self.manifest = manifest
        self.repository = manifest.repository
        self.key = manifest.key
        self.repo_objs = manifest.repo_objs
        self.progress = progress

        self.path = cache_dir(self.repository, path)
        self.security_manager = SecurityManager(self.repository)
        self.cache_config = CacheConfig(self.repository, self.path, lock_wait)

        # Warn user before sending data to a never seen before unencrypted repository
        if not os.path.exists(self.path):
            self.security_manager.assert_access_unknown(warn_if_unencrypted, manifest, self.key)
            self.create()

        self.open()
        try:
            self.security_manager.assert_secure(manifest, self.key)

            if not self.check_cache_compatibility():
                self.wipe_cache()

            self.update_compatibility()
        except:  # noqa
            self.close()
            raise

    def __enter__(self):
        self._chunks = None
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        self._chunks = None

    def create(self):
        """Create a new empty cache at `self.path`"""
        os.makedirs(self.path)
        with open(os.path.join(self.path, "README"), "w") as fd:
            fd.write(CACHE_README)
        self.cache_config.create()
        self._create_empty_files_cache(self.path)

    def open(self):
        if not os.path.isdir(self.path):
            raise Exception("%s Does not look like a Borg cache" % self.path)
        self.cache_config.open()
        self.cache_config.load()

    def close(self):
        self.security_manager.save(self.manifest, self.key)
        pi = ProgressIndicatorMessage(msgid="cache.close")
        if self._files is not None:
            pi.output("Saving files cache")
            integrity_data = self._write_files_cache(self._files)
            self.cache_config.integrity[self.files_cache_name()] = integrity_data
        pi.output("Saving cache config")
        self.cache_config.save(self.manifest)
        self.cache_config.close()
        pi.finish()
        self.cache_config = None

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
        self._chunks = ChunkIndex()
        self._create_empty_files_cache(self.path)
        self.cache_config.manifest_id = ""
        self.cache_config._config.set("cache", "manifest", "")

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


class AdHocCache(ChunksMixin):
    """
    Ad-hoc, non-persistent cache.

    The AdHocCache does not maintain accurate reference count, nor does it provide a files cache
    (which would require persistence).
    Chunks that were not added during the current AdHocCache lifetime won't have correct size set
    (0 bytes) and will have an infinite reference count (MAX_VALUE).
    """

    def __init__(self, manifest, warn_if_unencrypted=True, lock_wait=None, iec=False):
        ChunksMixin.__init__(self)
        assert isinstance(manifest, Manifest)
        self.manifest = manifest
        self.repository = manifest.repository
        self.key = manifest.key
        self.repo_objs = manifest.repo_objs

        self.security_manager = SecurityManager(self.repository)
        self.security_manager.assert_secure(manifest, self.key, lock_wait=lock_wait)

    # Public API

    def __enter__(self):
        self._chunks = None
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self.security_manager.save(self.manifest, self.key)
        self._chunks = None

    files = None  # type: ignore
    cache_mode = "d"

    def file_known_and_unchanged(self, hashed_path, path_hash, st):
        files_cache_logger.debug("UNKNOWN: files cache not implemented")
        return False, None

    def memorize_file(self, hashed_path, path_hash, st, chunks):
        pass

import configparser
import io
import os
import shutil
import stat
from collections import namedtuple
from datetime import datetime, timezone, timedelta
from pathlib import Path
from time import perf_counter

from borgstore.backends.errors import PermissionDenied

from .logger import create_logger

logger = create_logger()

files_cache_logger = create_logger("borg.debug.files_cache")

from borgstore.store import ItemInfo

from .constants import CACHE_README, FILES_CACHE_MODE_DISABLED, ROBJ_FILE_STREAM, TIME_DIFFERS2_NS
from .checksums import xxh64
from .hashindex import ChunkIndex, ChunkIndexEntry
from .helpers import Error
from .helpers import get_cache_dir, get_security_dir
from .helpers import hex_to_bin, bin_to_hex, parse_stringified_list
from .helpers import format_file_size, safe_encode
from .helpers import safe_ns
from .helpers import yes
from .helpers import ProgressIndicatorMessage
from .helpers import msgpack
from .helpers.msgpack import int_to_timestamp, timestamp_to_int
from .item import ChunkListEntry
from .crypto.key import PlaintextKey
from .crypto.file_integrity import IntegrityCheckedFile, FileIntegrityError
from .manifest import Manifest
from .platform import SaveFile
from .remote import RemoteRepository
from .repository import LIST_SCAN_LIMIT, Repository, StoreObjectNotFound, repo_lister


def files_cache_name(archive_name, files_cache_name="files"):
    """
    Return the name of the files cache file for the given archive name.

    :param archive_name: name of the archive (ideally a series name)
    :param files_cache_name: base name of the files cache file
    :return: name of the files cache file
    """
    suffix = os.environ.get("BORG_FILES_CACHE_SUFFIX", "")
    # when using archive series, we automatically make up a separate cache file per series.
    # when not, the user may manually do that by using the env var.
    if not suffix:
        # avoid issues with too complex or long archive_name by hashing it:
        suffix = bin_to_hex(xxh64(archive_name.encode()))
    return files_cache_name + "." + suffix


def discover_files_cache_names(path, files_cache_name="files"):
    """
    Return a list of all files cache file names in the given directory.

    :param path: path to the directory to search in
    :param files_cache_name: base name of the files cache files
    :return: list of files cache file names
    """
    return [p.name for p in path.iterdir() if p.name.startswith(files_cache_name + ".")]


# chunks is a list of ChunkListEntry
FileCacheEntry = namedtuple("FileCacheEntry", "age inode size ctime mtime chunks")


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
        self.dir = Path(get_security_dir(repository.id_str, legacy=(repository.version == 1)))
        self.key_type_file = self.dir / "key-type"
        self.location_file = self.dir / "location"
        self.manifest_ts_file = self.dir / "manifest-timestamp"

    @staticmethod
    def destroy(repository, path=None):
        """destroy the security dir for ``repository`` or at ``path``"""
        path = path or get_security_dir(repository.id_str, legacy=(repository.version == 1))
        if Path(path).exists():
            shutil.rmtree(path)

    def known(self):
        return all(f.exists() for f in (self.key_type_file, self.location_file, self.manifest_ts_file))

    def key_matches(self, key):
        if not self.known():
            return False
        try:
            with self.key_type_file.open() as fd:
                type = fd.read()
                return type == str(key.TYPE)
        except OSError as exc:
            logger.warning("Could not read/parse key type file: %s", exc)

    def save(self, manifest, key):
        logger.debug("security: saving state for %s to %s", self.repository.id_str, str(self.dir))
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
            with self.location_file.open() as fd:
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
            with self.manifest_ts_file.open() as fd:
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

    def assert_secure(self, manifest, key, *, warn_if_unencrypted=True):
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


def assert_secure(repository, manifest):
    sm = SecurityManager(repository)
    sm.assert_secure(manifest, manifest.key)


def cache_dir(repository, path=None):
    return Path(path) if path else Path(get_cache_dir()) / repository.id_str


class CacheConfig:
    def __init__(self, repository, path=None):
        self.repository = repository
        self.path = cache_dir(repository, path)
        logger.debug("Using %s as cache", self.path)
        self.config_path = self.path / "config"

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def exists(self):
        return self.config_path.exists()

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
        self.load()

    def load(self):
        self._config = configparser.ConfigParser(interpolation=None)
        with self.config_path.open() as fd:
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
        pass

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
        pass

    @staticmethod
    def destroy(repository, path=None):
        """destroy the cache for ``repository`` or at ``path``"""
        path = cache_dir(repository, path)
        config = path / "config"
        if config.exists():
            config.unlink()  # kill config first
            shutil.rmtree(path)

    def __new__(
        cls,
        repository,
        manifest,
        path=None,
        sync=True,
        warn_if_unencrypted=True,
        progress=False,
        cache_mode=FILES_CACHE_MODE_DISABLED,
        iec=False,
        archive_name=None,
        start_backup=None,
    ):
        return AdHocWithFilesCache(
            manifest=manifest,
            path=path,
            warn_if_unencrypted=warn_if_unencrypted,
            progress=progress,
            iec=iec,
            cache_mode=cache_mode,
            archive_name=archive_name,
            start_backup=start_backup,
        )


class FilesCacheMixin:
    """
    Massively accelerate processing of unchanged files.
    We read the "files cache" (either from cache directory or from previous archive
    in repo) that has metadata for all "already stored" files, like size, ctime/mtime,
    inode number and chunks id/size list.
    When finding a file on disk, we use the metadata to determine if the file is unchanged.
    If so, we use the cached chunks list and skip reading/chunking the file contents.
    """

    FILES_CACHE_NAME = "files"

    def __init__(self, cache_mode, archive_name=None, start_backup=None):
        self.archive_name = archive_name  # ideally a SERIES name
        assert not ("c" in cache_mode and "m" in cache_mode)
        assert "d" in cache_mode or "c" in cache_mode or "m" in cache_mode
        self.cache_mode = cache_mode
        self._files = None
        self._newest_cmtime = 0
        self._newest_path_hashes = set()
        self.start_backup = start_backup

    def compress_entry(self, entry):
        """
        compress a files cache entry:

        - use the ChunkIndex to "compress" the entry's chunks list (256bit key + 32bit size -> 32bit index).
        - use msgpack to pack the entry (reduce memory usage by packing and having less python objects).

        Note: the result is only valid while the ChunkIndex is in memory!
        """
        assert isinstance(self.chunks, ChunkIndex), f"{self.chunks} is not a ChunkIndex"
        assert isinstance(entry, FileCacheEntry)
        compressed_chunks = []
        for id, size in entry.chunks:
            cie = self.chunks[id]  # may raise KeyError if chunk id is not in repo
            if cie.size == 0:  # size is not known in the chunks index yet
                self.chunks[id] = cie._replace(size=size)
            else:
                assert size == cie.size, f"{size} != {cie.size}"
            idx = self.chunks.k_to_idx(id)
            compressed_chunks.append(idx)
        entry = entry._replace(chunks=compressed_chunks)
        return msgpack.packb(entry)

    def decompress_entry(self, entry_packed):
        """reverse operation of compress_entry"""
        assert isinstance(self.chunks, ChunkIndex), f"{self.chunks} is not a ChunkIndex"
        assert isinstance(entry_packed, bytes)
        entry = msgpack.unpackb(entry_packed)
        entry = FileCacheEntry(*entry)
        chunks = []
        for idx in entry.chunks:
            assert isinstance(idx, int), f"{idx} is not an int"
            id = self.chunks.idx_to_k(idx)
            cie = self.chunks[id]
            assert cie.size > 0
            chunks.append((id, cie.size))
        entry = entry._replace(chunks=chunks)
        return entry

    @property
    def files(self):
        if self._files is None:
            self._files = self._read_files_cache()  # try loading from cache dir
        if self._files is None:
            self._files = self._build_files_cache()  # try loading from repository
        if self._files is None:
            self._files = {}  # start from scratch
        return self._files

    def _build_files_cache(self):
        """rebuild the files cache by reading previous archive from repository"""
        if "d" in self.cache_mode:  # d(isabled)
            return

        if not self.archive_name:
            return

        from .archive import Archive

        # get the latest archive with the IDENTICAL name, supporting archive series:
        try:
            archives = self.manifest.archives.list(match=[self.archive_name], sort_by=["ts"], last=1)
        except PermissionDenied:  # maybe repo is in write-only mode?
            archives = None
        if not archives:
            # nothing found
            return
        prev_archive = archives[0]

        files = {}
        logger.debug(
            f"Building files cache from {prev_archive.name} {prev_archive.ts} {bin_to_hex(prev_archive.id)} ..."
        )
        files_cache_logger.debug("FILES-CACHE-BUILD: starting...")
        archive = Archive(self.manifest, prev_archive.id)
        for item in archive.iter_items():
            # only put regular files' infos into the files cache:
            if stat.S_ISREG(item.mode):
                path_hash = self.key.id_hash(safe_encode(item.path))
                # keep track of the key(s) for the most recent timestamp(s):
                ctime_ns = item.ctime
                if ctime_ns > self._newest_cmtime:
                    self._newest_cmtime = ctime_ns
                    self._newest_path_hashes = {path_hash}
                elif ctime_ns == self._newest_cmtime:
                    self._newest_path_hashes.add(path_hash)
                mtime_ns = item.mtime
                if mtime_ns > self._newest_cmtime:
                    self._newest_cmtime = mtime_ns
                    self._newest_path_hashes = {path_hash}
                elif mtime_ns == self._newest_cmtime:
                    self._newest_path_hashes.add(path_hash)
                # add the file to the in-memory files cache
                entry = FileCacheEntry(
                    age=0,
                    inode=item.get("inode", 0),
                    size=item.size,
                    ctime=int_to_timestamp(ctime_ns),
                    mtime=int_to_timestamp(mtime_ns),
                    chunks=item.chunks,
                )
                # note: if the repo is an a valid state, next line should not fail with KeyError:
                files[path_hash] = self.compress_entry(entry)
        # deal with special snapshot / timestamp granularity case, see FAQ:
        for path_hash in self._newest_path_hashes:
            del files[path_hash]
        files_cache_logger.debug("FILES-CACHE-BUILD: finished, %d entries loaded.", len(files))
        return files

    def files_cache_name(self):
        return files_cache_name(self.archive_name, self.FILES_CACHE_NAME)

    def discover_files_cache_names(self, path):
        return discover_files_cache_names(path, self.FILES_CACHE_NAME)

    def _read_files_cache(self):
        """read files cache from cache directory"""
        if "d" in self.cache_mode:  # d(isabled)
            return

        files = {}
        logger.debug("Reading files cache ...")
        files_cache_logger.debug("FILES-CACHE-LOAD: starting...")
        msg = None
        try:
            with IntegrityCheckedFile(
                path=str(self.path / self.files_cache_name()),
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
                        for path_hash, entry in u:
                            entry = FileCacheEntry(*entry)
                            entry = entry._replace(age=entry.age + 1)
                            try:
                                files[path_hash] = self.compress_entry(entry)
                            except KeyError:
                                # repo is missing a chunk referenced from entry
                                logger.debug(f"compress_entry failed for {entry}, skipping.")
                    except (TypeError, ValueError) as exc:
                        msg = "The files cache seems invalid. [%s]" % str(exc)
                        break
        except OSError as exc:
            msg = "The files cache can't be read. [%s]" % str(exc)
        except FileIntegrityError as fie:
            msg = "The files cache is corrupted. [%s]" % str(fie)
        if msg is not None:
            logger.debug(msg)
            files = None
        files_cache_logger.debug("FILES-CACHE-LOAD: finished, %d entries loaded.", len(files or {}))
        return files

    def _write_files_cache(self, files):
        """write files cache to cache directory"""
        max_time_ns = 2**63 - 1  # nanoseconds, good until y2262
        # _self._newest_cmtime might be None if it was never set because no files were modified/added.
        newest_cmtime = self._newest_cmtime if self._newest_cmtime is not None else max_time_ns
        start_backup_time = self.start_backup - TIME_DIFFERS2_NS if self.start_backup is not None else max_time_ns
        # we don't want to persist files cache entries of potentially problematic files:
        discard_after = min(newest_cmtime, start_backup_time)
        ttl = int(os.environ.get("BORG_FILES_CACHE_TTL", 2))
        files_cache_logger.debug("FILES-CACHE-SAVE: starting...")
        # TODO: use something like SaveFile here, but that didn't work due to SyncFile missing .seek().
        with IntegrityCheckedFile(path=str(self.path / self.files_cache_name()), write=True) as fd:
            entries = 0
            age_discarded = 0
            race_discarded = 0
            for path_hash, entry in files.items():
                entry = self.decompress_entry(entry)
                if entry.age == 0:  # current entries
                    if max(timestamp_to_int(entry.ctime), timestamp_to_int(entry.mtime)) < discard_after:
                        # Only keep files seen in this backup that old enough not to suffer race conditions relating
                        # to filesystem snapshots and ctime/mtime granularity or being modified while we read them.
                        keep = True
                    else:
                        keep = False
                        race_discarded += 1
                else:  # old entries
                    if entry.age < ttl:
                        # Also keep files from older backups that have not reached BORG_FILES_CACHE_TTL yet.
                        keep = True
                    else:
                        keep = False
                        age_discarded += 1
                if keep:
                    msgpack.pack((path_hash, entry), fd)
                    entries += 1
        files_cache_logger.debug(f"FILES-CACHE-KILL: removed {age_discarded} entries with age >= TTL [{ttl}]")
        t_str = datetime.fromtimestamp(discard_after / 1e9, timezone.utc).isoformat()
        files_cache_logger.debug(f"FILES-CACHE-KILL: removed {race_discarded} entries with ctime/mtime >= {t_str}")
        files_cache_logger.debug(f"FILES-CACHE-SAVE: finished, {entries} remaining entries saved.")
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
        entry = self.decompress_entry(entry)
        if "s" in cache_mode and entry.size != st.st_size:
            files_cache_logger.debug("KNOWN-CHANGED: file size has changed: %r", hashed_path)
            return True, None
        if "i" in cache_mode and entry.inode != st.st_ino:
            files_cache_logger.debug("KNOWN-CHANGED: file inode number has changed: %r", hashed_path)
            return True, None
        ctime = int_to_timestamp(safe_ns(st.st_ctime_ns))
        if "c" in cache_mode and entry.ctime != ctime:
            files_cache_logger.debug("KNOWN-CHANGED: file ctime has changed: %r", hashed_path)
            return True, None
        mtime = int_to_timestamp(safe_ns(st.st_mtime_ns))
        if "m" in cache_mode and entry.mtime != mtime:
            files_cache_logger.debug("KNOWN-CHANGED: file mtime has changed: %r", hashed_path)
            return True, None
        # V = any of the inode number, mtime, ctime values.
        # we ignored V in the comparison above or it is still the same value.
        # if it is still the same, replacing it in the tuple doesn't change it.
        # if we ignored it, a reason for doing that is that files were moved/copied to
        # a new disk / new fs (so a one-time change of V is expected) and we wanted
        # to avoid everything getting chunked again. to be able to re-enable the
        # V comparison in a future backup run (and avoid chunking everything again at
        # that time), we need to update V in the cache with what we see in the filesystem.
        entry = entry._replace(inode=st.st_ino, ctime=ctime, mtime=mtime, age=0)
        self.files[path_hash] = self.compress_entry(entry)
        chunks = [ChunkListEntry(*chunk) for chunk in entry.chunks]  # convert to list of namedtuple
        return True, chunks

    def memorize_file(self, hashed_path, path_hash, st, chunks):
        if not stat.S_ISREG(st.st_mode):
            return
        # note: r(echunk) modes will update the files cache, d(isabled) mode won't
        if "d" in self.cache_mode:
            files_cache_logger.debug("FILES-CACHE-NOUPDATE: files cache disabled")
            return
        ctime_ns = safe_ns(st.st_ctime_ns)
        mtime_ns = safe_ns(st.st_mtime_ns)
        entry = FileCacheEntry(
            age=0,
            inode=st.st_ino,
            size=st.st_size,
            ctime=int_to_timestamp(ctime_ns),
            mtime=int_to_timestamp(mtime_ns),
            chunks=chunks,
        )
        self.files[path_hash] = self.compress_entry(entry)
        self._newest_cmtime = max(self._newest_cmtime or 0, ctime_ns)
        self._newest_cmtime = max(self._newest_cmtime or 0, mtime_ns)
        files_cache_logger.debug(
            "FILES-CACHE-UPDATE: put %r <- %r", entry._replace(chunks="[%d entries]" % len(entry.chunks)), hashed_path
        )


def try_upgrade_to_b14(repository):
    # TODO: remove this before 2.0.0 release
    # we just delete any present chunk index cache here, it is invalid due to the
    # refcount -> flags change we did and due to the different CHUNKINDEX_HASH_SEED.
    for name in "chunks_hash", "chunks":
        try:
            repository.store_delete(f"cache/{name}")
        except (Repository.ObjectNotFound, StoreObjectNotFound):
            pass  # likely already upgraded


def list_chunkindex_hashes(repository):
    hashes = []
    for info in repository.store_list("cache"):
        info = ItemInfo(*info)  # RPC does not give namedtuple
        if info.name.startswith("chunks."):
            hash = info.name.removeprefix("chunks.")
            hashes.append(hash)
    hashes = sorted(hashes)
    logger.debug(f"cached chunk indexes: {hashes}")
    return hashes


def delete_chunkindex_cache(repository):
    hashes = list_chunkindex_hashes(repository)
    for hash in hashes:
        cache_name = f"cache/chunks.{hash}"
        try:
            repository.store_delete(cache_name)
        except (Repository.ObjectNotFound, StoreObjectNotFound):
            # TODO: ^ seem like RemoteRepository raises Repository.ONF instead of StoreONF
            pass
    logger.debug(f"cached chunk indexes deleted: {hashes}")


CHUNKINDEX_HASH_SEED = 3


def write_chunkindex_to_repo_cache(
    repository, chunks, *, incremental=True, clear=False, force_write=False, delete_other=False, delete_these=None
):
    # for now, we don't want to serialize the flags or the size, just the keys (chunk IDs):
    cleaned_value = ChunkIndexEntry(flags=ChunkIndex.F_NONE, size=0)
    chunks_to_write = ChunkIndex()
    # incremental==True:
    # the borghash code has no means to only serialize the F_NEW table entries,
    # thus we copy only the new entries to a temporary table.
    # incremental==False:
    # maybe copying the stuff into a new ChunkIndex is not needed here,
    # but for simplicity, we do it anyway.
    for key, _ in chunks.iteritems(only_new=incremental):
        chunks_to_write[key] = cleaned_value
    with io.BytesIO() as f:
        chunks_to_write.write(f)
        data = f.getvalue()
    logger.debug(f"caching {len(chunks_to_write)} chunks (incremental={incremental}).")
    chunks_to_write.clear()  # free memory of the temporary table
    if clear:
        # if we don't need the in-memory chunks index anymore:
        chunks.clear()  # free memory, immediately
    new_hash = bin_to_hex(xxh64(data, seed=CHUNKINDEX_HASH_SEED))
    cached_hashes = list_chunkindex_hashes(repository)
    if force_write or new_hash not in cached_hashes:
        # when an updated chunks index is stored into the cache, we also store its hash as part of the name.
        # when a client is loading the chunks index from a cache, it has to compare its xxh64
        # hash against the hash in its name. if it is the same, the cache is valid.
        # if it is different, the cache is either corrupted or out of date and has to be discarded.
        # when some functionality is DELETING chunks from the repository, it has to delete
        # all existing cache/chunks.* and maybe write a new, valid cache/chunks.<hash>,
        # so that all clients will discard any client-local chunks index caches.
        cache_name = f"cache/chunks.{new_hash}"
        logger.debug(f"caching chunks index as {cache_name} in repository...")
        repository.store_store(cache_name, data)
        # we have successfully stored to the repository, so we can clear all F_NEW flags now:
        chunks.clear_new()
        # delete some not needed cached chunk indexes, but never the one we just wrote:
        if delete_other:
            delete_these = set(cached_hashes) - {new_hash}
        elif delete_these:
            delete_these = set(delete_these) - {new_hash}
        else:
            delete_these = set()
        for hash in delete_these:
            cache_name = f"cache/chunks.{hash}"
            try:
                repository.store_delete(cache_name)
            except (Repository.ObjectNotFound, StoreObjectNotFound):
                # TODO: ^ seem like RemoteRepository raises Repository.ONF instead of StoreONF
                pass
        if delete_these:
            logger.debug(f"cached chunk indexes deleted: {delete_these}")
    return new_hash


def read_chunkindex_from_repo_cache(repository, hash):
    cache_name = f"cache/chunks.{hash}"
    logger.debug(f"trying to load {cache_name} from the repo...")
    try:
        chunks_data = repository.store_load(cache_name)
    except (Repository.ObjectNotFound, StoreObjectNotFound):
        # TODO: ^ seem like RemoteRepository raises Repository.ONF instead of StoreONF
        logger.debug(f"{cache_name} not found in the repository.")
    else:
        if xxh64(chunks_data, seed=CHUNKINDEX_HASH_SEED) == hex_to_bin(hash):
            logger.debug(f"{cache_name} is valid.")
            with io.BytesIO(chunks_data) as f:
                chunks = ChunkIndex.read(f)
            return chunks
        else:
            logger.debug(f"{cache_name} is invalid.")


def build_chunkindex_from_repo(repository, *, disable_caches=False, cache_immediately=False):
    try_upgrade_to_b14(repository)
    # first, try to build a fresh, mostly complete chunk index from centrally cached chunk indexes:
    if not disable_caches:
        hashes = list_chunkindex_hashes(repository)
        if hashes:  # we have at least one cached chunk index!
            merged = 0
            chunks = ChunkIndex()  # we'll merge all we find into this
            for hash in hashes:
                chunks_to_merge = read_chunkindex_from_repo_cache(repository, hash)
                if chunks_to_merge is not None:
                    logger.debug(f"cached chunk index {hash} gets merged...")
                    for k, v in chunks_to_merge.items():
                        chunks[k] = v
                    merged += 1
                    chunks_to_merge.clear()
            if merged > 0:
                if merged > 1 and cache_immediately:
                    # immediately update cache/chunks, so we don't have to merge these again:
                    write_chunkindex_to_repo_cache(
                        repository, chunks, clear=False, force_write=True, delete_these=hashes
                    )
                else:
                    chunks.clear_new()
                return chunks
    # if we didn't get anything from the cache, compute the ChunkIndex the slow way:
    logger.debug("querying the chunk IDs list from the repo...")
    chunks = ChunkIndex()
    t0 = perf_counter()
    num_chunks = 0
    # The repo says it has these chunks, so we assume they are referenced/used chunks.
    # We do not know the plaintext size (!= stored_size), thus we set size = 0.
    init_entry = ChunkIndexEntry(flags=ChunkIndex.F_USED, size=0)
    for id, stored_size in repo_lister(repository, limit=LIST_SCAN_LIMIT):
        num_chunks += 1
        chunks[id] = init_entry
    # Cache does not contain the manifest.
    if not isinstance(repository, (Repository, RemoteRepository)):
        del chunks[Manifest.MANIFEST_ID]
    duration = perf_counter() - t0 or 0.001
    # Chunk IDs in a list are encoded in 34 bytes: 1 byte msgpack header, 1 byte length, 32 ID bytes.
    # Protocol overhead is neglected in this calculation.
    speed = format_file_size(num_chunks * 34 / duration)
    logger.debug(f"queried {num_chunks} chunk IDs in {duration} s, ~{speed}/s")
    if cache_immediately:
        # immediately update cache/chunks, so we only rarely have to do it the slow way:
        write_chunkindex_to_repo_cache(repository, chunks, clear=False, force_write=True, delete_other=True)
    return chunks


class ChunksMixin:
    """
    Chunks index related code for misc. Cache implementations.
    """

    def __init__(self):
        self._chunks = None
        self.last_refresh_dt = datetime.now(timezone.utc)
        self.refresh_td = timedelta(seconds=60)
        self.chunks_cache_last_write = datetime.now(timezone.utc)
        self.chunks_cache_write_td = timedelta(seconds=600)

    @property
    def chunks(self):
        if self._chunks is None:
            self._chunks = build_chunkindex_from_repo(self.repository, cache_immediately=True)
        return self._chunks

    def seen_chunk(self, id, size=None):
        entry = self.chunks.get(id)
        entry_exists = entry is not None
        if entry_exists and size is not None:
            if entry.size == 0:
                # AdHocWithFilesCache:
                # Here *size* is used to update the chunk's size information, which will be zero for existing chunks.
                self.chunks[id] = entry._replace(size=size)
            else:
                # in case we already have a size information in the entry, check consistency:
                assert size == entry.size
        return entry_exists

    def reuse_chunk(self, id, size, stats):
        assert isinstance(size, int) and size > 0
        stats.update(size, False)
        return ChunkListEntry(id, size)

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
        now = datetime.now(timezone.utc)
        self._maybe_write_chunks_cache(now)
        exists = self.seen_chunk(id, size)
        if exists:
            # if borg create is processing lots of unchanged files (no content and not metadata changes),
            # there could be a long time without any repository operations and the repo lock would get stale.
            self.refresh_lock(now)
            return self.reuse_chunk(id, size, stats)
        cdata = self.repo_objs.format(
            id, meta, data, compress=compress, size=size, ctype=ctype, clevel=clevel, ro_type=ro_type
        )
        self.repository.put(id, cdata, wait=wait)
        self.last_refresh_dt = now  # .put also refreshed the lock
        self.chunks.add(id, size)
        stats.update(size, not exists)
        return ChunkListEntry(id, size)

    def _maybe_write_chunks_cache(self, now, force=False, clear=False):
        if force or now > self.chunks_cache_last_write + self.chunks_cache_write_td:
            if self._chunks is not None:
                write_chunkindex_to_repo_cache(self.repository, self._chunks, clear=clear)
            self.chunks_cache_last_write = now

    def refresh_lock(self, now):
        if now > self.last_refresh_dt + self.refresh_td:
            # the repository lock needs to get refreshed regularly, or it will be killed as stale.
            # refreshing the lock is not part of the repository API, so we do it indirectly via repository.info.
            self.repository.info()
            self.last_refresh_dt = now


class AdHocWithFilesCache(FilesCacheMixin, ChunksMixin):
    """
    An ad-hoc chunks and files cache.

    Chunks: it does not maintain accurate reference count.
    Chunks that were not added during the current lifetime won't have correct size set (0 bytes)
    and will have an infinite reference count (MAX_VALUE).

    Files: if a previous_archive_id is given, ad-hoc build a in-memory files cache from that archive.
    """

    def __init__(
        self,
        manifest,
        path=None,
        warn_if_unencrypted=True,
        progress=False,
        cache_mode=FILES_CACHE_MODE_DISABLED,
        iec=False,
        archive_name=None,
        start_backup=None,
    ):
        """
        :param warn_if_unencrypted: print warning if accessing unknown unencrypted repository
        :param cache_mode: what shall be compared in the file stat infos vs. cached stat infos comparison
        """
        FilesCacheMixin.__init__(self, cache_mode, archive_name, start_backup)
        ChunksMixin.__init__(self)
        assert isinstance(manifest, Manifest)
        self.manifest = manifest
        self.repository = manifest.repository
        self.key = manifest.key
        self.repo_objs = manifest.repo_objs
        self.progress = progress

        self.path = cache_dir(self.repository, path)
        self.security_manager = SecurityManager(self.repository)
        self.cache_config = CacheConfig(self.repository, self.path)

        # Warn user before sending data to a never seen before unencrypted repository
        if not self.path.exists():
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
        self.path.mkdir(parents=True, exist_ok=True)
        with open(self.path / "README", "w") as fd:
            fd.write(CACHE_README)
        self.cache_config.create()

    def open(self):
        if not self.path.is_dir():
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
        if self._chunks is not None:
            for key, value in sorted(self._chunks.stats.items()):
                logger.debug(f"Chunks index stats: {key}: {value}")
            pi.output("Saving chunks cache")
            # note: cache/chunks.* in repo has a different integrity mechanism
            now = datetime.now(timezone.utc)
            self._maybe_write_chunks_cache(now, force=True, clear=True)
            self._chunks = None  # nothing there (cleared!)
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

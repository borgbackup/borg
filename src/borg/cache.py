import configparser
import hashlib
import io
import os
import shutil
import stat
import struct
from collections import namedtuple
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter

from borgstore.backends.errors import PermissionDenied

from .logger import create_logger

logger = create_logger()

files_cache_logger = create_logger("borg.debug.files_cache")

from borgstore.store import ItemInfo

from .constants import CACHE_README, FILES_CACHE_MODE_DISABLED, ROBJ_FILE_STREAM, TIME_DIFFERS2_NS
from .constants import CHUNKINDEX_FRAGMENT_ENTRIES_MIN, CHUNKINDEX_FRAGMENT_ENTRIES_MAX
from .constants import CHUNKINDEX_SMALL_FRAGMENT_CAP, CHUNKINDEX_MERGE_ATTEMPTS
from .hashindex import ChunkIndex, ChunkIndexEntry, ChunkIndexEntryFormat
from .helpers import get_cache_dir
from .helpers import hex_to_bin, bin_to_hex, parse_stringified_list
from .helpers import format_file_size, safe_encode
from .helpers import safe_ns
from .helpers import ProgressIndicatorMessage
from .helpers import msgpack
from .helpers.msgpack import int_to_timestamp, timestamp_to_int
from .item import ChunkListEntry
from .crypto.file_integrity import IntegrityCheckedFile, FileIntegrityError
from .manifest import Manifest
from .platform import SaveFile
from .repository import Repository, StoreObjectNotFound, PackReader
from .security import SecurityManager, assert_secure  # noqa: F401


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
        suffix = hashlib.sha256(archive_name.encode()).hexdigest()
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

    from .security import (
        CacheInitAbortedError,
        EncryptionMethodMismatch,
        RepositoryAccessAborted,
        RepositoryIDNotUnique,
        RepositoryReplay,
    )  # noqa: F401

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
        self._newest_cmtime = None  # None means "no file was chunked/seen yet", see _write_files_cache
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
                if self._newest_cmtime is None or ctime_ns > self._newest_cmtime:
                    self._newest_cmtime = ctime_ns
                    self._newest_path_hashes = {path_hash}
                elif ctime_ns == self._newest_cmtime:
                    self._newest_path_hashes.add(path_hash)
                mtime_ns = item.mtime
                if self._newest_cmtime is None or mtime_ns > self._newest_cmtime:
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
        cache_path = str(self.path / self.files_cache_name())
        with SaveFile(cache_path, binary=True) as sync_file:
            with IntegrityCheckedFile(path=cache_path, write=True, override_fd=sync_file) as fd:
                entries = 0
                age_discarded = 0
                race_discarded = 0
                broken_discarded = 0
                for path_hash, entry in files.items():
                    try:
                        entry = self.decompress_entry(entry)
                    except KeyError:
                        # the entry references a chunk that is no longer in the chunks index (e.g.
                        # after an aborted / out-of-space backup rolled back pending chunks). such an
                        # entry is unusable; drop it rather than crash while saving the cache — the
                        # file will simply be re-chunked in a future backup. this mirrors the
                        # compress_entry KeyError handling in _read_files_cache.
                        broken_discarded += 1
                        continue
                    if entry.age == 0:  # current entries
                        if max(timestamp_to_int(entry.ctime), timestamp_to_int(entry.mtime)) < discard_after:
                            # Only keep files seen in this backup that old enough not to suffer race conditions
                            # relating to filesystem snapshots and ctime/mtime granularity or being modified
                            # while we read them.
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
            integrity_data = fd.integrity_data
        files_cache_logger.debug(f"FILES-CACHE-KILL: removed {age_discarded} entries with age >= TTL [{ttl}]")
        if broken_discarded:
            files_cache_logger.debug(f"FILES-CACHE-KILL: removed {broken_discarded} entries referencing missing chunks")
        t_str = datetime.fromtimestamp(discard_after / 1e9, UTC).isoformat()
        files_cache_logger.debug(f"FILES-CACHE-KILL: removed {race_discarded} entries with ctime/mtime >= {t_str}")
        files_cache_logger.debug(f"FILES-CACHE-SAVE: finished, {entries} remaining entries saved.")
        return integrity_data

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
        try:
            entry = self.decompress_entry(entry)
        except KeyError:
            # the cached entry references a chunk that is no longer in the chunks index (e.g. after
            # an aborted / out-of-space backup); treat the file as unknown so it gets re-chunked.
            files_cache_logger.debug("UNKNOWN: cached entry references a missing chunk: %r", hashed_path)
            return False, None
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


def list_chunkindex_hashes(repository):
    hashes = []
    for info in repository.store_list("index"):
        info = ItemInfo(*info)  # RPC does not give namedtuple
        # in the index/ namespace, each object's name is the sha256 hash of its content.
        hashes.append(info.name)
    hashes = sorted(hashes)
    logger.debug(f"chunk indexes: {hashes}")
    return hashes


def chunkindex_fragment_entry_size():
    """Approximate on-disk bytes per serialized chunks-index entry.

    Derived from the actual ChunkIndex layout instead of a hardcoded constant, so it tracks any change
    to the entry format automatically: a fragment stores each entry as its 32-byte key followed by the
    struct-packed value (ChunkIndexEntryFormat, little-endian as borghash serializes it). Only used to
    estimate a fragment's entry count from its stored byte size (see list_chunkindex_fragments), so we
    can classify fragments without loading them; the small fixed header is ignored (negligible for the
    fragment sizes we care about).
    """
    key_size = 32  # a chunk id is a 256bit / 32 byte hash
    value_size = struct.calcsize("<" + "".join(ChunkIndexEntryFormat))
    return key_size + value_size


def list_chunkindex_fragments(repository):
    """Like list_chunkindex_hashes, but also return each fragment's approximate entry count.

    The entry count is estimated from the stored object's byte size (chunkindex_fragment_entry_size()
    bytes per entry), so we can classify fragments (small vs. sealed) without loading them. The estimate
    ignores the small fixed header, which is negligible for the fragment sizes we care about.
    Returns a list of (name, approx_entries) tuples, sorted by name.
    """
    entry_size = chunkindex_fragment_entry_size()
    fragments = []
    for info in repository.store_list("index"):
        info = ItemInfo(*info)  # RPC does not give namedtuple
        fragments.append((info.name, info.size // entry_size))
    fragments.sort()
    return fragments


def delete_chunkindex_from_repo(repository):
    hashes = list_chunkindex_hashes(repository)
    for hash in hashes:
        index_name = f"index/{hash}"
        try:
            repository.store_delete(index_name)
        except StoreObjectNotFound:
            pass
    logger.debug(f"chunk indexes deleted: {hashes}")
    # the in-memory index is now stale; drop it so close() does not write it back into the
    # index we just deleted. the next .chunks access rebuilds it from actual repo contents.
    repository.invalidate_chunk_index()


def _store_chunkindex_fragment(repository, batch, stored_hashes, *, force_write):
    """Serialize a temporary ChunkIndex `batch` and store it as an index/<sha256> fragment.

    We don't serialize the flags or the size, so callers pass entries with those zeroed. The object
    is stored under index/<hash>, where <hash> is the sha256 of its content, so borgstore can verify
    it like any other object; an incompatible format from a different borg version is rejected by
    borghash's own versioned header (MAGIC + VERSION) when read back.

    Returns (new_hash, stored) where `stored` is True iff we actually wrote to the repository (we skip
    the write if a fragment with the same content hash already exists and force_write is not set).
    """
    with io.BytesIO() as f:
        batch.write(f)
        data = f.getvalue()
    new_hash = hashlib.sha256(data).hexdigest()
    stored = False
    if force_write or new_hash not in stored_hashes:
        index_name = f"index/{new_hash}"
        logger.debug(f"storing chunks index as {index_name} in repository...")
        repository.store_store(index_name, data)
        stored = True
    return new_hash, stored


def write_chunkindex_to_repo(
    repository, chunks, *, incremental=True, clear=False, force_write=False, delete_other=False, delete_these=None
):
    # incremental controls *which* entries we write: only the F_NEW ones (a backup's new chunks) when
    #   True, else the whole index. borghash cannot serialize just the F_NEW entries, so either way we
    #   copy the selected entries into temporary table(s).
    # Regardless of that, we always split the output into fragments of at most
    #   CHUNKINDEX_FRAGMENT_ENTRIES_MAX entries, so no single fragment gets too large (even the one
    #   incremental fragment of a huge initial backup). See repack_chunkindex for why we prefer many
    #   bounded, immutable fragments over one big index.
    max_entries = CHUNKINDEX_FRAGMENT_ENTRIES_MAX
    # the fragment set present in the repo before we start writing:
    stored_hashes = set(list_chunkindex_hashes(repository))
    new_hashes = set()  # content hashes of the fragments that make up the index we are writing now
    stored_anything = False
    fragments_written = 0

    def flush(batch):
        nonlocal stored_anything, fragments_written
        count = len(batch)
        if count == 0 and not force_write:
            # don't persist an empty fragment: if it became the only index/* (e.g. right after
            # delete_chunkindex_from_repo()), build_chunkindex_from_repo() would return it as-is
            # instead of rebuilding from the repo. with nothing to write, the repo is already correct.
            logger.debug("no new chunks to persist; not writing an empty chunk index fragment.")
            batch.clear()
            return
        new_hash, stored = _store_chunkindex_fragment(repository, batch, stored_hashes, force_write=force_write)
        batch.clear()  # free memory of the temporary table
        new_hashes.add(new_hash)
        if stored:
            stored_anything = True
            fragments_written += 1

    # sort the selected keys, so that an identical set of entries always produces identical
    # fragments (identical content hashes), no matter in which order the entries were inserted
    # into the hash table. this makes writing/repacking idempotent and convergent across clients:
    # a fragment that already exists in the repo is not stored again (see _store_chunkindex_fragment)
    # and no differently-partitioned duplicates of the same entries can pile up.
    keys = sorted(key for key, _ in chunks.iteritems(only_new=incremental))
    total = len(keys)
    # partition the selected entries into batches of at most max_entries entries and store each:
    batch = ChunkIndex()
    n = 0
    for key in keys:
        # for now, we don't want to serialize the flags or the size:
        batch[key] = chunks[key]._replace(flags=ChunkIndex.F_NONE, size=0)
        n += 1
        if n >= max_entries:
            flush(batch)
            batch = ChunkIndex()
            n = 0
    if n > 0 or total == 0:
        # trailing, partially filled batch - or nothing to write at all:
        # let flush handle force_write / the empty-index short-circuit.
        flush(batch)
    else:
        batch.clear()  # entries were an exact multiple of max_entries; no trailing batch to write

    logger.debug(f"cached {total} chunks (incremental={incremental}) in {fragments_written} fragment(s).")
    if clear:
        # if we don't need the in-memory chunks index anymore:
        chunks.clear()  # free memory, immediately
    if stored_anything:
        # we have successfully stored to the repository, so we can clear all F_NEW flags now:
        chunks.clear_new()

    # delete some no longer needed index objects, but never the ones we just wrote. we gate this on
    # new_hashes (the fragments that make up the index we just wrote), not on whether we actually
    # uploaded them: a fragment can be dedupe-skipped because its content already exists in the repo
    # (see _store_chunkindex_fragment), and in that case the replacement is verifiably present, so
    # deleting the superseded fragments is still safe. this also makes repack idempotent -- if a
    # previous repack crashed after storing but before deleting, the next one re-derives the same
    # fragments, dedupe-skips the uploads, and still deletes the small sources. when there is nothing
    # to write (new_hashes empty, e.g. an empty incremental index), we skip deletion so we never leave
    # the repo without an index.
    if new_hashes and (delete_other or delete_these):
        if delete_other:
            delete_these = set(stored_hashes) - new_hashes
        else:
            delete_these = set(delete_these) - new_hashes
        for hash in delete_these:
            index_name = f"index/{hash}"
            try:
                repository.store_delete(index_name)
            except StoreObjectNotFound:
                pass
        if delete_these:
            logger.debug(f"chunk indexes deleted: {delete_these}")
    return new_hashes


def read_chunkindex_from_repo(repository, hash):
    index_name = f"index/{hash}"
    logger.debug(f"trying to load {index_name} from the repo...")
    try:
        chunks_data = repository.store_load(index_name)
    except StoreObjectNotFound:
        logger.debug(f"{index_name} not found in the repository.")
    else:
        if hashlib.sha256(chunks_data).digest() == hex_to_bin(hash):
            logger.debug(f"{index_name} is valid.")
            with io.BytesIO(chunks_data) as f:
                chunks = ChunkIndex.read(f)
            return chunks
        else:
            logger.debug(f"{index_name} is invalid.")


def repack_chunkindex(repository):
    """Consolidate small chunk-index fragments to keep their number and size in a healthy range.

    The chunks index lives in the repo as immutable, content-addressed index/<hash> fragments.
    Ordinary backups append a small incremental fragment each, so small fragments pile up over time.
    This merges the small (< CHUNKINDEX_FRAGMENT_ENTRIES_MIN entries) fragments into fragments of up
    to CHUNKINDEX_FRAGMENT_ENTRIES_MAX entries and deletes the small sources. Fragments already in
    range are left untouched, so they stay immutable (and, once index/ is cache-backed, stay cached
    for every client instead of being invalidated by an all-in-one consolidation).

    Merging is deferred: we only act when we can seal at least one full fragment (the small entries
    sum to >= MIN) or when too many small fragments have piled up (more than
    CHUNKINDEX_SMALL_FRAGMENT_CAP), so we don't rewrite a slowly growing fragment on every backup.
    """
    small = [
        (name, approx)
        for name, approx in list_chunkindex_fragments(repository)
        if approx < CHUNKINDEX_FRAGMENT_ENTRIES_MIN
    ]
    if len(small) < 2:
        return  # nothing to gain from merging zero or one fragment
    small_total = sum(approx for _, approx in small)
    if small_total < CHUNKINDEX_FRAGMENT_ENTRIES_MIN and len(small) <= CHUNKINDEX_SMALL_FRAGMENT_CAP:
        # can't seal a full fragment yet and not too many have piled up: defer.
        return
    logger.debug(f"repacking {len(small)} small chunk index fragments (~{small_total} entries)...")
    merged = ChunkIndex()
    merged_hashes = []
    for name, _ in small:
        fragment = read_chunkindex_from_repo(repository, name)
        if fragment is None:
            # gone or invalid (e.g. deleted by another client); just don't merge it.
            continue
        for k, v in fragment.items():
            merged[k] = v
        merged_hashes.append(name)
        fragment.clear()
    if not merged_hashes:
        return
    # write the merged entries split into bounded (<= MAX) fragments and delete the small sources.
    # force_write=False so a merged fragment whose content already exists in the repo is dedupe-skipped
    # rather than re-uploaded; write_chunkindex_to_repo still deletes the small sources because deletion
    # is gated on the fragment set being present, not on a fresh upload (so repack is idempotent and
    # avoids redundant uploads). write_chunkindex_to_repo also never deletes a hash it just wrote, so a
    # fragment whose content is unchanged by the merge survives rather than being deleted and re-created.
    write_chunkindex_to_repo(
        repository, merged, incremental=False, clear=True, force_write=False, delete_these=merged_hashes
    )


def build_chunkindex_from_repo(
    repository, *, disable_caches=False, cache_immediately=False, init_flags=ChunkIndex.F_USED
):
    # first, try to build a fresh, mostly complete chunk index from centrally cached chunk indexes:
    if not disable_caches:
        # a concurrent repack_chunkindex (another client, shared lock) deletes the small fragments it
        # merged - only after storing the merged replacement, so no entries are ever lost, but a
        # fragment we just listed can vanish before we load it. the index must be built from ALL
        # fragments or not at all: a partially merged index would miss chunks that exist in the repo
        # (spurious ObjectNotFound, lost deduplication). so on a failed load, re-list and retry -
        # the fresh listing contains the replacement fragment. if we cannot get a complete, consistent
        # set (e.g. a persistently unreadable fragment), fall through to the slow rebuild instead.
        for _ in range(CHUNKINDEX_MERGE_ATTEMPTS):
            hashes = list_chunkindex_hashes(repository)
            if not hashes:  # no cached chunk index available
                break
            chunks = ChunkIndex()  # we'll merge all fragments into this
            complete = True
            for hash in hashes:
                chunks_to_merge = read_chunkindex_from_repo(repository, hash)
                if chunks_to_merge is None:
                    logger.debug(f"cached chunk index {hash} vanished or is invalid, restarting the merge...")
                    complete = False
                    break
                logger.debug(f"cached chunk index {hash} gets merged...")
                for k, v in chunks_to_merge.items():
                    chunks[k] = v
                chunks_to_merge.clear()
            if complete:
                if len(hashes) > 1 and cache_immediately:
                    # consolidate small fragments on the repo so they don't pile up. this is a
                    # bounded repack: it does not collapse large, already-sealed fragments, so those
                    # stay immutable (and cache-stable for other clients) rather than being re-uploaded.
                    repack_chunkindex(repository)
                # merging set F_NEW on every entry (see ChunkIndex.__setitem__); clear it, the repo
                # already holds these entries in its fragments.
                chunks.clear_new()
                return chunks
            chunks.clear()  # free the partial merge before retrying
        else:
            logger.warning("could not read a complete set of cached chunk index fragments, rebuilding the index.")
    # if we didn't get anything from the cache, compute the ChunkIndex the slow way:
    logger.debug("rebuilding the chunk index from the repo the slow way...")
    chunks = ChunkIndex()
    t0 = perf_counter()
    num_chunks = 0
    # By default we assume the repo's chunks are used; callers that compute usage themselves
    # (e.g. compact) pass init_flags=F_NONE. Plaintext size is unknown here (!= stored size), so size=0.
    # Every caller passes a (modern) Repository; legacy borg 1.x repos never reach here (transfer reads
    # their archives directly and never builds a chunk index for them), so there is no legacy branch.
    assert isinstance(repository, Repository)
    # Read each pack's object headers with borgstore range requests, fetching only the fixed-size
    # headers and skipping the (much larger) encrypted payloads. Don't call Repository.list() here:
    # it iterates this same index we are building, so it would recurse. The headers also give each
    # object's real (chunk_id, offset, size), so every object in a pack is indexed individually.
    for info in repository.store_list("packs"):
        # PackReader uses the store directly, so refresh the lock here; a full rebuild can be slow.
        repository._lock_refresh()
        pack_id = hex_to_bin(info.name)
        for chunk_id, obj_offset, obj_size in PackReader(repository.store, pack_id).iter_headers():
            num_chunks += 1
            chunks[chunk_id] = ChunkIndexEntry(
                flags=init_flags, size=0, pack_id=pack_id, obj_offset=obj_offset, obj_size=obj_size
            )
    duration = perf_counter() - t0 or 0.001
    # Chunk IDs in a list are encoded in 34 bytes: 1 byte msgpack header, 1 byte length, 32 ID bytes.
    # Protocol overhead is neglected in this calculation.
    speed = format_file_size(num_chunks * 34 / duration)
    logger.debug(f"queried {num_chunks} chunk IDs in {duration} s, ~{speed}/s")
    if cache_immediately:
        # immediately update the index, so we only rarely have to do it the slow way:
        write_chunkindex_to_repo(
            repository, chunks, incremental=False, clear=False, force_write=True, delete_other=True
        )
    return chunks


class ChunksMixin:
    """
    Chunks index related code for misc. Cache implementations.
    """

    def __init__(self):
        self._chunks = None
        self.last_refresh_dt = datetime.now(UTC)
        self.refresh_td = timedelta(seconds=60)
        self.chunks_cache_last_write = datetime.now(UTC)
        self.chunks_cache_write_td = timedelta(seconds=600)

    @property
    def chunks(self):
        if self._chunks is None:
            # the repository owns the one and only chunk index; use it rather than
            # building a second one and pushing it back into the repository.
            self._chunks = self.repository.chunks
            # note: we deliberately do NOT consolidate the cached chunk index fragments here.
            # each backup writes a small incremental index/* fragment (only its new chunks),
            # which is cheap. collapsing them all into one big fragment on every run would re-upload
            # the whole index and, with delete_other, invalidate every other client's fragments --
            # a multi-GB churn per run on a shared repo. instead, fragment count is bounded by
            # repack_chunkindex (a size/threshold-based policy that merges only small fragments and
            # leaves large, already-sealed ones untouched), run on close() and by `borg compact`.
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
        self, id, meta, data, *, stats, compress=True, size=None, ctype=None, clevel=None, ro_type=ROBJ_FILE_STREAM
    ):
        assert ro_type is not None
        if size is None:
            if compress:
                size = len(data)  # data is still uncompressed
            else:
                raise ValueError("when giving compressed data for a chunk, the uncompressed size must be given also")
        now = datetime.now(UTC)
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
        pack_results = self.repository.put(id, cdata)
        self.last_refresh_dt = now  # .put also refreshed the lock
        self.chunks.add(id, size)
        self.chunks.update_pack_info(pack_results)
        stats.update(size, not exists)
        return ChunkListEntry(id, size)

    def _maybe_write_chunks_cache(self, now, force=False, clear=False):
        if force or now > self.chunks_cache_last_write + self.chunks_cache_write_td:
            if self._chunks is not None:
                write_chunkindex_to_repo(self.repository, self._chunks, clear=clear)
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
        if self._chunks is not None:
            self.repository.flush()
        if self._files is not None:
            pi.output("Saving files cache")
            integrity_data = self._write_files_cache(self._files)
            self.cache_config.integrity[self.files_cache_name()] = integrity_data
            self._files = None  # release the (potentially large) files cache dict, like _chunks below
        if self._chunks is not None:
            for key, value in sorted(self._chunks.stats.items()):
                logger.debug(f"Chunks index stats: {key}: {value}")
            pi.output("Saving chunks cache")
            # note: index/* in repo has a different integrity mechanism
            now = datetime.now(UTC)
            self._maybe_write_chunks_cache(now, force=True, clear=True)
            self._chunks = None  # nothing there (cleared!)
            # this run just appended a (small) incremental fragment; consolidate accumulated small
            # fragments so their count/size stays in a healthy range (bounded repack, see the function).
            # repack works on the repo's index/* fragments, so it is independent of the in-memory index.
            # the archive and its incremental fragment are already durably stored above, so repack is
            # optional maintenance: if it fails (e.g. a transient store error), warn and carry on
            # rather than failing an already-committed backup. the next run will repack again.
            try:
                repack_chunkindex(self.repository)
            except Exception as exc:
                logger.warning(f"consolidating the chunk index fragments failed (will retry next time): {exc}")
            # the index we just cleared in-place is the same object the repository holds; drop the
            # repository's reference too, so a later .chunks access rebuilds it from the repo instead
            # of seeing a valid-looking but empty index (and so is_chunk_index_loaded reports False).
            self.repository.invalidate_chunk_index()
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
        self.repository.chunks = self._chunks
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

import errno
import os
import shutil
import struct
import tempfile
import time

from .algorithms.checksums import xxh64
from .compress import LZ4
from .helpers import Error, ErrorWithTraceback, IntegrityError, Location
from .helpers import bin_to_hex
from .helpers import format_file_size
from .helpers import truncate_and_unlink
from .logger import create_logger

logger = create_logger(__name__)

MAGIC = b'BORG_SEG'
MAGIC_LEN = len(MAGIC)
ATTIC_MAGIC = b'ATTICSEG'
assert len(ATTIC_MAGIC) == MAGIC_LEN

TAG_PUT = 0
TAG_DELETE = 1
TAG_COMMIT = 2


class Repository:

    class DoesNotExist(Error):
        """Repository {} does not exist."""

    class AlreadyExists(Error):
        """A repository already exists at {}."""

    class PathAlreadyExists(Error):
        """There is already something at {}."""

    class ParentPathDoesNotExist(Error):
        """The parent path of the repo directory [{}] does not exist."""

    class InvalidRepository(Error):
        """{} is not a valid repository. Check repo config."""

    class InvalidRepositoryConfig(Error):
        """{} does not have a valid configuration. Check repo config [{}]."""

    class AtticRepository(Error):
        """Attic repository detected. Please run "borg upgrade {}"."""

    class CheckNeeded(ErrorWithTraceback):
        """Inconsistency detected. Please run "borg check {}"."""

    class ObjectNotFound(ErrorWithTraceback):
        """Object with key {} not found in repository {}."""

        def __init__(self, id, repo):
            if isinstance(id, bytes):
                id = bin_to_hex(id)
            super().__init__(id, repo)

    class InsufficientFreeSpaceError(Error):
        """Insufficient free space to complete transaction (required: {}, available: {})."""

    class StorageQuotaExceeded(Error):
        """The storage quota ({}) has been exceeded ({}). Try deleting some archives."""

    def __init__(self, location, create=False, exclusive=False, lock_wait=None, lock=True, args=None):
        if type(location) == str:
            # Convenience handling of a string as a local path
            location = Location('file://' + location)

        self._location = location
        self._remote = True

        append_only = getattr(args, 'append_only', False)
        storage_quota = getattr(args, 'storage_quota', None)
        make_parent_dirs = getattr(args, 'make_parent_dirs', False)

        try:
            if location.proto == 'ssh':
                from .repositories.remote import RemoteRepository
                repo = RemoteRepository(location, create=create,
                                        exclusive=exclusive,
                                        lock_wait=lock_wait, lock=lock,
                                        make_parent_dirs=make_parent_dirs,
                                        append_only=append_only, args=args)
            elif location.proto == 'file':
                from .repositories.local import LocalRepository
                repo = LocalRepository(location.path, create=create,
                                       exclusive=exclusive,
                                       lock_wait=lock_wait, lock=lock,
                                       make_parent_dirs=make_parent_dirs,
                                       append_only=append_only,
                                       storage_quota=storage_quota)
                self._remote = False
            else:
                raise Exception('Unrecognized location: ' + location.canonical_path())
        except ImportError:
            logger.warning('Missing dependencies needed to handle this repository location:')
            raise

        self._repo = repo

    def __repr__(self):
        return '<%s %s %s>' % (self.__class__.__name__,
                               self._repo.__class__.__name__,
                               self.location.canonical_path())

    def __len__(self):
        return self._repo.__len__()

    def __enter__(self):
        self._repo.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._repo.__exit__(exc_type, exc_val, exc_tb)

    @property
    def location(self):
        return self._location

    @property
    def remote(self):
        return self._remote

    @property
    def id(self):
        return self._repo.id

    @property
    def id_str(self):
        return bin_to_hex(self.id)

    def check(self, repair=False, save_space=False, max_duration=0):
        return self._repo.check(repair, save_space, max_duration)

    def commit(self, save_space=False, compact=True, threshold=0.1, cleanup_commits=False):
        self._repo.commit(save_space, compact, threshold, cleanup_commits)

    def destroy(self):
        self._repo.destroy()

    def list(self, limit=None, marker=None):
        return self._repo.list(limit, marker)

    def scan(self, limit=None, marker=None):
        return self._repo.scan(limit, marker)

    def get(self, id):
        for resp in self.get_many([id]):
            return resp

    def get_many(self, ids, is_preloaded=False):
        for resp in self._repo.get_many(ids, is_preloaded):
            yield resp

    def put(self, id, data, wait=True):
        self._repo.put(id, data, wait)

    def delete(self, id, wait=True):
        self._repo.delete(id, wait)

    def save_key(self, keydata):
        return self._repo.save_key(keydata)

    def load_key(self):
        return self._repo.load_key()

    def get_free_nonce(self):
        return self._repo.get_free_nonce()

    def commit_nonce_reservation(self, next_unreserved, start_nonce):
        self._repo.commit_nonce_reservation(next_unreserved, start_nonce)

    def break_lock(self):
        self._repo.break_lock()

    def migrate_lock(self, old_id, new_id):
        self._repo.migrate_lock(old_id, new_id)

    def async_response(self, wait=True):
        return self._repo.async_response(wait)

    def preload(self, ids):
        self._repo.preload(ids)

    @property
    def config(self):
        return self._repo.config

    def save_config(self):
        self._repo.save_config()


class RepositoryNoCache:
    """A not caching Repository wrapper, passes through to repository.

    Just to have same API (including the context manager) as RepositoryCache.

    *transform* is a callable taking two arguments, key and raw repository data.
    The return value is returned from get()/get_many(). By default, the raw
    repository data is returned.
    """
    def __init__(self, repository, transform=None):
        self.repository = repository
        self.transform = transform or (lambda key, data: data)

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def get(self, key):
        return next(self.get_many([key], cache=False))

    def get_many(self, keys, cache=True):
        for key, data in zip(keys, self.repository.get_many(keys)):
            yield self.transform(key, data)

    def log_instrumentation(self):
        pass


class RepositoryCache(RepositoryNoCache):
    """
    A caching Repository wrapper.

    Caches Repository GET operations locally.

    *pack* and *unpack* complement *transform* of the base class.
    *pack* receives the output of *transform* and should return bytes,
    which are stored in the cache. *unpack* receives these bytes and
    should return the initial data (as returned by *transform*).
    """

    def __init__(self, repository, pack=None, unpack=None, transform=None):
        super().__init__(repository, transform)
        self.pack = pack or (lambda data: data)
        self.unpack = unpack or (lambda data: data)
        self.cache = set()
        self.basedir = tempfile.mkdtemp(prefix='borg-cache-')
        self.query_size_limit()
        self.size = 0
        # Instrumentation
        self.hits = 0
        self.misses = 0
        self.slow_misses = 0
        self.slow_lat = 0.0
        self.evictions = 0
        self.enospc = 0

    def query_size_limit(self):
        available_space = shutil.disk_usage(self.basedir).free
        self.size_limit = int(min(available_space * 0.25, 2**31))

    def key_filename(self, key):
        return os.path.join(self.basedir, bin_to_hex(key))

    def backoff(self):
        self.query_size_limit()
        target_size = int(0.9 * self.size_limit)
        while self.size > target_size and self.cache:
            key = self.cache.pop()
            file = self.key_filename(key)
            self.size -= os.stat(file).st_size
            os.unlink(file)
            self.evictions += 1

    def add_entry(self, key, data, cache):
        transformed = self.transform(key, data)
        if not cache:
            return transformed
        packed = self.pack(transformed)
        file = self.key_filename(key)
        try:
            with open(file, 'wb') as fd:
                fd.write(packed)
        except OSError as os_error:
            try:
                truncate_and_unlink(file)
            except FileNotFoundError:
                pass  # open() could have failed as well
            if os_error.errno == errno.ENOSPC:
                self.enospc += 1
                self.backoff()
            else:
                raise
        else:
            self.size += len(packed)
            self.cache.add(key)
            if self.size > self.size_limit:
                self.backoff()
        return transformed

    def log_instrumentation(self):
        logger.debug('RepositoryCache: current items %d, size %s / %s, %d hits, %d misses, %d slow misses (+%.1fs), '
                     '%d evictions, %d ENOSPC hit',
                     len(self.cache), format_file_size(self.size), format_file_size(self.size_limit),
                     self.hits, self.misses, self.slow_misses, self.slow_lat,
                     self.evictions, self.enospc)

    def close(self):
        self.log_instrumentation()
        self.cache.clear()
        shutil.rmtree(self.basedir)

    def get_many(self, keys, cache=True):
        unknown_keys = [key for key in keys if key not in self.cache]
        repository_iterator = zip(unknown_keys, self.repository.get_many(unknown_keys))
        for key in keys:
            if key in self.cache:
                file = self.key_filename(key)
                with open(file, 'rb') as fd:
                    self.hits += 1
                    yield self.unpack(fd.read())
            else:
                for key_, data in repository_iterator:
                    if key_ == key:
                        transformed = self.add_entry(key, data, cache)
                        self.misses += 1
                        yield transformed
                        break
                else:
                    # slow path: eviction during this get_many removed this key from the cache
                    t0 = time.perf_counter()
                    data = self.repository.get(key)
                    self.slow_lat += time.perf_counter() - t0
                    transformed = self.add_entry(key, data, cache)
                    self.slow_misses += 1
                    yield transformed
        # Consume any pending requests
        for _ in repository_iterator:
            pass


def cache_if_remote(repository, *, decrypted_cache=False, pack=None, unpack=None, transform=None, force_cache=False):
    """
    Return a Repository(No)Cache for *repository*.

    If *decrypted_cache* is a key object, then get and get_many will return a tuple
    (csize, plaintext) instead of the actual data in the repository. The cache will
    store decrypted data, which increases CPU efficiency (by avoiding repeatedly decrypting
    and more importantly MAC and ID checking cached objects).
    Internally, objects are compressed with LZ4.
    """
    if decrypted_cache and (pack or unpack or transform):
        raise ValueError('decrypted_cache and pack/unpack/transform are incompatible')
    elif decrypted_cache:
        key = decrypted_cache
        # 32 bit csize, 64 bit (8 byte) xxh64
        cache_struct = struct.Struct('=I8s')
        compressor = LZ4()

        def pack(data):
            csize, decrypted = data
            compressed = compressor.compress(decrypted)
            return cache_struct.pack(csize, xxh64(compressed)) + compressed

        def unpack(data):
            data = memoryview(data)
            csize, checksum = cache_struct.unpack(data[:cache_struct.size])
            compressed = data[cache_struct.size:]
            if checksum != xxh64(compressed):
                raise IntegrityError('detected corrupted data in metadata cache')
            return csize, compressor.decompress(compressed)

        def transform(id_, data):
            csize = len(data)
            decrypted = key.decrypt(id_, data)
            return csize, decrypted

    if repository.remote or force_cache:
        return RepositoryCache(repository, pack, unpack, transform)
    else:
        return RepositoryNoCache(repository, transform)

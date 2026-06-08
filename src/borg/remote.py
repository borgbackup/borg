import errno
import inspect
import logging
import os
import queue
import select
import shutil
import struct
import sys
import tempfile
import time
import traceback

from xxhash import xxh64

import borg.logger
from . import __version__
from .compress import Compressor
from .constants import *  # NOQA
from .helpers import Error, IntegrityError
from .helpers import bin_to_hex
from .helpers import get_limited_unpacker
from .helpers import sysinfo
from .helpers import format_file_size
from .helpers import safe_unlink
from .logger import create_logger, borg_serve_log_queue
from .helpers import msgpack
from .repository import Repository, StoreObjectNotFound
from .version import parse_version

logger = create_logger(__name__)

BORG_VERSION = parse_version(__version__)
MSGID, MSG, ARGS, RESULT, LOG = "i", "m", "a", "r", "l"


class PathNotAllowed(Error):
    """Repository path not allowed: {}"""

    exit_mcode = 83


class InvalidRPCMethod(Error):
    """RPC method {} is not valid"""

    exit_mcode = 82


class UnexpectedRPCDataFormatFromClient(Error):
    """Borg {}: Got unexpected RPC data format from client."""

    exit_mcode = 85


# Protocol compatibility:
# borg only serves legacy (borg 1.x / v1) repositories over ssh:// now (current repositories use rest://).
# The legacy client lives in borg.legacy.remote (LegacyRemoteRepository); this server keeps the legacy
# RPC method allowlist and opens repositories using LegacyRepository.


class RepositoryServer:  # pragma: no cover
    _legacy_rpc_methods = (  # LegacyRepository
        "__len__",
        "check",
        "commit",
        "delete",
        "destroy",
        "get",
        "list",
        "negotiate",
        "open",
        "close",
        "info",
        "put",
        "rollback",
        "save_key",
        "load_key",
        "break_lock",
        "inject_exception",
        "get_manifest",  # borg2 LegacyRepository has this
    )

    def __init__(self, restrict_to_paths, restrict_to_repositories, permissions=None):
        self.repository = None
        self.RepoCls = None
        self.rpc_methods = ("open", "close", "negotiate")
        self.restrict_to_paths = restrict_to_paths
        self.restrict_to_repositories = restrict_to_repositories
        self.permissions = permissions
        self.client_version = None  # we update this after client sends version information

    def filter_args(self, f, kwargs):
        """Remove unknown named parameters from call, because client did (implicitly) say it's ok."""
        known = set(inspect.signature(f).parameters)
        return {name: kwargs[name] for name in kwargs if name in known}

    def send_queued_log(self):
        while True:
            try:
                # lr_dict contents see BorgQueueHandler
                lr_dict = borg_serve_log_queue.get_nowait()
            except queue.Empty:
                break
            else:
                msg = msgpack.packb({LOG: lr_dict})
                os.write(self.stdout_fd, msg)

    def serve(self):
        def inner_serve():
            os.set_blocking(self.stdin_fd, False)
            assert not os.get_blocking(self.stdin_fd)
            os.set_blocking(self.stdout_fd, True)
            assert os.get_blocking(self.stdout_fd)

            unpacker = get_limited_unpacker("server")
            shutdown_serve = False
            while True:
                # before processing any new RPCs, send out all pending log output
                self.send_queued_log()

                if shutdown_serve:
                    # shutdown wanted! get out of here after sending all log output.
                    assert self.repository is None
                    return

                # process new RPCs
                r, w, es = select.select([self.stdin_fd], [], [], 10)
                if r:
                    data = os.read(self.stdin_fd, BUFSIZE)
                    if not data:
                        shutdown_serve = True
                        continue
                    unpacker.feed(data)
                    for unpacked in unpacker:
                        if isinstance(unpacked, dict):
                            msgid = unpacked[MSGID]
                            method = unpacked[MSG]
                            args = unpacked[ARGS]
                        else:
                            if self.repository is not None:
                                self.repository.close()
                            raise UnexpectedRPCDataFormatFromClient(__version__)
                        try:
                            # logger.debug(f"{type(self)} method: {type(self.repository)}.{method}")
                            if method not in self.rpc_methods:
                                raise InvalidRPCMethod(method)
                            try:
                                f = getattr(self, method)
                            except AttributeError:
                                f = getattr(self.repository, method)
                            args = self.filter_args(f, args)
                            res = f(**args)
                        except BaseException as e:
                            # These exceptions are reconstructed on the client end in RemoteRepository.call_many(),
                            # and will be handled just like locally raised exceptions. Suppress the remote traceback
                            # for these, except ErrorWithTraceback, which should always display a traceback.
                            reconstructed_exceptions = (
                                Repository.InvalidRepository,
                                Repository.InvalidRepositoryConfig,
                                Repository.DoesNotExist,
                                Repository.AlreadyExists,
                                Repository.PathAlreadyExists,
                                PathNotAllowed,
                                Repository.InsufficientFreeSpaceError,
                            )
                            # logger.exception(e)
                            ex_short = traceback.format_exception_only(e.__class__, e)
                            ex_full = traceback.format_exception(*sys.exc_info())
                            ex_trace = True
                            if isinstance(e, Error):
                                ex_short = [e.get_message()]
                                ex_trace = e.traceback
                            if not isinstance(e, reconstructed_exceptions):
                                logging.debug("\n".join(ex_full))

                            sys_info = sysinfo()
                            # StoreObjectNotFound and Repository.ObjectNotFound both have
                            # __name__ == "ObjectNotFound", so we need to distinguish them
                            # explicitly for correct client-side reconstruction.
                            exc_cls_name = (
                                "StoreObjectNotFound" if isinstance(e, StoreObjectNotFound) else e.__class__.__name__
                            )
                            try:
                                msg = msgpack.packb(
                                    {
                                        MSGID: msgid,
                                        "exception_class": exc_cls_name,
                                        "exception_args": e.args,
                                        "exception_full": ex_full,
                                        "exception_short": ex_short,
                                        "exception_trace": ex_trace,
                                        "sysinfo": sys_info,
                                    }
                                )
                            except TypeError:
                                msg = msgpack.packb(
                                    {
                                        MSGID: msgid,
                                        "exception_class": exc_cls_name,
                                        "exception_args": [
                                            x if isinstance(x, (str, bytes, int)) else None for x in e.args
                                        ],
                                        "exception_full": ex_full,
                                        "exception_short": ex_short,
                                        "exception_trace": ex_trace,
                                        "sysinfo": sys_info,
                                    }
                                )
                            os.write(self.stdout_fd, msg)
                        else:
                            os.write(self.stdout_fd, msgpack.packb({MSGID: msgid, RESULT: res}))
                if es:
                    shutdown_serve = True
                    continue

        # server for one ssh:// connection
        self.stdin_fd = sys.stdin.fileno()
        self.stdout_fd = sys.stdout.fileno()
        inner_serve()

    def negotiate(self, client_data):
        if isinstance(client_data, dict):
            self.client_version = client_data["client_version"]
        else:
            self.client_version = BORG_VERSION  # seems to be newer than current version (no known old format)

        # not a known old format, send newest negotiate this version knows
        return {"server_version": BORG_VERSION}

    def _resolve_path(self, path):
        if isinstance(path, bytes):
            path = os.fsdecode(path)
        path = os.path.realpath(path)
        return path

    def open(self, path, create=False, lock_wait=None, lock=True, exclusive=None, v1_legacy=False):
        # borg only serves legacy (v1) repositories now; current repositories are accessed via rest://.
        from .legacy.repository import LegacyRepository

        self.RepoCls = LegacyRepository
        self.rpc_methods = self._legacy_rpc_methods
        logging.debug("Resolving repository path %r", path)
        path = self._resolve_path(path)
        logging.debug("Resolved repository path to %r", path)
        path_with_sep = os.path.join(path, "")  # make sure there is a trailing slash (os.sep)
        if self.restrict_to_paths:
            # if --restrict-to-path P is given, we make sure that we only operate in/below path P.
            # for the prefix check, it is important that the compared paths both have trailing slashes,
            # so that a path /foobar will NOT be accepted with --restrict-to-path /foo option.
            for restrict_to_path in self.restrict_to_paths:
                restrict_to_path_with_sep = os.path.join(os.path.realpath(restrict_to_path), "")  # trailing slash
                if path_with_sep.startswith(restrict_to_path_with_sep):
                    break
            else:
                raise PathNotAllowed(path)
        if self.restrict_to_repositories:
            for restrict_to_repository in self.restrict_to_repositories:
                restrict_to_repository_with_sep = os.path.join(os.path.realpath(restrict_to_repository), "")
                if restrict_to_repository_with_sep == path_with_sep:
                    break
            else:
                raise PathNotAllowed(path)
        kwargs = dict(lock_wait=lock_wait, lock=lock, exclusive=exclusive, send_log_cb=self.send_queued_log)
        self.repository = self.RepoCls(path, create, **kwargs)
        self.repository.__enter__()  # clean exit handled by serve() method
        return self.repository.id

    def close(self):
        if self.repository is not None:
            self.repository.__exit__(None, None, None)
            self.repository = None
        borg.logger.flush_logging()
        self.send_queued_log()

    def inject_exception(self, kind):
        s1 = "test string"
        s2 = "test string2"
        if kind == "DoesNotExist":
            raise self.RepoCls.DoesNotExist(s1)
        elif kind == "AlreadyExists":
            raise self.RepoCls.AlreadyExists(s1)
        elif kind == "CheckNeeded":
            raise self.RepoCls.CheckNeeded(s1)
        elif kind == "IntegrityError":
            raise IntegrityError(s1)
        elif kind == "PathNotAllowed":
            raise PathNotAllowed("foo")
        elif kind == "ObjectNotFound":
            raise self.RepoCls.ObjectNotFound(s1, s2)
        elif kind == "StoreObjectNotFound":
            raise StoreObjectNotFound(s1)
        elif kind == "InvalidRPCMethod":
            raise InvalidRPCMethod(s1)
        elif kind == "divide":
            0 // 0


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

    def get(self, key, read_data=True, raise_missing=True):
        return next(self.get_many([key], read_data=read_data, raise_missing=raise_missing, cache=False))

    def get_many(self, keys, read_data=True, raise_missing=True, cache=True):
        for key, data in zip(keys, self.repository.get_many(keys, read_data=read_data, raise_missing=raise_missing)):
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
        self.basedir = tempfile.mkdtemp(prefix="borg-cache-")
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

    def prefixed_key(self, key, complete):
        # just prefix another byte telling whether this key refers to a complete chunk
        # or a without-data-metadata-only chunk (see also read_data param).
        prefix = b"\x01" if complete else b"\x00"
        return prefix + key

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

    def add_entry(self, key, data, cache, complete):
        transformed = self.transform(key, data)
        if not cache:
            return transformed
        packed = self.pack(transformed)
        pkey = self.prefixed_key(key, complete=complete)
        file = self.key_filename(pkey)
        try:
            with open(file, "wb") as fd:
                fd.write(packed)
        except OSError as os_error:
            try:
                safe_unlink(file)
            except FileNotFoundError:
                pass  # open() could have failed as well
            if os_error.errno == errno.ENOSPC:
                self.enospc += 1
                self.backoff()
            else:
                raise
        else:
            self.size += len(packed)
            self.cache.add(pkey)
            if self.size > self.size_limit:
                self.backoff()
        return transformed

    def log_instrumentation(self):
        logger.debug(
            "RepositoryCache: current items %d, size %s / %s, %d hits, %d misses, %d slow misses (+%.1fs), "
            "%d evictions, %d ENOSPC hit",
            len(self.cache),
            format_file_size(self.size),
            format_file_size(self.size_limit),
            self.hits,
            self.misses,
            self.slow_misses,
            self.slow_lat,
            self.evictions,
            self.enospc,
        )

    def close(self):
        self.log_instrumentation()
        self.cache.clear()
        shutil.rmtree(self.basedir)

    def get_many(self, keys, read_data=True, raise_missing=True, cache=True):
        # It could use different cache keys depending on read_data and cache full vs. meta-only chunks.
        unknown_keys = [key for key in keys if self.prefixed_key(key, complete=read_data) not in self.cache]
        repository_iterator = zip(
            unknown_keys, self.repository.get_many(unknown_keys, read_data=read_data, raise_missing=raise_missing)
        )
        for key in keys:
            pkey = self.prefixed_key(key, complete=read_data)
            if pkey in self.cache:
                file = self.key_filename(pkey)
                with open(file, "rb") as fd:
                    self.hits += 1
                    yield self.unpack(fd.read())
            else:
                for key_, data in repository_iterator:
                    if key_ == key:
                        transformed = self.add_entry(key, data, cache, complete=read_data)
                        self.misses += 1
                        yield transformed
                        break
                else:
                    # slow path: eviction during this get_many removed this key from the cache
                    t0 = time.perf_counter()
                    data = self.repository.get(key, read_data=read_data, raise_missing=raise_missing)
                    self.slow_lat += time.perf_counter() - t0
                    transformed = self.add_entry(key, data, cache, complete=read_data)
                    self.slow_misses += 1
                    yield transformed
        # Consume any pending requests
        for _ in repository_iterator:
            pass


def cache_if_remote(repository, *, decrypted_cache=False, pack=None, unpack=None, transform=None, force_cache=False):
    """
    Return a Repository(No)Cache for *repository*.

    If *decrypted_cache* is a repo_objs object, then get and get_many will return a tuple
    (csize, plaintext) instead of the actual data in the repository. The cache will
    store decrypted data, which increases CPU efficiency (by avoiding repeatedly decrypting
    and more importantly MAC and ID checking cached objects).
    Internally, objects are compressed with LZ4.
    """
    if decrypted_cache and (pack or unpack or transform):
        raise ValueError("decrypted_cache and pack/unpack/transform are incompatible")
    elif decrypted_cache:
        repo_objs = decrypted_cache
        # 32 bit csize, 64 bit (8 byte) xxh64, 1 byte ctype, 1 byte clevel
        cache_struct = struct.Struct("=I8sBB")
        compressor = Compressor("lz4")

        def pack(data):
            csize, decrypted = data
            meta, compressed = compressor.compress({}, decrypted)
            return cache_struct.pack(csize, xxh64(compressed).digest(), meta["ctype"], meta["clevel"]) + compressed

        def unpack(data):
            data = memoryview(data)
            csize, checksum, ctype, clevel = cache_struct.unpack(data[: cache_struct.size])
            compressed = data[cache_struct.size :]
            if checksum != xxh64(compressed).digest():
                raise IntegrityError("detected corrupted data in metadata cache")
            meta = dict(ctype=ctype, clevel=clevel, csize=len(compressed))
            _, decrypted = compressor.decompress(meta, compressed)
            return csize, decrypted

        def transform(id_, data):
            meta, decrypted = repo_objs.parse(id_, data, ro_type=ROBJ_DONTCARE)
            csize = meta.get("csize", len(data))
            return csize, decrypted

    if force_cache:
        return RepositoryCache(repository, pack, unpack, transform)
    else:
        return RepositoryNoCache(repository, transform)

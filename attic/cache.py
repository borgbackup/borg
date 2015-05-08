from configparser import RawConfigParser
from attic.remote import cache_if_remote
import msgpack
import os
import sys
from binascii import hexlify
import shutil

from .key import PlaintextKey
from .helpers import Error, get_cache_dir, decode_dict, st_mtime_ns, unhexlify, UpgradableLock, int_to_bigint, \
    bigint_to_int
from .hashindex import ChunkIndex


class Cache(object):
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

    def __init__(self, repository, key, manifest, path=None, sync=True, warn_if_unencrypted=True):
        self.lock = None
        self.timestamp = None
        self.txn_active = False
        self.repository = repository
        self.key = key
        self.manifest = manifest
        self.path = path or os.path.join(get_cache_dir(), hexlify(repository.id).decode('ascii'))
        # Warn user before sending data to a never seen before unencrypted repository
        if not os.path.exists(self.path):
            if warn_if_unencrypted and isinstance(key, PlaintextKey):
                if not self._confirm('Warning: Attempting to access a previously unknown unencrypted repository',
                                     'ATTIC_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK'):
                    raise self.CacheInitAbortedError()
            self.create()
        self.open()
        # Warn user before sending data to a relocated repository
        if self.previous_location and self.previous_location != repository._location.canonical_path():
            msg = 'Warning: The repository at location {} was previously located at {}'.format(repository._location.canonical_path(), self.previous_location)
            if not self._confirm(msg, 'ATTIC_RELOCATED_REPO_ACCESS_IS_OK'):
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
        """Create a new empty cache at `path`
        """
        os.makedirs(self.path)
        with open(os.path.join(self.path, 'README'), 'w') as fd:
            fd.write('This is an Attic cache')
        config = RawConfigParser()
        config.add_section('cache')
        config.set('cache', 'version', '1')
        config.set('cache', 'repository', hexlify(self.repository.id).decode('ascii'))
        config.set('cache', 'manifest', '')
        with open(os.path.join(self.path, 'config'), 'w') as fd:
            config.write(fd)
        ChunkIndex().write(os.path.join(self.path, 'chunks').encode('utf-8'))
        with open(os.path.join(self.path, 'files'), 'w') as fd:
            pass  # empty file

    def _do_open(self):
        self.config = RawConfigParser()
        self.config.read(os.path.join(self.path, 'config'))
        if self.config.getint('cache', 'version') != 1:
            raise Exception('%s Does not look like an Attic cache')
        self.id = self.config.get('cache', 'repository')
        self.manifest_id = unhexlify(self.config.get('cache', 'manifest'))
        self.timestamp = self.config.get('cache', 'timestamp', fallback=None)
        self.key_type = self.config.get('cache', 'key_type', fallback=None)
        self.previous_location = self.config.get('cache', 'previous_location', fallback=None)
        self.chunks = ChunkIndex.read(os.path.join(self.path, 'chunks').encode('utf-8'))
        self.files = None

    def open(self):
        if not os.path.isdir(self.path):
            raise Exception('%s Does not look like an Attic cache' % self.path)
        self.lock = UpgradableLock(os.path.join(self.path, 'config'), exclusive=True)
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
        """Initializes cache by fetching and reading all archive indicies
        """
        def add(id, size, csize):
            try:
                count, size, csize = self.chunks[id]
                self.chunks[id] = count + 1, size, csize
            except KeyError:
                self.chunks[id] = 1, size, csize
        self.begin_txn()
        print('Initializing cache...')
        self.chunks.clear()
        unpacker = msgpack.Unpacker()
        repository = cache_if_remote(self.repository)
        for name, info in self.manifest.archives.items():
            archive_id = info[b'id']
            cdata = repository.get(archive_id)
            data = self.key.decrypt(archive_id, cdata)
            add(archive_id, len(data), len(cdata))
            archive = msgpack.unpackb(data)
            if archive[b'version'] != 1:
                raise Exception('Unknown archive metadata version')
            decode_dict(archive, (b'name',))
            print('Analyzing archive:', archive[b'name'])
            for key, chunk in zip(archive[b'items'], repository.get_many(archive[b'items'])):
                data = self.key.decrypt(key, chunk)
                add(key, len(data), len(chunk))
                unpacker.feed(data)
                for item in unpacker:
                    if b'chunks' in item:
                        for chunk_id, size, csize in item[b'chunks']:
                            add(chunk_id, size, csize)

    def add_chunk(self, id, data, stats):
        if not self.txn_active:
            self.begin_txn()
        if self.seen_chunk(id):
            return self.chunk_incref(id, stats)
        size = len(data)
        data = self.key.encrypt(data)
        csize = len(data)
        self.repository.put(id, data, wait=False)
        self.chunks[id] = (1, size, csize)
        stats.update(size, csize, True)
        return id, size, csize

    def seen_chunk(self, id):
        return self.chunks.get(id, (0, 0, 0))[0]

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
        # Entry: Age, inode, size, mtime, chunk ids
        mtime_ns = st_mtime_ns(st)
        self.files[path_hash] = msgpack.packb((0, st.st_ino, st.st_size, int_to_bigint(mtime_ns), ids))
        self._newest_mtime = max(self._newest_mtime, mtime_ns)

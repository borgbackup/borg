from __future__ import with_statement
from datetime import datetime, timedelta
from getpass import getuser
from itertools import izip_longest, islice
import msgpack
import os
import socket
import stat
import sys
import time
from cStringIO import StringIO
from xattr import xattr, XATTR_NOFOLLOW

from ._speedups import chunkify
from .helpers import uid2user, user2uid, gid2group, group2gid, \
    encode_filename, Statistics

ITEMS_BUFFER = 1024 * 1024
CHUNK_SIZE = 64 * 1024
WINDOW_SIZE = 4096

have_lchmod = hasattr(os, 'lchmod')
linux = sys.platform == 'linux2'



class ItemIter(object):

    def __init__(self, unpacker, filter):
        self.unpacker = iter(unpacker)
        self.filter = filter
        self.stack = []
        self.peeks = 0
        self._peek = None
        self._peek_iter = None
        global foo
        foo = self

    def __iter__(self):
        return self

    def next(self):
        if self.stack:
            item = self.stack.pop(0)
        else:
            self._peek = None
            item = self.get_next()
        self.peeks = max(0, self.peeks - len(item.get('chunks', [])))
        return item

    def get_next(self):
        next = self.unpacker.next()
        while self.filter and not self.filter(next):
            next = self.unpacker.next()
        return next

    def peek(self):
        while True:
            while not self._peek or not self._peek_iter:
                if self.peeks > 100:
                    raise StopIteration
                self._peek = self.get_next()
                self.stack.append(self._peek)
                if 'chunks' in self._peek:
                    self._peek_iter = iter(self._peek['chunks'])
                else:
                    self._peek_iter = None
            try:
                item = self._peek_iter.next()
                self.peeks += 1
                return item
            except StopIteration:
                self._peek = None


class Archive(object):

    class DoesNotExist(Exception):
        pass

    class AlreadyExists(Exception):
        pass

    def __init__(self, store, key, manifest, name, cache=None, create=False,
                 checkpoint_interval=300, numeric_owner=False):
        if sys.platform == 'darwin':
            self.cwd = os.getcwdu()
        else:
            self.cwd = os.getcwd()
        self.key = key
        self.store = store
        self.cache = cache
        self.manifest = manifest
        self.items = StringIO()
        self.items_ids = []
        self.hard_links = {}
        self.stats = Statistics()
        self.name = name
        self.checkpoint_interval = checkpoint_interval
        self.numeric_owner = numeric_owner
        if create:
            if name in manifest.archives:
                raise self.AlreadyExists
            self.last_checkpoint = time.time()
            i = 0
            while True:
                self.checkpoint_name = '%s.checkpoint%s' % (name, i and ('.%d' % i) or '')
                if not self.checkpoint_name in manifest.archives:
                    break
                i += 1
        else:
            try:
                info = self.manifest.archives[name]
            except KeyError:
                raise self.DoesNotExist
            self.load(info['id'])

    def load(self, id):
        self.id = id
        data = self.key.decrypt(self.id, self.store.get(self.id))
        self.metadata = msgpack.unpackb(data)
        if self.metadata['version'] != 1:
            raise Exception('Unknown archive metadata version')
        self.name = self.metadata['name']

    @property
    def ts(self):
        """Timestamp of archive creation in UTC"""
        t, f = self.metadata['time'].split('.', 1)
        return datetime.strptime(t, '%Y-%m-%dT%H:%M:%S') + timedelta(seconds=float('.' + f))

    def __repr__(self):
        return 'Archive(%r)' % self.name

    def iter_items(self, filter=None):
        unpacker = msgpack.Unpacker()
        i = 0
        n = 20
        while True:
            items = self.metadata['items'][i:i + n]
            i += n
            if not items:
                break
            for id, chunk in [(id, chunk) for id, chunk in izip_longest(items, self.store.get_many(items))]:
                unpacker.feed(self.key.decrypt(id, chunk))
                iter = ItemIter(unpacker, filter)
                for item in iter:
                    yield item, iter.peek

    def add_item(self, item):
        self.items.write(msgpack.packb(item))
        now = time.time()
        if now - self.last_checkpoint > self.checkpoint_interval:
            self.last_checkpoint = now
            self.write_checkpoint()
        if self.items.tell() > ITEMS_BUFFER:
            self.flush_items()

    def flush_items(self, flush=False):
        if self.items.tell() == 0:
            return
        self.items.seek(0)
        chunks = list(str(s) for s in chunkify(self.items, CHUNK_SIZE, WINDOW_SIZE, self.key.chunk_seed))
        self.items.seek(0)
        self.items.truncate()
        for chunk in chunks[:-1]:
            id, _, _ = self.cache.add_chunk(self.key.id_hash(chunk), chunk, self.stats)
            self.items_ids.append(id)
        if flush or len(chunks) == 1:
            id, _, _ = self.cache.add_chunk(self.key.id_hash(chunks[-1]), chunks[-1], self.stats)
            self.items_ids.append(id)
        else:
            self.items.write(chunks[-1])

    def write_checkpoint(self):
        self.save(self.checkpoint_name)
        del self.manifest.archives[self.checkpoint_name]
        self.cache.chunk_decref(self.id)

    def save(self, name=None):
        name = name or self.name
        if name in self.manifest.archives:
            raise self.AlreadyExists(name)
        self.flush_items(flush=True)
        metadata = {
            'version': 1,
            'name': name,
            'items': self.items_ids,
            'cmdline': sys.argv,
            'hostname': socket.gethostname(),
            'username': getuser(),
            'time': datetime.utcnow().isoformat(),
        }
        data = msgpack.packb(metadata)
        self.id = self.key.id_hash(data)
        self.cache.add_chunk(self.id, data, self.stats)
        self.manifest.archives[name] = {'id': self.id, 'time': metadata['time']}
        self.manifest.write()
        self.store.commit()
        self.cache.commit()

    def calc_stats(self, cache):
        def add(id):
            count, size, csize = self.cache.chunks[id]
            stats.update(size, csize, count == 1)
            self.cache.chunks[id] = count - 1, size, csize
        # This function is a bit evil since it abuses the cache to calculate
        # the stats. The cache transaction must be rolled back afterwards
        unpacker = msgpack.Unpacker()
        cache.begin_txn()
        stats = Statistics()
        add(self.id)
        for id, chunk in izip_longest(self.metadata['items'], self.store.get_many(self.metadata['items'])):
            add(id)
            unpacker.feed(self.key.decrypt(id, chunk))
            for item in unpacker:
                try:
                    for id, size, csize in item['chunks']:
                        add(id)
                    stats.nfiles += 1
                except KeyError:
                    pass
        cache.rollback()
        return stats

    def extract_item(self, item, dest=None, restore_attrs=True, peek=None):
        dest = dest or self.cwd
        assert item['path'][0] not in ('/', '\\', ':')
        path = os.path.join(dest, encode_filename(item['path']))
        # Attempt to remove existing files, ignore errors on failure
        try:
            st = os.lstat(path)
            if stat.S_ISDIR(st.st_mode):
                os.rmdir(path)
            else:
                os.unlink(path)
        except OSError:
            pass
        mode = item['mode']
        if stat.S_ISDIR(mode):
            if not os.path.exists(path):
                os.makedirs(path)
            if restore_attrs:
                self.restore_attrs(path, item)
        elif stat.S_ISREG(mode):
            if not os.path.exists(os.path.dirname(path)):
                os.makedirs(os.path.dirname(path))
            # Hard link?
            if 'source' in item:
                source = os.path.join(dest, item['source'])
                if os.path.exists(path):
                    os.unlink(path)
                os.link(source, path)
            else:
                with open(path, 'wbx') as fd:
                    ids = [id for id, size, csize in item['chunks']]
                    for id, chunk in izip_longest(ids, self.store.get_many(ids, peek)):
                        data = self.key.decrypt(id, chunk)
                        fd.write(data)
                self.restore_attrs(path, item)
        elif stat.S_ISFIFO(mode):
            if not os.path.exists(os.path.dirname(path)):
                os.makedirs(os.path.dirname(path))
            os.mkfifo(path)
            self.restore_attrs(path, item)
        elif stat.S_ISLNK(mode):
            if not os.path.exists(os.path.dirname(path)):
                os.makedirs(os.path.dirname(path))
            source = item['source']
            if os.path.exists(path):
                os.unlink(path)
            os.symlink(source, path)
            self.restore_attrs(path, item, symlink=True)
        elif stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
            os.mknod(path, item['mode'], item['dev'])
            self.restore_attrs(path, item)
        else:
            raise Exception('Unknown archive item type %r' % item['mode'])

    def restore_attrs(self, path, item, symlink=False):
        xattrs = item.get('xattrs')
        if xattrs:
            xa = xattr(path, XATTR_NOFOLLOW)
            for k, v in xattrs.items():
                try:
                    xa.set(k, v)
                except (IOError, KeyError):
                    pass
        if have_lchmod:
            os.lchmod(path, item['mode'])
        elif not symlink:
            os.chmod(path, item['mode'])
        uid = gid = None
        if not self.numeric_owner:
            uid = user2uid(item['user'])
            gid = group2gid(item['group'])
        uid = uid or item['uid']
        gid = gid or item['gid']
        try:
            os.lchown(path, uid, gid)
        except OSError:
            pass
        if not symlink:
            # FIXME: We should really call futimes here (c extension required)
            os.utime(path, (item['mtime'], item['mtime']))

    def verify_file(self, item, start, result, peek=None):
        if not item['chunks']:
            start(item)
            result(item, True)
        else:
            start(item)
            ids = [id for id, size, csize in item['chunks']]
            try:
                for id, chunk in izip_longest(ids, self.store.get_many(ids, peek)):
                    self.key.decrypt(id, chunk)
            except Exception:
                result(item, False)
                return
            result(item, True)

    def delete(self, cache):
        unpacker = msgpack.Unpacker()
        for id in self.metadata['items']:
            unpacker.feed(self.key.decrypt(id, self.store.get(id)))
            for item in unpacker:
                try:
                    for chunk_id, size, csize in item['chunks']:
                        self.cache.chunk_decref(chunk_id)
                except KeyError:
                    pass
            self.cache.chunk_decref(id)
        self.cache.chunk_decref(self.id)
        del self.manifest.archives[self.name]
        self.manifest.write()
        self.store.commit()
        cache.commit()

    def stat_attrs(self, st, path):
        item = {
            'mode': st.st_mode,
            'uid': st.st_uid, 'user': uid2user(st.st_uid),
            'gid': st.st_gid, 'group': gid2group(st.st_gid),
            'mtime': st.st_mtime,
        }
        if self.numeric_owner:
            item['user'] = item['group'] = None
        try:
            xa = xattr(path, XATTR_NOFOLLOW)
            xattrs = {}
            for key in xa:
                # Only store the user namespace on Linux
                if linux and not key.startswith('user'):
                    continue
                xattrs[key] = xa[key]
            if xattrs:
                item['xattrs'] = xattrs
        except IOError:
            pass
        return item

    def process_item(self, path, st):
        item = {'path': path.lstrip('/\\:')}
        item.update(self.stat_attrs(st, path))
        self.add_item(item)

    def process_dev(self, path, st):
        item = {'path': path.lstrip('/\\:'), 'dev': st.st_dev}
        item.update(self.stat_attrs(st, path))
        self.add_item(item)

    def process_symlink(self, path, st):
        source = os.readlink(path)
        item = {'path': path.lstrip('/\\:'), 'source': source}
        item.update(self.stat_attrs(st, path))
        self.add_item(item)

    def process_file(self, path, st, cache):
        safe_path = path.lstrip('/\\:')
        # Is it a hard link?
        if st.st_nlink > 1:
            source = self.hard_links.get((st.st_ino, st.st_dev))
            if (st.st_ino, st.st_dev) in self.hard_links:
                item = self.stat_attrs(st, path)
                item.update({'path': safe_path, 'source': source})
                self.add_item(item)
                return
            else:
                self.hard_links[st.st_ino, st.st_dev] = safe_path
        path_hash = self.key.id_hash(path)
        ids = cache.file_known_and_unchanged(path_hash, st)
        chunks = None
        if ids is not None:
            # Make sure all ids are available
            for id in ids:
                if not cache.seen_chunk(id):
                    break
            else:
                chunks = [cache.chunk_incref(id, self.stats) for id in ids]
        # Only chunkify the file if needed
        if chunks is None:
            with open(path, 'rb') as fd:
                chunks = []
                for chunk in chunkify(fd, CHUNK_SIZE, WINDOW_SIZE,
                                      self.key.chunk_seed):
                    chunks.append(cache.add_chunk(self.key.id_hash(chunk), chunk, self.stats))
            ids = [id for id, _, _ in chunks]
            cache.memorize_file(path_hash, st, ids)
        item = {'path': safe_path, 'chunks': chunks}
        item.update(self.stat_attrs(st, path))
        self.stats.nfiles += 1
        self.add_item(item)

    @staticmethod
    def list_archives(store, key, manifest, cache=None):
        for name, info in manifest.archives.items():
            yield Archive(store, key, manifest, name, cache=cache)

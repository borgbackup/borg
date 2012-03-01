from __future__ import with_statement
from datetime import datetime, timedelta
from getpass import getuser
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
    Counter, encode_filename, Statistics

ITEMS_BUFFER = 1024 * 1024
CHUNK_SIZE = 64 * 1024
WINDOW_SIZE = 4096

have_lchmod = hasattr(os, 'lchmod')
linux = sys.platform == 'linux2'


class Archive(object):

    class DoesNotExist(Exception):
        pass

    class AlreadyExists(Exception):
        pass

    def __init__(self, store, key, manifest, name, cache=None, create=False,
                 checkpoint_interval=300, numeric_owner=False):
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

    def iter_items(self, callback):
        unpacker = msgpack.Unpacker()
        counter = Counter(0)

        def cb(chunk, error, id):
            if error:
                raise error
            assert not error
            counter.dec()
            data = self.key.decrypt(id, chunk)
            unpacker.feed(data)
            for item in unpacker:
                callback(item)
        for id in self.metadata['items']:
            # Limit the number of concurrent items requests to 10
            self.store.flush_rpc(counter, 10)
            counter.inc()
            self.store.get(id, callback=cb, callback_data=id)

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
        # This function is a bit evil since it abuses the cache to calculate
        # the stats. The cache transaction must be rolled back afterwards
        def cb(chunk, error, id):
            assert not error
            data = self.key.decrypt(id, chunk)
            unpacker.feed(data)
            for item in unpacker:
                try:
                    for id, size, csize in item['chunks']:
                        count, _, _ = self.cache.chunks[id]
                        stats.update(size, csize, count == 1)
                        stats.nfiles += 1
                        self.cache.chunks[id] = count - 1, size, csize
                except KeyError:
                    pass
        unpacker = msgpack.Unpacker()
        cache.begin_txn()
        stats = Statistics()
        for id in self.metadata['items']:
            self.store.get(id, callback=cb, callback_data=id)
            count, size, csize = self.cache.chunks[id]
            stats.update(size, csize, count == 1)
            self.cache.chunks[id] = count - 1, size, csize
        self.store.flush_rpc()
        cache.rollback()
        return stats

    def extract_item(self, item, dest=None, start_cb=None, restore_attrs=True):
        dest = dest or os.getcwdu()
        assert item['path'][0] not in ('/', '\\', ':')
        path = os.path.join(dest, encode_filename(item['path']))
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
                def link_cb(_, __, item):
                    source = os.path.join(dest, item['source'])
                    if os.path.exists(path):
                        os.unlink(path)
                    os.link(source, path)
                self.store.add_callback(link_cb, item)
            else:
                def extract_cb(chunk, error, (id, i)):
                    if i == 0:
                        state['fd'] = open(path, 'wb')
                        start_cb(item)
                    assert not error
                    data = self.key.decrypt(id, chunk)
                    state['fd'].write(data)
                    if i == n - 1:
                        state['fd'].close()
                        self.restore_attrs(path, item)
                state = {}
                n = len(item['chunks'])
                ## 0 chunks indicates an empty (0 bytes) file
                if n == 0:
                    open(path, 'wb').close()
                    start_cb(item)
                    self.restore_attrs(path, item)
                else:
                    for i, (id, size, csize) in enumerate(item['chunks']):
                        self.store.get(id, callback=extract_cb, callback_data=(id, i))
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

    def verify_file(self, item, start, result):
        def verify_chunk(chunk, error, (id, i)):
            if error:
                if not state:
                    result(item, False)
                    state[True] = True
                return
            if i == 0:
                start(item)
            self.key.decrypt(id, chunk)
            if i == n - 1:
                result(item, True)
        state = {}
        n = len(item['chunks'])
        if n == 0:
            start(item)
            result(item, True)
        else:
            for i, (id, size, csize) in enumerate(item['chunks']):
                self.store.get(id, callback=verify_chunk, callback_data=(id, i))

    def delete(self, cache):
        def callback(chunk, error, id):
            assert not error
            data = self.key.decrypt(id, chunk)
            unpacker.feed(data)
            for item in unpacker:
                try:
                    for chunk_id, size, csize in item['chunks']:
                        self.cache.chunk_decref(chunk_id)
                except KeyError:
                    pass
            self.cache.chunk_decref(id)
        unpacker = msgpack.Unpacker()
        for id in self.metadata['items']:
            self.store.get(id, callback=callback, callback_data=id)
        self.store.flush_rpc()
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

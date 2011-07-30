from __future__ import with_statement
from datetime import datetime, timedelta
from getpass import getuser
import msgpack
import os
import socket
import stat
import sys
from os.path import dirname
from xattr import xattr, XATTR_NOFOLLOW

from . import NS_ARCHIVE_METADATA, NS_CHUNK
from ._speedups import chunkify
from .helpers import uid2user, user2uid, gid2group, group2gid, IntegrityError

CHUNK_SIZE = 64 * 1024
WINDOW_SIZE = 4096

have_lchmod = hasattr(os, 'lchmod')
linux = sys.platform == 'linux2'


class Archive(object):

    class DoesNotExist(Exception):
        pass

    def __init__(self, store, key, name=None, cache=None):
        self.key = key
        self.store = store
        self.cache = cache
        self.items = ''
        self.items_refs = []
        self.items_prefix = ''
        self.items_ids = []
        self.hard_links = {}
        if name:
            self.load(self.key.archive_hash(name))

    def load(self, id):
        self.id = id
        try:
            data, self.hash = self.key.decrypt(self.store.get(NS_ARCHIVE_METADATA, self.id))
        except self.store.DoesNotExist:
            raise self.DoesNotExist
        self.metadata = msgpack.unpackb(data)
        assert self.metadata['version'] == 1

    @property
    def ts(self):
        """Timestamp of archive creation in UTC"""
        t, f = self.metadata['time'].split('.', 1)
        return datetime.strptime(t, '%Y-%m-%dT%H:%M:%S') + timedelta(seconds=float('.' + f))

    def get_items(self):
        unpacker = msgpack.Unpacker()
        for id, size, csize in self.metadata['items']:
            data, items_hash = self.key.decrypt(self.store.get(NS_CHUNK, id))
            assert self.key.id_hash(data) == id
            unpacker.feed(data)
            for item in unpacker:
                yield item

    def add_item(self, item, refs=None):
        data = msgpack.packb(item)
        prefix = dirname(item['path'])
        if self.items_prefix and self.items_prefix != prefix:
            self.flush_items()
        if refs:
            self.items_refs += refs
        self.items += data
        self.items_prefix = prefix

    def flush_items(self):
        if not self.items:
            return
        id = self.key.id_hash(self.items)
        if self.cache.seen_chunk(id):
            self.items_ids.append(self.cache.chunk_incref(id))
            for id in self.items_refs:
                self.cache.chunk_decref(id)
        else:
            self.items_ids.append(self.cache.add_chunk(id, self.items))
        self.items = ''
        self.items_refs = []
        self.items_prefix = ''

    def save(self, name, cache):
        self.id = self.key.archive_hash(name)
        self.flush_items()
        metadata = {
            'version': 1,
            'name': name,
            'items': self.items_ids,
            'cmdline': sys.argv,
            'hostname': socket.gethostname(),
            'username': getuser(),
            'time': datetime.utcnow().isoformat(),
        }
        data, self.hash = self.key.encrypt(msgpack.packb(metadata))
        self.store.put(NS_ARCHIVE_METADATA, self.id, data)
        self.store.commit()
        cache.commit()

    def get_chunks(self):
        for item in self.get_items():
            try:
                for chunk in item['chunks']:
                    yield chunk
            except KeyError:
                pass

    def stats(self, cache):
        # This function is a bit evil since it abuses the cache to calculate
        # the stats. The cache transaction must be rolled back afterwards
        unpacker = msgpack.Unpacker()
        cache.begin_txn()
        osize = zsize = usize = 0
        for id, size, csize in self.metadata['items']:
            osize += size
            zsize += csize
            unique = self.cache.seen_chunk(id) == 1
            if unique:
                usize += csize
            data, items_hash = self.key.decrypt(self.store.get(NS_CHUNK, id))
            assert self.key.id_hash(data) == id
            unpacker.feed(data)
            for item in unpacker:
                try:
                    for id, size, csize in item['chunks']:
                        osize += size
                        zsize += csize
                        if unique and self.cache.seen_chunk(id) == 1:
                            usize += csize
                except KeyError:
                    pass
        cache.rollback()
        return osize, zsize, usize

    def extract_item(self, item, dest=None, start_cb=None):
        dest = dest or os.getcwdu()
        dir_stat_queue = []
        assert item['path'][0] not in ('/', '\\', ':')
        path = os.path.join(dest, item['path'].decode('utf-8'))
        mode = item['mode']
        if stat.S_ISDIR(mode):
            if not os.path.exists(path):
                os.makedirs(path)
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
        elif stat.S_ISREG(mode):
            if not os.path.exists(os.path.dirname(path)):
                os.makedirs(os.path.dirname(path))
            # Hard link?
            if 'source' in item:
                source = os.path.join(dest, item['source'].decode('utf-8'))
                if os.path.exists(path):
                    os.unlink(path)
                os.link(source, path)
            else:
                def extract_cb(chunk, error, (id, i, last)):
                    if i==0:
                        start_cb(item)
                    assert not error
                    data, hash = self.key.decrypt(chunk)
                    if self.key.id_hash(data) != id:
                        raise IntegrityError('chunk hash did not match')
                    fd.write(data)
                    if last:
                        fd.close()
                        self.restore_attrs(path, item)

                fd = open(path, 'wb')
                n = len(item['chunks'])
                if n == 0:
                    start_cb(item)
                    self.restore_attrs(path, item)
                    fd.close()
                else:
                    for i, (id, size, csize) in enumerate(item['chunks']):
                        self.store.get(NS_CHUNK, id, callback=extract_cb, callback_data=(id, i, i==n-1))

        else:
            raise Exception('Unknown archive item type %r' % item['mode'])

    def restore_attrs(self, path, item, symlink=False):
        xattrs = item.get('xattrs')
        if xattrs:
            xa = xattr(path, XATTR_NOFOLLOW)
            for k, v in xattrs.items():
                try:
                    xa.set(k, v)
                except KeyError:
                    pass
        if have_lchmod:
            os.lchmod(path, item['mode'])
        elif not symlink:
            os.chmod(path, item['mode'])
        uid = user2uid(item['user']) or item['uid']
        gid = group2gid(item['group']) or item['gid']
        try:
            os.lchown(path, uid, gid)
        except OSError:
            pass
        if not symlink:
            # FIXME: We should really call futimes here (c extension required)
            os.utime(path, (item['mtime'], item['mtime']))

    def verify_file(self, item, start, result):
        def verify_chunk(chunk, error, (id, i, last)):
            if i == 0:
                start(item)
            assert not error
            data, hash = self.key.decrypt(chunk)
            if self.key.id_hash(data) != id:
                result(item, False)
            elif last:
                result(item, True)
        n = len(item['chunks'])
        if n == 0:
            start(item)
            result(item, True)
        else:
            for i, (id, size, csize) in enumerate(item['chunks']):
                self.store.get(NS_CHUNK, id, callback=verify_chunk, callback_data=(id, i, i==n-1))

    def delete(self, cache):
        unpacker = msgpack.Unpacker()
        for id, size, csize in self.metadata['items']:
            if self.cache.seen_chunk(id) == 1:
                data, items_hash = self.key.decrypt(self.store.get(NS_CHUNK, id))
                assert self.key.id_hash(data) == id
                unpacker.feed(data)
                for item in unpacker:
                    try:
                        for chunk_id, size, csize in item['chunks']:
                            self.cache.chunk_decref(chunk_id)
                    except KeyError:
                        pass
            self.cache.chunk_decref(id)
        self.store.delete(NS_ARCHIVE_METADATA, self.id)
        self.store.commit()
        cache.commit()

    def stat_attrs(self, st, path):
        item = {
            'mode': st.st_mode,
            'uid': st.st_uid, 'user': uid2user(st.st_uid),
            'gid': st.st_gid, 'group': gid2group(st.st_gid),
            'mtime': st.st_mtime,
        }
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

    def process_dir(self, path, st):
        item = {'path': path.lstrip('/\\:')}
        item.update(self.stat_attrs(st, path))
        self.add_item(item)

    def process_fifo(self, path, st):
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
        path_hash = self.key.id_hash(path.encode('utf-8'))
        ids = cache.file_known_and_unchanged(path_hash, st)
        chunks = None
        if ids is not None:
            # Make sure all ids are available
            for id in ids:
                if not cache.seen_chunk(id):
                    break
            else:
                chunks = [cache.chunk_incref(id) for id in ids]
        # Only chunkify the file if needed
        if chunks is None:
            with open(path, 'rb') as fd:
                chunks = []
                for chunk in chunkify(fd, CHUNK_SIZE, WINDOW_SIZE,
                                      self.key.chunk_seed):
                    chunks.append(cache.add_chunk(self.key.id_hash(chunk), chunk))
            ids = [id for id, _, _ in chunks]
            cache.memorize_file(path_hash, st, ids)
        item = {'path': safe_path, 'chunks': chunks}
        item.update(self.stat_attrs(st, path))
        self.add_item(item, ids)

    @staticmethod
    def list_archives(store, key):
        for id in list(store.list(NS_ARCHIVE_METADATA)):
            archive = Archive(store, key)
            archive.load(id)
            yield archive


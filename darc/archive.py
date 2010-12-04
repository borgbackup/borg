from datetime import datetime
from getpass import getuser
import msgpack
import os
import socket
import stat
import sys
from xattr import xattr, XATTR_NOFOLLOW

from . import NS_ARCHIVE_METADATA, NS_ARCHIVE_ITEMS, NS_ARCHIVE_CHUNKS, NS_CHUNK
from ._speedups import chunkify
from .helpers import uid2user, user2uid, gid2group, group2gid, IntegrityError

CHUNK_SIZE = 64 * 1024
WINDOW_SIZE = 4096

have_lchmod = hasattr(os, 'lchmod')
linux = sys.platform == 'linux2'


class Archive(object):

    class DoesNotExist(Exception):
        pass

    def __init__(self, store, keychain, name=None):
        self.keychain = keychain
        self.store = store
        self.items = []
        self.items_ids = []
        self.hard_links = {}
        if name:
            self.load(self.keychain.id_hash(name))

    def load(self, id):
        self.id = id
        try:
            data, self.hash = self.keychain.decrypt(self.store.get(NS_ARCHIVE_METADATA, self.id))
        except self.store.DoesNotExist:
            raise self.DoesNotExist
        self.metadata = msgpack.unpackb(data)
        assert self.metadata['version'] == 1

    def get_chunks(self):
        for id in self.metadata['chunks_ids']:
            data, items_hash = self.keychain.decrypt(self.store.get(NS_ARCHIVE_CHUNKS, id))
            assert items_hash == id
            items = msgpack.unpackb(data)
            assert items['version'] == 1
            for item in items['chunks']:
                yield item

    def get_items(self):
        for id in self.metadata['items_ids']:
            data, items_hash = self.keychain.decrypt(self.store.get(NS_ARCHIVE_ITEMS, id))
            assert items_hash == id
            items = msgpack.unpackb(data)
            assert items['version'] == 1
            for item in items['items']:
                yield item

    def add_item(self, item):
        self.items.append(item)
        if len(self.items) > 100000:
            self.flush_items()

    def flush_items(self):
        items = {'version': 1, 'items': self.items}
        data, items_hash = self.keychain.encrypt_read(msgpack.packb(items))
        self.store.put(NS_ARCHIVE_ITEMS, items_hash, data)
        self.items = []
        self.items_ids.append(items_hash)

    def save_chunks(self, cache):
        chunks = []
        ids = []
        def flush(chunks):
            data = { 'version': 1, 'chunks': chunks }
            data, chunks_hash = self.keychain.encrypt_create(msgpack.packb(data))
            self.store.put(NS_ARCHIVE_CHUNKS, chunks_hash, data)
            ids.append(chunks_hash)
        for id, (count, size) in cache.chunk_counts.iteritems():
            if count > 1000000:
                chunks.append((id, size))
            if len(chunks) > 100000:
                flush(chunks)
                chunks = []
        flush(chunks)
        return ids

    def save(self, name, cache):
        self.id = self.keychain.id_hash(name)
        chunks_ids = self.save_chunks(cache)
        self.flush_items()
        metadata = {
            'version': 1,
            'name': name,
            'chunks_ids': chunks_ids,
            'items_ids': self.items_ids,
            'cmdline': sys.argv,
            'hostname': socket.gethostname(),
            'username': getuser(),
            'time': datetime.utcnow().isoformat(),
        }
        data, self.hash = self.keychain.encrypt_read(msgpack.packb(metadata))
        self.store.put(NS_ARCHIVE_METADATA, self.id, data)
        self.store.commit()

    def stats(self, cache):
        osize = csize = usize = 0
        for item in self.get_items():
            if stat.S_ISREG(item['mode']) and not 'source' in item:
                osize += item['size']
        for id, size in self.get_chunks():
            csize += size
            if cache.seen_chunk(id) == 1:
                usize += size
        return osize, csize, usize

    def extract_item(self, item, dest=None):
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
                source = os.path.join(dest, item['source'])
                if os.path.exists(path):
                    os.unlink(path)
                os.link(source, path)
            else:
                with open(path, 'wb') as fd:
                    for id in item['chunks']:
                        try:
                            data, hash = self.keychain.decrypt(self.store.get(NS_CHUNK, id))
                            if self.keychain.id_hash(data) != id:
                                raise IntegrityError('chunk hash did not match')
                            fd.write(data)
                        except ValueError:
                            raise Exception('Invalid chunk checksum')
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
            os.utime(path, (item['atime'], item['mtime']))

    def verify_file(self, item):
        for id in item['chunks']:
            try:
                data, hash = self.keychain.decrypt(self.store.get(NS_CHUNK, id))
                if self.keychain.id_hash(data) != id:
                    raise IntegrityError('chunk id did not match')
            except IntegrityError:
                return False
        return True

    def delete(self, cache):
        for id, size in self.get_chunks():
            cache.chunk_decref(id)
        self.store.delete(NS_ARCHIVE_METADATA, self.id)
        for id in self.metadata['chunks_ids']:
            self.store.delete(NS_ARCHIVE_CHUNKS, id)
        for id in self.metadata['items_ids']:
            self.store.delete(NS_ARCHIVE_ITEMS, id)
        self.store.commit()
        cache.save()

    def stat_attrs(self, st, path):
        item = {
            'mode': st.st_mode,
            'uid': st.st_uid, 'user': uid2user(st.st_uid),
            'gid': st.st_gid, 'group': gid2group(st.st_gid),
            'atime': st.st_atime, 'mtime': st.st_mtime,
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
                self.add_item({'mode': st.st_mode,
                               'path': path, 'source': source})
                return
            else:
                self.hard_links[st.st_ino, st.st_dev] = safe_path
        path_hash = self.keychain.id_hash(path.encode('utf-8'))
        ids, size = cache.file_known_and_unchanged(path_hash, st)
        if ids is not None:
            # Make sure all ids are available
            for id in ids:
                if not cache.seen_chunk(id):
                    ids = None
                    break
            else:
                for id in ids:
                    cache.chunk_incref(id)
        # Only chunkify the file if needed
        if ids is None:
            with open(path, 'rb') as fd:
                size = 0
                ids = []
                for chunk in chunkify(fd, CHUNK_SIZE, WINDOW_SIZE,
                                      self.keychain.get_chunkify_seed()):
                    ids.append(cache.add_chunk(self.keychain.id_hash(chunk), chunk))
                    size += len(chunk)
            cache.memorize_file_chunks(path_hash, st, ids)
        item = {'path': safe_path, 'chunks': ids, 'size': size}
        item.update(self.stat_attrs(st, path))
        self.add_item(item)

    @staticmethod
    def list_archives(store, keychain):
        for id in list(store.list(NS_ARCHIVE_METADATA)):
            archive = Archive(store, keychain)
            archive.load(id)
            yield archive

from datetime import datetime
from getpass import getuser
import logging
import msgpack
import os
import socket
import stat
import sys

from . import NS_ARCHIVE_METADATA, NS_ARCHIVE_ITEMS, NS_ARCHIVE_CHUNKS, NS_CHUNK
from .chunkifier import chunkify
from .helpers import uid2user, user2uid, gid2group, group2gid, IntegrityError

CHUNK_SIZE = 55001


class Archive(object):

    def __init__(self, store, crypto, name=None):
        self.crypto = crypto
        self.store = store
        self.items = []
        self.chunks = []
        self.chunk_idx = {}
        self.hard_links = {}
        if name:
            self.load(self.crypto.id_hash(name))

    def load(self, id):
        self.id = id
        data, self.hash = self.crypto.decrypt(self.store.get(NS_ARCHIVE_METADATA, self.id))
        self.metadata = msgpack.unpackb(data)
        assert self.metadata['version'] == 1

    def get_items(self):
        data, chunks_hash = self.crypto.decrypt(self.store.get(NS_ARCHIVE_CHUNKS, self.id))
        chunks = msgpack.unpackb(data)
        assert chunks['version'] == 1
        assert self.metadata['chunks_hash'] == chunks_hash
        self.chunks = chunks['chunks']
        data, items_hash = self.crypto.decrypt(self.store.get(NS_ARCHIVE_ITEMS, self.id))
        items = msgpack.unpackb(data)
        assert items['version'] == 1
        assert self.metadata['items_hash'] == items_hash
        self.items = items['items']
        for i, chunk in enumerate(self.chunks):
            self.chunk_idx[i] = chunk[0]

    def save(self, name):
        self.id = self.crypto.id_hash(name)
        chunks = {'version': 1, 'chunks': self.chunks}
        data, chunks_hash = self.crypto.encrypt_create(msgpack.packb(chunks))
        self.store.put(NS_ARCHIVE_CHUNKS, self.id, data)
        items = {'version': 1, 'items': self.items}
        data, items_hash = self.crypto.encrypt_read(msgpack.packb(items))
        self.store.put(NS_ARCHIVE_ITEMS, self.id, data)
        metadata = {
            'version': 1,
            'name': name,
            'chunks_hash': chunks_hash,
            'items_hash': items_hash,
            'cmdline': sys.argv,
            'hostname': socket.gethostname(),
            'username': getuser(),
            'time': datetime.utcnow().isoformat(),
        }
        data, self.hash = self.crypto.encrypt_read(msgpack.packb(metadata))
        self.store.put(NS_ARCHIVE_METADATA, self.id, data)
        self.store.commit()

    def add_chunk(self, id, size):
        try:
            return self.chunk_idx[id]
        except KeyError:
            idx = len(self.chunks)
            self.chunks.append((id, size))
            self.chunk_idx[id] = idx
            return idx

    def stats(self, cache):
        self.get_items()
        osize = csize = usize = 0
        for item in self.items:
            if item['type'] == 'FILE':
                osize += item['size']
        for id, size in self.chunks:
            csize += size
            if cache.seen_chunk(id) == 1:
                usize += size
        return osize, csize, usize

    def list(self):
        self.get_items()
        for item in self.items:
            mode = str(item['mode'])
            size = item.get('size', 0)
            mtime = datetime.fromtimestamp(item['mtime'])
            print '%s %-6s %-6s %8d %s %s' % (mode, item['user'], item['group'],
                                              size, mtime, item['path'])

    def extract(self, dest=None):
        self.get_items()
        dest = dest or os.getcwdu()
        dir_stat_queue = []
        for item in self.items:
            assert item['path'][0] not in ('/', '\\', ':')
            path = os.path.join(dest, item['path'].decode('utf-8'))
            if item['type'] == 'DIRECTORY':
                logging.info(path)
                if not os.path.exists(path):
                    os.makedirs(path)
                dir_stat_queue.append((path, item))
                continue
            elif item['type'] == 'SYMLINK':
                if not os.path.exists(os.path.dirname(path)):
                    os.makedirs(os.path.dirname(path))
                source = item['source']
                logging.info('%s -> %s', path, source)
                if os.path.exists(path):
                    os.unlink(path)
                os.symlink(source, path)
                self.restore_stat(path, item, symlink=True)
            elif item['type'] == 'HARDLINK':
                if not os.path.exists(os.path.dirname(path)):
                    os.makedirs(os.path.dirname(path))
                source = os.path.join(dest, item['source'])
                logging.info('%s => %s', path, source)
                if os.path.exists(path):
                    os.unlink(path)
                os.link(source, path)
            elif item['type'] == 'FILE':
                logging.info(path)
                if not os.path.exists(os.path.dirname(path)):
                    os.makedirs(os.path.dirname(path))
                with open(path, 'wb') as fd:
                    for chunk in item['chunks']:
                        id = self.chunk_idx[chunk]
                        try:
                            data, hash = self.crypto.decrypt(self.store.get(NS_CHUNK, id))
                            if self.crypto.id_hash(data) != id:
                                raise IntegrityError('chunk id did not match')
                            fd.write(data)
                        except ValueError:
                            raise Exception('Invalid chunk checksum')
                self.restore_stat(path, item)
            else:
                raise Exception('Unknown archive item type %r' % item['type'])
            if dir_stat_queue and not path.startswith(dir_stat_queue[-1][0]):
                self.restore_stat(*dir_stat_queue.pop())

    def restore_stat(self, path, item, symlink=False):
        os.lchmod(path, item['mode'])
        uid = user2uid(item['user']) or item['uid']
        gid = group2gid(item['group']) or item['gid']
        try:
            if hasattr(os, 'lchown'):  # Not available on Linux
                os.lchown(path, uid, gid)
            elif not symlink:
                os.chown(path, uid, gid)
        except OSError:
            pass
        if not symlink:
            # FIXME: We should really call futimes here (c extension required)
            os.utime(path, (item['ctime'], item['mtime']))

    def verify(self):
        self.get_items()
        for item in self.items:
            if item['type'] == 'FILE':
                item['path'] = item['path'].decode('utf-8')
                for chunk in item['chunks']:
                    id = self.chunk_idx[chunk]
                    try:
                        data, hash = self.crypto.decrypt(self.store.get(NS_CHUNK, id))
                        if self.crypto.id_hash(data) != id:
                            raise IntegrityError('chunk id did not match')
                    except IntegrityError:
                        logging.error('%s ... ERROR', item['path'])
                        break
                else:
                    logging.info('%s ... OK', item['path'])

    def delete(self, cache):
        self.get_items()
        self.store.delete(NS_ARCHIVE_CHUNKS, self.id)
        self.store.delete(NS_ARCHIVE_ITEMS, self.id)
        self.store.delete(NS_ARCHIVE_METADATA, self.id)
        for id, size in self.chunks:
            cache.chunk_decref(id)
        self.store.commit()
        cache.save()

    def _walk(self, path):
        st = os.lstat(path)
        yield path, st
        if stat.S_ISDIR(st.st_mode):
            for f in os.listdir(path):
                for x in self._walk(os.path.join(path, f)):
                    yield x

    def create(self, name, paths, cache):
        id = self.crypto.id_hash(name)
        try:
            self.store.get(NS_ARCHIVE_METADATA, id)
        except self.store.DoesNotExist:
            pass
        else:
            raise NameError('Archive already exists')
        for path in paths:
            for path, st in self._walk(unicode(path)):
                if stat.S_ISDIR(st.st_mode):
                    self.process_dir(path, st)
                elif stat.S_ISLNK(st.st_mode):
                    self.process_symlink(path, st)
                elif stat.S_ISREG(st.st_mode):
                    self.process_file(path, st, cache)
                else:
                    logging.error('Unknown file type: %s', path)
        self.save(name)
        cache.save()

    def process_dir(self, path, st):
        path = path.lstrip('/\\:')
        logging.info(path)
        self.items.append({
            'type': 'DIRECTORY', 'path': path,
            'mode': st.st_mode,
            'uid': st.st_uid, 'user': uid2user(st.st_uid),
            'gid': st.st_gid, 'group': gid2group(st.st_gid),
            'ctime': st.st_ctime, 'mtime': st.st_mtime,
        })

    def process_symlink(self, path, st):
        source = os.readlink(path)
        path = path.lstrip('/\\:')
        logging.info('%s -> %s', path, source)
        self.items.append({
            'type': 'SYMLINK', 'path': path, 'source': source,
            'mode': st.st_mode,
            'uid': st.st_uid, 'user': uid2user(st.st_uid),
            'gid': st.st_gid, 'group': gid2group(st.st_gid),
            'ctime': st.st_ctime, 'mtime': st.st_mtime,
        })
    def process_file(self, path, st, cache):
        safe_path = path.lstrip('/\\:')
        if st.st_nlink > 1:
            source = self.hard_links.get((st.st_ino, st.st_dev))
            if (st.st_ino, st.st_dev) in self.hard_links:
                logging.info('%s => %s', path, source)
                self.items.append({ 'type': 'HARDLINK',
                                    'path': path, 'source': source})
                return
            else:
                self.hard_links[st.st_ino, st.st_dev] = safe_path
        try:
            fd = open(path, 'rb')
        except IOError, e:
            logging.error(e)
            return
        with fd:
            logging.info(safe_path)
            chunks = []
            size = 0
            for chunk in chunkify(fd, CHUNK_SIZE, 30):
                chunks.append(self.process_chunk(chunk, cache))
                size += len(chunk)
        self.items.append({
            'type': 'FILE', 'path': safe_path, 'chunks': chunks, 'size': size,
            'mode': st.st_mode,
            'uid': st.st_uid, 'user': uid2user(st.st_uid),
            'gid': st.st_gid, 'group': gid2group(st.st_gid),
            'ctime': st.st_ctime, 'mtime': st.st_mtime,
        })

    def process_chunk(self, data, cache):
        id = self.crypto.id_hash(data)
        try:
            return self.chunk_idx[id]
        except KeyError:
            idx = len(self.chunks)
            size = cache.add_chunk(id, data, self.crypto)
            self.chunks.append((id, size))
            self.chunk_idx[id] = idx
            return idx

    @staticmethod
    def list_archives(store, crypto):
        for id in list(store.list(NS_ARCHIVE_METADATA)):
            archive = Archive(store, crypto)
            archive.load(id)
            yield archive

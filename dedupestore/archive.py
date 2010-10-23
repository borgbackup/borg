from datetime import datetime
import logging
import msgpack
import os
import stat
import sys

from .cache import NS_ARCHIVES, NS_CHUNKS, NS_CINDEX
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
        archive = msgpack.unpackb(self.crypto.decrypt(self.store.get(NS_ARCHIVES, self.id)))
        if archive['version'] != 1:
            raise Exception('Archive version %r not supported' % archive['version'])
        self.items = archive['items']
        self.name = archive['name']
        cindex = msgpack.unpackb(self.crypto.decrypt(self.store.get(NS_CINDEX, self.id)))
        assert cindex['version'] == 1
        self.chunks = cindex['chunks']
        for i, chunk in enumerate(self.chunks):
            self.chunk_idx[i] = chunk[0]

    def save(self, name):
        self.id = self.crypto.id_hash(name)
        archive = {
            'version': 1,
            'name': name,
            'cmdline': sys.argv,
            'ts': datetime.utcnow().isoformat(),
            'items': self.items,
        }
        data = self.crypto.encrypt_read(msgpack.packb(archive))
        self.store.put(NS_ARCHIVES, self.id, data)
        cindex = {
            'version': 1,
            'chunks': self.chunks,
        }
        data = self.crypto.encrypt_create(msgpack.packb(cindex))
        self.store.put(NS_CINDEX, self.id, data)
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
        for item in self.items:
            print item['path']

    def extract(self, dest=None):
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
                self.restore_stat(path, item, call_utime=False)
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
                            fd.write(self.crypto.decrypt(self.store.get(NS_CHUNKS, id)))
                        except ValueError:
                            raise Exception('Invalid chunk checksum')
                self.restore_stat(path, item)
            else:
                raise Exception('Unknown archive item type %r' % item['type'])
            if dir_stat_queue and not path.startswith(dir_stat_queue[-1][0]):
                self.restore_stat(*dir_stat_queue.pop())

    def restore_stat(self, path, item, call_utime=True):
        os.lchmod(path, item['mode'])
        uid = user2uid(item['user']) or item['uid']
        gid = group2gid(item['group']) or item['gid']
        try:
            os.lchown(path, uid, gid)
        except OSError:
            pass
        if call_utime:
            # FIXME: We should really call futimes here (c extension required)
            os.utime(path, (item['ctime'], item['mtime']))

    def verify(self):
        for item in self.items:
            if item['type'] == 'FILE':
                item['path'] = item['path'].decode('utf-8')
                for chunk in item['chunks']:
                    id = self.chunk_idx[chunk]
                    try:
                        self.crypto.decrypt(self.store.get(NS_CHUNKS, id))
                    except IntegrityError:
                        logging.error('%s ... ERROR', item['path'])
                        break
                else:
                    logging.info('%s ... OK', item['path'])

    def delete(self, cache):
        self.store.delete(NS_ARCHIVES, self.id)
        self.store.delete(NS_CINDEX, self.id)
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
        try:
            self.store.get(NS_ARCHIVES, name)
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
        for id in store.list(NS_ARCHIVES):
            archive = Archive(store, crypto)
            archive.load(id)
            yield archive

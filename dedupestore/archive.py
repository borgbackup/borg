from datetime import datetime
import hashlib
import logging
import msgpack
import os
import stat
import zlib

from .cache import NS_ARCHIVES, NS_CHUNKS
from .chunkifier import chunkify
from .helpers import uid2user, user2uid, gid2group, group2gid

CHUNK_SIZE = 55001


class Archive(object):

    def __init__(self, store, cache, name=None):
        self.store = store
        self.cache = cache
        self.items = []
        self.chunks = []
        self.chunk_idx = {}
        if name:
            self.open(name)

    def open(self, name):
        id = self.cache.archives[name]
        data = self.store.get(NS_ARCHIVES, id)
        if hashlib.sha256(data).digest() != id:
            raise Exception('Archive hash did not match')
        archive = msgpack.unpackb(zlib.decompress(data))
        self.items = archive['items']
        self.name = archive['name']
        self.chunks = archive['chunks']
        for i, chunk in enumerate(archive['chunks']):
            self.chunk_idx[i] = chunk[0]

    def save(self, name):
        archive = {
            'name': name,
            'ts': datetime.utcnow().isoformat(),
            'items': self.items,
            'chunks': self.chunks
        }
        data = zlib.compress(msgpack.packb(archive))
        self.id = hashlib.sha256(data).digest()
        self.store.put(NS_ARCHIVES, self.id, data)
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
        total_osize = 0
        total_csize = 0
        total_usize = 0
        chunk_count = {}
        for item in self.items:
            if item['type'] == 'FILE':
                total_osize += item['size']
                for idx in item['chunks']:
                    id = self.chunk_idx[idx]
                    chunk_count.setdefault(id, 0)
                    chunk_count[id] += 1
        for id, c in chunk_count.items():
            count, size = cache.chunkmap[id]
            total_csize += size
            if  c == count:
                total_usize += size
        return dict(osize=total_osize, csize=total_csize, usize=total_usize)

    def list(self):
        for item in self.items:
            print item['path']

    def extract(self, dest=None):
        dest = dest or os.getcwdu()
        for item in self.items:
            assert item['path'][0] not in ('/', '\\', ':')
            path = os.path.join(dest, item['path'].decode('utf-8'))
            if item['type'] == 'DIRECTORY':
                logging.info(path)
                if not os.path.exists(path):
                    os.makedirs(path)
            elif item['type'] == 'SYMLINK':
                logging.info('%s => %s', path, item['source'])
                if not os.path.exists(os.path.dirname(path)):
                    os.makedirs(os.path.dirname(path))
                os.symlink(item['source'], path)
            elif item['type'] == 'FILE':
                logging.info(path)
                if not os.path.exists(os.path.dirname(path)):
                    os.makedirs(os.path.dirname(path))
                with open(path, 'wb') as fd:
                    for chunk in item['chunks']:
                        id = self.chunk_idx[chunk]
                        data = self.store.get(NS_CHUNKS, id)
                        cid = data[:32]
                        data = data[32:]
                        if hashlib.sha256(data).digest() != cid:
                            raise Exception('Invalid chunk checksum')
                        data = zlib.decompress(data)
                        fd.write(data)
                os.chmod(path, item['mode'])
                uid = user2uid(item['user']) or item['uid']
                gid = group2gid(item['group']) or item['gid']
                try:
                    os.chown(path, uid, gid)
                except OSError:
                    pass
                os.utime(path, (item['ctime'], item['mtime']))

    def verify(self):
        for item in self.items:
            if item['type'] == 'FILE':
                item['path'] = item['path'].decode('utf-8')
                for chunk in item['chunks']:
                    id = self.chunk_idx[chunk]
                    data = self.store.get(NS_CHUNKS, id)
                    data = self.store.get(NS_CHUNKS, id)
                    cid = data[:32]
                    data = data[32:]
                    if (hashlib.sha256(data).digest() != cid):
                        logging.error('%s ... ERROR', item['path'])
                        break
                else:
                    logging.info('%s ... OK', item['path'])

    def delete(self, cache):
        self.store.delete(NS_ARCHIVES, self.cache.archives[self.name])
        for item in self.items:
            if item['type'] == 'FILE':
                for c in item['chunks']:
                    id = self.chunk_idx[c]
                    cache.chunk_decref(id)
        self.store.commit()
        del cache.archives[self.name]
        cache.save()

    def walk(self, path):
        st = os.lstat(path)
        if stat.S_ISDIR(st.st_mode):
            for f in os.listdir(path):
                for x in self.walk(os.path.join(path, f)):
                    yield x
        else:
            yield path, st

    def create(self, name, paths, cache):
        if name in cache.archives:
            raise NameError('Archive already exists')
        for path in paths:
            for path, st in self.walk(unicode(path)):
                if stat.S_ISDIR(st.st_mode):
                    self.process_dir(path, st)
                elif stat.S_ISLNK(st.st_mode):
                    self.process_link(path, st)
                elif stat.S_ISREG(st.st_mode):
                    self.process_file(path, st)
                else:
                    logging.error('Unknown file type: %s', path)
        self.save(name)
        cache.archives[name] = self.id
        cache.save()

    def process_dir(self, path, st):
        path = path.lstrip('/\\:')
        logging.info(path)
        self.items.append({'type': 'DIRECTORY', 'path': path})

    def process_link(self, path, st):
        source = os.readlink(path)
        path = path.lstrip('/\\:')
        logging.info('%s => %s', path, source)
        self.items.append({'type': 'SYMLINK', 'path': path, 'source': source})

    def process_file(self, path, st):
        try:
            fd = open(path, 'rb')
        except IOError, e:
            logging.error(e)
            return
        with fd:
            path = path.lstrip('/\\:')
            logging.info(path)
            chunks = []
            size = 0
            for chunk in chunkify(fd, CHUNK_SIZE, 30):
                size += len(chunk)
                chunks.append(self.add_chunk(*self.cache.add_chunk(chunk)))
        self.items.append({
            'type': 'FILE', 'path': path, 'chunks': chunks, 'size': size,
            'mode': st.st_mode,
            'uid': st.st_uid, 'user': uid2user(st.st_uid),
            'gid': st.st_gid, 'group': gid2group(st.st_gid),
            'ctime': st.st_ctime, 'mtime': st.st_mtime,
        })




import hashlib
import hmac
import msgpack
import os
import zlib

from Crypto.Cipher import AES


class CryptoManager(object):

    KEY_CREATE = 1
    KEY_READ = 2
    KEY_ID = 3
    KEY_ARCHIVE = 4
    KEY_CINDEX = 5

    def __init__(self, store):
        self.key_cache = {}
        self.store = store
        self.tid = store.tid
        self.id_key = '0' * 32
        self.read_key = os.urandom(32)
        self.create_key = os.urandom(32)

    def get_key(self, tid):
        try:
            return self.key_cache[tid]
        except KeyError:
            keys = self.load_key(tid)
            self.key_cache[tid] = keys
            return keys

    def load_key(self, tid):
        data = self.store.get('K', str(tid))
        id = data[:32]
        if self.id_hash(data[32:]) != id:
            raise Exception('Invalid key object found')
        key = msgpack.unpackb(data[32:])
        return key['create'], key['read']

    def store_key(self):
        key = {
            'version': 1,
            'read': self.read_key,
            'create': self.create_key,
        }
        data = msgpack.packb(key)
        id = self.id_hash(data)
        self.store.put('K', str(self.tid), id + data)

    def id_hash(self, data):
        return hmac.new(self.id_key, data, hashlib.sha256).digest()

    def pack(self, data, key):
        data = zlib.compress(msgpack.packb(data))
        id = hmac.new(key, data, hashlib.sha256).digest()
        data = AES.new(key, AES.MODE_CFB, id[:16]).encrypt(data)
        return id + msgpack.packb((1, self.tid, data))

    def pack_read(self, data):
        return self.pack(data, self.read_key)

    def pack_create(self, data):
        return self.pack(data, self.create_key)

    def unpack(self, data, key_idx):
        id = data[:32]
        version, tid, data = msgpack.unpackb(data[32:])
        assert version == 1
        key = self.get_key(tid)[key_idx]
        data = AES.new(key, AES.MODE_CFB, id[:16]).decrypt(data)
        if hmac.new(key, data, hashlib.sha256).digest() != id:
            raise ValueError
        return msgpack.unpackb(zlib.decompress(data))

    def unpack_read(self, data):
        return self.unpack(data, 1)

    def unpack_create(self, data):
        return self.unpack(data, 0)


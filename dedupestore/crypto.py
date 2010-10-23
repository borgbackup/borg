import os
import zlib

from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Util.number import bytes_to_long, long_to_bytes

from .helpers import IntegrityError
from .oaep import OAEP


class CryptoManager(object):

    CREATE = '\1'
    READ = '\2'

    def __init__(self, store):
        self.key_cache = {}
        self.store = store
        self.tid = store.tid
        self.id_key = '0' * 32
        self.read_key = os.urandom(32)
        self.create_key = os.urandom(32)
        self.read_encrypted = OAEP(256, hash=SHA256).encode(self.read_key, os.urandom(32))
        self.create_encrypted = OAEP(256, hash=SHA256).encode(self.create_key, os.urandom(32))

    def id_hash(self, data):
        return HMAC.new(self.id_key, data, SHA256).digest()

    def encrypt_read(self, data):
        key_data = OAEP(256, hash=SHA256).encode(self.read_key, os.urandom(32))
        #key_data = self.rsa_create.encrypt(key_data)
        data = zlib.compress(data)
        hash = SHA256.new(data).digest()
        data = AES.new(self.read_key, AES.MODE_CFB, hash[:16]).encrypt(data)
        return ''.join((self.READ, self.read_encrypted, hash, data))

    def encrypt_create(self, data):
        key_data = OAEP(256, hash=SHA256).encode(self.create_key, os.urandom(32))
        #key_data = self.rsa_create.encrypt(key_data)
        data = zlib.compress(data)
        hash = SHA256.new(data).digest()
        data = AES.new(self.create_key, AES.MODE_CFB, hash[:16]).encrypt(data)
        return ''.join((self.CREATE, self.create_encrypted, hash, data))

    def decrypt(self, data):
        type = data[0]
        if type == self.READ:
            key_data = data[1:257]
            hash = data[257:289]
            #key_data = self.rsa_create.decrypt(key_data)
            key = OAEP(256, hash=SHA256).decode(key_data)
            data = AES.new(key, AES.MODE_CFB, hash[:16]).decrypt(data[289:])
            if SHA256.new(data).digest() != hash:
                raise IntegrityError('decryption failed')
            return zlib.decompress(data)
        elif type == self.CREATE:
            key_data = data[1:257]
            hash = data[257:289]
            #key_data = self.rsa_create.decrypt(key_data)
            key = OAEP(256, hash=SHA256).decode(key_data)
            data = AES.new(key, AES.MODE_CFB, hash[:16]).decrypt(data[289:])
            if SHA256.new(data).digest() != hash:
                raise IntegrityError('decryption failed')
            return zlib.decompress(data)
        else:
            raise Exception('Unknown pack type %d found' % ord(type))

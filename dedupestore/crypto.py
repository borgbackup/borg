import os
import logging
import msgpack
import zlib

from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.PublicKey import RSA
from Crypto.Util import Counter
from Crypto.Util.number import bytes_to_long

from .helpers import IntegrityError
from .oaep import OAEP


class KeyChain(object):

    def __init__(self, path=None):
        self.aes_id = self.rsa_read = self.rsa_create = None
        if path:
            self.open(path)

    def open(self, path):
        with open(path, 'rb') as fd:
            chain = msgpack.unpackb(fd.read())
        logging.info('Key chain "%s" opened', path)
        assert chain['version'] == 1
        self.aes_id = chain['aes_id']
        self.rsa_read = RSA.importKey(chain['rsa_read'])
        self.rsa_create = RSA.importKey(chain['rsa_create'])

    def save(self, path):
        chain = {
            'version': 1,
            'aes_id': self.aes_id,
            'rsa_read': self.rsa_read.exportKey('PEM'),
            'rsa_create': self.rsa_create.exportKey('PEM'),
        }
        with open(path, 'wb') as fd:
            fd.write(msgpack.packb(chain))
            logging.info('Key chain "%s" saved', path)

    @staticmethod
    def generate():
        chain = KeyChain()
        chain.aes_id = os.urandom(32)
        chain.rsa_read = RSA.generate(2048)
        chain.rsa_create = RSA.generate(2048)
        return chain

class CryptoManager(object):

    CREATE = '\1'
    READ = '\2'

    def __init__(self, keychain):
        self._key_cache = {}
        self.keychain = keychain
        self.read_key = os.urandom(32)
        self.create_key = os.urandom(32)
        self.read_encrypted = OAEP(256, hash=SHA256).encode(self.read_key, os.urandom(32))
        self.read_encrypted = keychain.rsa_read.encrypt(self.read_encrypted, '')[0]
        self.create_encrypted = OAEP(256, hash=SHA256).encode(self.create_key, os.urandom(32))
        self.create_encrypted = keychain.rsa_create.encrypt(self.create_encrypted, '')[0]

    def id_hash(self, data):
        return HMAC.new(self.keychain.aes_id, data, SHA256).digest()

    def encrypt_read(self, data):
        data = zlib.compress(data)
        hash = SHA256.new(data).digest()
        counter = Counter.new(128, initial_value=bytes_to_long(hash[:16]), allow_wraparound=True)
        data = AES.new(self.read_key, AES.MODE_CTR, '', counter=counter).encrypt(data)
        return ''.join((self.READ, self.read_encrypted, hash, data))

    def encrypt_create(self, data):
        data = zlib.compress(data)
        hash = SHA256.new(data).digest()
        counter = Counter.new(128, initial_value=bytes_to_long(hash[:16]), allow_wraparound=True)
        data = AES.new(self.create_key, AES.MODE_CTR, '', counter=counter).encrypt(data)
        return ''.join((self.CREATE, self.create_encrypted, hash, data))

    def decrypt_key(self, data, rsa_key):
        try:
            return self._key_cache[data]
        except KeyError:
            self._key_cache[data] = OAEP(256, hash=SHA256).decode(rsa_key.decrypt(data))
            return self._key_cache[data]

    def decrypt(self, data):
        type = data[0]
        if type == self.READ:
            key = self.decrypt_key(data[1:257], self.keychain.rsa_read)
            hash = data[257:289]
            counter = Counter.new(128, initial_value=bytes_to_long(hash[:16]), allow_wraparound=True)
            data = AES.new(key, AES.MODE_CTR, counter=counter).decrypt(data[289:])
            if SHA256.new(data).digest() != hash:
                raise IntegrityError('decryption failed')
            return zlib.decompress(data)
        elif type == self.CREATE:
            key = self.decrypt_key(data[1:257], self.keychain.rsa_create)
            hash = data[257:289]
            counter = Counter.new(128, initial_value=bytes_to_long(hash[:16]), allow_wraparound=True)
            data = AES.new(key, AES.MODE_CTR, '', counter=counter).decrypt(data[289:])
            if SHA256.new(data).digest() != hash:
                raise IntegrityError('decryption failed')
            return zlib.decompress(data)
        else:
            raise Exception('Unknown pack type %d found' % ord(type))

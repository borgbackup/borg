from getpass import getpass
import hashlib
import os
import msgpack
import zlib

from pbkdf2 import pbkdf2
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.PublicKey import RSA
from Crypto.Util import Counter
from Crypto.Util.number import bytes_to_long, long_to_bytes

from .helpers import IntegrityError, zero_pad
from .oaep import OAEP


class Keychain(object):
    FILE_ID = 'DARC KEYCHAIN'

    CREATE = '\1'
    READ = '\2'

    def __init__(self, path=None):
        self._key_cache = {}
        self.read_key = os.urandom(32)
        self.create_key = os.urandom(32)
        self.counter = Counter.new(64, prefix='\0' * 8)
        self.aes_id = self.rsa_read = self.rsa_create = None
        self.path = path
        if path:
            self.open(path)

    def get_chunkify_seed(self):
        return bytes_to_long(self.aes_id[:4])

    def open(self, path):
        print 'Opening keychain "%s"' % path
        with open(path, 'rb') as fd:
            if fd.read(len(self.FILE_ID)) != self.FILE_ID:
                raise ValueError('Not a keychain')
            cdata = fd.read()
        self.password = ''
        data = self.decrypt_keychain(cdata, '')
        while not data:
            self.password = getpass('Keychain password: ')
            if not self.password:
                raise Exception('Keychain decryption failed')
            data = self.decrypt_keychain(cdata, self.password)
            if not data:
                print 'Incorrect password'
        chain = msgpack.unpackb(data)
        assert chain['version'] == 1
        self.aes_id = chain['aes_id']
        self.rsa_read = RSA.importKey(chain['rsa_read'])
        self.rsa_create = RSA.importKey(chain['rsa_create'])
        self.read_encrypted = OAEP(256, hash=SHA256).encode(self.read_key, os.urandom(32))
        self.read_encrypted = zero_pad(self.rsa_read.encrypt(self.read_encrypted, '')[0], 256)
        self.create_encrypted = OAEP(256, hash=SHA256).encode(self.create_key, os.urandom(32))
        self.create_encrypted = zero_pad(self.rsa_create.encrypt(self.create_encrypted, '')[0], 256)

    def encrypt_keychain(self, data, password):
        salt = os.urandom(32)
        iterations = 2000
        key = pbkdf2(password, salt, 32, iterations, hashlib.sha256)
        hash = HMAC.new(key, data, SHA256).digest()
        cdata = AES.new(key, AES.MODE_CTR, counter=Counter.new(128)).encrypt(data)
        d = {
            'version': 1,
            'salt': salt,
            'iterations': iterations,
            'algorithm': 'SHA256',
            'hash': hash,
            'data': cdata,
        }
        return msgpack.packb(d)

    def decrypt_keychain(self, data, password):
        d = msgpack.unpackb(data)
        assert d['version'] == 1
        assert d['algorithm'] == 'SHA256'
        key = pbkdf2(password, d['salt'], 32, d['iterations'], hashlib.sha256)
        data = AES.new(key, AES.MODE_CTR, counter=Counter.new(128)).decrypt(d['data'])
        if HMAC.new(key, data, SHA256).digest() != d['hash']:
            return None
        return data

    def save(self, path, password):
        chain = {
            'version': 1,
            'aes_id': self.aes_id,
            'rsa_read': self.rsa_read.exportKey('PEM'),
            'rsa_create': self.rsa_create.exportKey('PEM'),
        }
        data = self.encrypt_keychain(msgpack.packb(chain), password)
        with open(path, 'wb') as fd:
            fd.write(self.FILE_ID)
            fd.write(data)
            print 'Key chain "%s" saved' % path

    def restrict(self, path):
        if os.path.exists(path):
            print '%s already exists' % path
            return 1
        self.rsa_read = self.rsa_read.publickey()
        self.save(path, self.password)
        return 0

    def chpass(self):
        password, password2 = 1, 2
        while password != password2:
            password = getpass('New password: ')
            password2 = getpass('New password again: ')
            if password != password2:
                print 'Passwords do not match'
        self.save(self.path, password)
        return 0

    @staticmethod
    def generate(path):
        if os.path.exists(path):
            print '%s already exists' % path
            return 1
        password, password2 = 1, 2
        while password != password2:
            password = getpass('Keychain password: ')
            password2 = getpass('Keychain password again: ')
            if password != password2:
                print 'Passwords do not match'
        chain = Keychain()
        print 'Generating keychain'
        chain.aes_id = os.urandom(32)
        chain.rsa_read = RSA.generate(2048)
        chain.rsa_create = RSA.generate(2048)
        chain.save(path, password)
        return 0

    def id_hash(self, data):
        """Return HMAC hash using the "id" AES key
        """
        return HMAC.new(self.aes_id, data, SHA256).digest()

    def _encrypt(self, id, rsa_key, key, data):
        """Helper function used by `encrypt_read` and `encrypt_create`
        """
        data = zlib.compress(data)
        nonce = long_to_bytes(self.counter.next_value(), 8)
        data = nonce + rsa_key + AES.new(key, AES.MODE_CTR, '', counter=self.counter).encrypt(data)
        hash = self.id_hash(data)
        return ''.join((id, hash, data)), hash

    def encrypt_read(self, data):
        """Encrypt `data` using the AES "read" key

        An RSA encrypted version of the AES key is included in the header
        """
        return self._encrypt(self.READ, self.read_encrypted, self.read_key, data)

    def encrypt_create(self, data, iv=None):
        """Encrypt `data` using the AES "create" key

        An RSA encrypted version of the AES key is included in the header
        """
        return self._encrypt(self.CREATE, self.create_encrypted, self.create_key, data)

    def _decrypt_key(self, data, rsa_key):
        """Helper function used by `decrypt`
        """
        try:
            return self._key_cache[data]
        except KeyError:
            self._key_cache[data] = OAEP(256, hash=SHA256).decode(rsa_key.decrypt(data))
            return self._key_cache[data]

    def decrypt(self, data):
        """Decrypt `data` previously encrypted by `encrypt_create` or `encrypt_read`
        """
        type = data[0]
        hash = data[1:33]
        if self.id_hash(data[33:]) != hash:
            raise IntegrityError('Encryption integrity error')
        nonce = bytes_to_long(data[33:41])
        counter = Counter.new(64, prefix='\0' * 8, initial_value=nonce)
        if type == self.READ:
            key = self._decrypt_key(data[41:297], self.rsa_read)
        elif type == self.CREATE:
            key = self._decrypt_key(data[41:297], self.rsa_create)
        else:
            raise Exception('Unknown pack type %d found' % ord(type))
        data = AES.new(key, AES.MODE_CTR, counter=counter).decrypt(data[297:])
        return zlib.decompress(data), hash




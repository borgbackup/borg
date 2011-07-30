from __future__ import with_statement
from getpass import getpass
import hashlib
import os
import msgpack
import zlib

from pbkdf2 import pbkdf2
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Util import Counter
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Random import get_random_bytes

from .helpers import IntegrityError


class Key(object):
    FILE_ID = 'DARC KEY'

    def __init__(self, store=None):
        if store:
            self.open(store)

    def open(self, store):
        path = os.path.join(os.path.expanduser('~'),
                            '.darc', 'keys', store.id.encode('hex'))
        with open(path, 'rb') as fd:
            lines = fd.readlines()
            if not lines[0].startswith(self.FILE_ID) != self.FILE_ID:
                raise ValueError('Not a DARC key file')
            self.store_id = lines[0][len(self.FILE_ID):].strip().decode('hex')
            cdata = (''.join(lines[1:])).decode('base64')
        self.password = ''
        data = self.decrypt_key_file(cdata, '')
        while not data:
            self.password = getpass('Key password: ')
            if not self.password:
                raise Exception('Key decryption failed')
            data = self.decrypt_key_file(cdata, self.password)
            if not data:
                print 'Incorrect password'
        key = msgpack.unpackb(data)
        assert key['version'] == 1
        self.store_id = key['store_id']
        self.enc_key = key['enc_key']
        self.enc_hmac_key = key['enc_hmac_key']
        self.id_key = key['id_key']
        self.archive_key = key['archive_key']
        self.chunk_seed = key['chunk_seed']
        self.counter = Counter.new(128, initial_value=bytes_to_long(os.urandom(16)), allow_wraparound=True)

    def encrypt_key_file(self, data, password):
        salt = get_random_bytes(32)
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

    def decrypt_key_file(self, data, password):
        d = msgpack.unpackb(data)
        assert d['version'] == 1
        assert d['algorithm'] == 'SHA256'
        key = pbkdf2(password, d['salt'], 32, d['iterations'], hashlib.sha256)
        data = AES.new(key, AES.MODE_CTR, counter=Counter.new(128)).decrypt(d['data'])
        if HMAC.new(key, data, SHA256).digest() != d['hash']:
            return None
        return data

    def save(self, path, password):
        key = {
            'version': 1,
            'store_id': self.store_id,
            'enc_key': self.enc_key,
            'enc_hmac_key': self.enc_hmac_key,
            'id_key': self.enc_key,
            'archive_key': self.enc_key,
            'chunk_seed': self.chunk_seed,
        }
        data = self.encrypt_key_file(msgpack.packb(key), password)
        with open(path, 'wb') as fd:
            fd.write('%s %s\n' % (self.FILE_ID, self.store_id.encode('hex')))
            fd.write(data.encode('base64'))
            print 'Key chain "%s" created' % path

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
    def create(store):
        path = os.path.join(os.path.expanduser('~'),
                            '.darc', 'keys', store.id.encode('hex'))
        if os.path.exists(path):
            print '%s already exists' % path
            return 1
        password, password2 = 1, 2
        while password != password2:
            password = getpass('Keychain password: ')
            password2 = getpass('Keychain password again: ')
            if password != password2:
                print 'Passwords do not match'
        key = Key()
        key.store_id = store.id
        # Chunk AES256 encryption key
        key.enc_key = get_random_bytes(32)
        # Chunk encryption HMAC key
        key.enc_hmac_key = get_random_bytes(32)
        # Chunk id HMAC key
        key.id_key = get_random_bytes(32)
        # Archive name HMAC key
        key.archive_key = get_random_bytes(32)
        # Chunkifier seed
        key.chunk_seed = bytes_to_long(get_random_bytes(4)) & 0x7fffffff
        key.save(path, password)
        return 0

    def id_hash(self, data):
        """Return HMAC hash using the "id" HMAC key
        """
        return HMAC.new(self.id_key, data, SHA256).digest()

    def archive_hash(self, data):
        """Return HMAC hash using the "archive" HMAC key
        """
        return HMAC.new(self.archive_key, data, SHA256).digest()

    def encrypt(self, data):
        data = zlib.compress(data)
        nonce = long_to_bytes(self.counter.next_value(), 16)
        data = ''.join((nonce, AES.new(self.enc_key, AES.MODE_CTR, '',
                                       counter=self.counter).encrypt(data)))
        hash = HMAC.new(self.enc_hmac_key, data, SHA256).digest()
        return ''.join(('\0', hash, data)), hash

    def decrypt(self, data):
        assert data[0] == '\0'
        hash = data[1:33]
        if HMAC.new(self.enc_hmac_key, data[33:], SHA256).digest() != hash:
            raise IntegrityError('Encryption integrity error')
        nonce = bytes_to_long(data[33:49])
        counter = Counter.new(128, initial_value=nonce, allow_wraparound=True)
        data = AES.new(self.enc_key, AES.MODE_CTR, counter=counter).decrypt(data[49:])
        return zlib.decompress(data), hash


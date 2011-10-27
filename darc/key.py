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

from .helpers import IntegrityError, get_keys_dir

PREFIX = '\0' * 8

class Key(object):
    FILE_ID = 'DARC KEY'

    def __init__(self, store=None, password=None):
        if store:
            self.open(self.find_key_file(store), password=password)

    def find_key_file(self, store):
        id = store.id.encode('hex')
        keys_dir = get_keys_dir()
        for name in os.listdir(keys_dir):
            filename = os.path.join(keys_dir, name)
            with open(filename, 'rb') as fd:
                line = fd.readline().strip()
                if line and line.startswith(self.FILE_ID) and line[9:] == id:
                    return filename
        raise Exception('Key file for store with ID %s not found' % id)

    def open(self, filename, prompt=None, password=None):
        prompt = prompt or 'Enter password for %s: ' % filename
        with open(filename, 'rb') as fd:
            lines = fd.readlines()
            if not lines[0].startswith(self.FILE_ID) != self.FILE_ID:
                raise ValueError('Not a DARC key file')
            self.store_id = lines[0][len(self.FILE_ID):].strip().decode('hex')
            cdata = (''.join(lines[1:])).decode('base64')
        self.password = password or ''
        data = self.decrypt_key_file(cdata, self.password)
        while not data:
            self.password = getpass(prompt)
            if not self.password:
                raise Exception('Key decryption failed')
            data = self.decrypt_key_file(cdata, self.password)
            if not data:
                print 'Incorrect password'
        key = msgpack.unpackb(data)
        if key['version'] != 1:
            raise IntegrityError('Invalid key file header')
        self.store_id = key['store_id']
        self.enc_key = key['enc_key']
        self.enc_hmac_key = key['enc_hmac_key']
        self.id_key = key['id_key']
        self.chunk_seed = key['chunk_seed']
        self.counter = Counter.new(64, initial_value=1, prefix=PREFIX)
        self.path = filename

    def post_manifest_load(self, config):
        iv = bytes_to_long(config['aes_counter'])+100
        self.counter = Counter.new(64, initial_value=iv, prefix=PREFIX)

    def pre_manifest_write(self, manifest):
        manifest.config['aes_counter'] = long_to_bytes(self.counter.next_value(), 8)

    def encrypt_key_file(self, data, password):
        salt = get_random_bytes(32)
        iterations = 10000
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
            'chunk_seed': self.chunk_seed,
        }
        data = self.encrypt_key_file(msgpack.packb(key), password)
        with open(path, 'wb') as fd:
            fd.write('%s %s\n' % (self.FILE_ID, self.store_id.encode('hex')))
            fd.write(data.encode('base64'))
        self.path = path

    def chpasswd(self):
        password, password2 = 1, 2
        while password != password2:
            password = getpass('New password: ')
            password2 = getpass('New password again: ')
            if password != password2:
                print 'Passwords do not match'
        self.save(self.path, password)
        return 0

    @staticmethod
    def create(store, filename, password=None):
        i = 1
        path = filename
        while os.path.exists(path):
            i += 1
            path = filename + '.%d' % i
        if password is not None:
            password2 = password
        else:
            password, password2 = 1, 2
        while password != password2:
            password = getpass('Key file password (Leave blank for no password): ')
            password2 = getpass('Key file password again: ')
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
        # Chunkifier seed
        key.chunk_seed = bytes_to_long(get_random_bytes(4))
        # Convert to signed int32
        if key.chunk_seed & 0x80000000:
            key.chunk_seed = key.chunk_seed - 0xffffffff - 1
        key.save(path, password)
        return Key(store, password=password)

    def id_hash(self, data):
        """Return HMAC hash using the "id" HMAC key
        """
        return HMAC.new(self.id_key, data, SHA256).digest()

    def encrypt(self, data):
        data = zlib.compress(data)
        nonce = long_to_bytes(self.counter.next_value(), 8)
        data = ''.join((nonce, AES.new(self.enc_key, AES.MODE_CTR, '',
                                       counter=self.counter).encrypt(data)))
        hash = HMAC.new(self.enc_hmac_key, data, SHA256).digest()
        return ''.join(('\0', hash, data))

    def decrypt(self, id, data):
        if data[0] != '\0':
            raise IntegrityError('Invalid encryption envelope')
        hash = data[1:33]
        if HMAC.new(self.enc_hmac_key, data[33:], SHA256).digest() != hash:
            raise IntegrityError('Encryption envelope checksum mismatch')
        nonce = bytes_to_long(data[33:41])
        counter = Counter.new(64, initial_value=nonce, prefix=PREFIX)
        data = zlib.decompress(AES.new(self.enc_key, AES.MODE_CTR, counter=counter).decrypt(data[41:]))
        if id and HMAC.new(self.id_key, data, SHA256).digest() != id:
            raise IntegrityError('Chunk id verification failed')
        return data


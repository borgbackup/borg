from __future__ import with_statement
from getpass import getpass
import os
import msgpack
import tempfile
import unittest
import zlib

from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Util import Counter
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

from .helpers import IntegrityError, get_keys_dir

PREFIX = '\0' * 8

KEYFILE = '\0'
PASSPHRASE = '\1'
PLAINTEXT = '\2'


def key_creator(store, args):
    if args.keyfile:
        return KeyfileKey.create(store, args)
    elif args.passphrase:
        return PassphraseKey.create(store, args)
    else:
        return PlaintextKey.create(store, args)


def key_factory(store, manifest_data):
    if manifest_data[0] == KEYFILE:
        return KeyfileKey.detect(store, manifest_data)
    elif manifest_data[0] == PASSPHRASE:
        return PassphraseKey.detect(store, manifest_data)
    elif manifest_data[0] == PLAINTEXT:
        return PlaintextKey.detect(store, manifest_data)
    else:
        raise Exception('Unkown Key type %d' % ord(manifest_data[0]))


def SHA256_PDF(p, s):
    return HMAC.new(p, s, SHA256).digest()


class KeyBase(object):

    def id_hash(self, data):
        """Return HMAC hash using the "id" HMAC key
        """

    def encrypt(self, data):
        pass

    def decrypt(self, id, data):
        pass

    def post_manifest_load(self, config):
        pass

    def pre_manifest_write(self, manifest):
        pass


class PlaintextKey(KeyBase):
    TYPE = PLAINTEXT

    chunk_seed = 0

    @classmethod
    def create(cls, store, args):
        print 'Encryption NOT enabled.\nUse the --key-file or --passphrase options to enable encryption.'
        return cls()

    @classmethod
    def detect(cls, store, manifest_data):
        return cls()

    def id_hash(self, data):
        return SHA256.new(data).digest()

    def encrypt(self, data):
        return ''.join([self.TYPE, zlib.compress(data)])

    def decrypt(self, id, data):
        if data[0] != self.TYPE:
            raise IntegrityError('Invalid encryption envelope')
        data = zlib.decompress(data[1:])
        if id and SHA256.new(data).digest() != id:
            raise IntegrityError('Chunk id verification failed')
        return data


class AESKeyBase(KeyBase):

    def post_manifest_load(self, config):
        iv = bytes_to_long(config['aes_counter']) + 100
        self.counter = Counter.new(64, initial_value=iv, prefix=PREFIX)

    def pre_manifest_write(self, manifest):
        manifest.config['aes_counter'] = long_to_bytes(self.counter.next_value(), 8)

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
        return ''.join((self.TYPE, hash, data))

    def decrypt(self, id, data):
        if data[0] != self.TYPE:
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

    def init_from_random_data(self, data):
        self.enc_key = data[0:32]
        self.enc_hmac_key = data[32:64]
        self.id_key = data[64:96]
        self.chunk_seed = bytes_to_long(data[96:100])
        # Convert to signed int32
        if self.chunk_seed & 0x80000000:
            self.chunk_seed = self.chunk_seed - 0xffffffff - 1
        self.counter = Counter.new(64, initial_value=1, prefix=PREFIX)


class PassphraseKey(AESKeyBase):
    TYPE = PASSPHRASE
    iterations = 10000

    @classmethod
    def create(cls, store, args):
        key = cls()
        passphrase = os.environ.get('DARC_PASSPHRASE')
        if passphrase is not None:
            passphrase2 = passphrase
        else:
            passphrase, passphrase2 = 1, 2
        while passphrase != passphrase2:
            passphrase = getpass('Enter passphrase: ')
            if not passphrase:
                print 'Passphrase must not be blank'
                continue
            passphrase2 = getpass('Enter same passphrase again: ')
            if passphrase != passphrase2:
                print 'Passphrases do not match'
        key.init(store, passphrase)
        if passphrase:
            print 'Remember your passphrase. Your data will be inaccessible without it.'
        return key

    @classmethod
    def detect(cls, store, manifest_data):
        prompt = 'Enter passphrase for %s: ' % store._location.orig
        key = cls()
        passphrase = os.environ.get('DARC_PASSPHRASE')
        if passphrase is None:
            passphrase = getpass(prompt)
        while True:
            key.init(store, passphrase)
            try:
                key.decrypt(None, manifest_data)
                return key
            except IntegrityError:
                passphrase = getpass(prompt)

    def init(self, store, passphrase):
        self.init_from_random_data(PBKDF2(passphrase, store.id, 100, self.iterations, SHA256_PDF))


class KeyfileKey(AESKeyBase):
    FILE_ID = 'DARC KEY'
    TYPE = KEYFILE

    @classmethod
    def detect(cls, store, manifest_data):
        key = cls()
        path = cls.find_key_file(store)
        prompt = 'Enter passphrase for key file %s: ' % path
        passphrase = os.environ.get('DARC_PASSPHRASE', '')
        while not key.load(path, passphrase):
            passphrase = getpass(prompt)
        return key

    @classmethod
    def find_key_file(cls, store):
        id = store.id.encode('hex')
        keys_dir = get_keys_dir()
        for name in os.listdir(keys_dir):
            filename = os.path.join(keys_dir, name)
            with open(filename, 'rb') as fd:
                line = fd.readline().strip()
                if line and line.startswith(cls.FILE_ID) and line[9:] == id:
                    return filename
        raise Exception('Key file for store with ID %s not found' % id)

    def load(self, filename, passphrase):
        with open(filename, 'rb') as fd:
            cdata = (''.join(fd.readlines()[1:])).decode('base64')
        data = self.decrypt_key_file(cdata, passphrase)
        if data:
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
            return True

    def decrypt_key_file(self, data, passphrase):
        d = msgpack.unpackb(data)
        assert d['version'] == 1
        assert d['algorithm'] == 'SHA256'
        key = PBKDF2(passphrase, d['salt'], 32, d['iterations'], SHA256_PDF)
        data = AES.new(key, AES.MODE_CTR, counter=Counter.new(128)).decrypt(d['data'])
        if HMAC.new(key, data, SHA256).digest() != d['hash']:
            return None
        return data

    def encrypt_key_file(self, data, passphrase):
        salt = get_random_bytes(32)
        iterations = 10000
        key = PBKDF2(passphrase, salt, 32, iterations, SHA256_PDF)
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

    def save(self, path, passphrase):
        key = {
            'version': 1,
            'store_id': self.store_id,
            'enc_key': self.enc_key,
            'enc_hmac_key': self.enc_hmac_key,
            'id_key': self.enc_key,
            'chunk_seed': self.chunk_seed,
        }
        data = self.encrypt_key_file(msgpack.packb(key), passphrase)
        with open(path, 'wb') as fd:
            fd.write('%s %s\n' % (self.FILE_ID, self.store_id.encode('hex')))
            fd.write(data.encode('base64'))
        self.path = path

    def change_passphrase(self):
        passphrase, passphrase2 = 1, 2
        while passphrase != passphrase2:
            passphrase = getpass('New passphrase: ')
            passphrase2 = getpass('Enter same passphrase again: ')
            if passphrase != passphrase2:
                print 'Passphrases do not match'
        self.save(self.path, passphrase)
        print 'Key file "%s" updated' % self.path

    @classmethod
    def create(cls, store, args):
        filename = args.store.to_key_filename()
        path = filename
        i = 1
        while os.path.exists(path):
            i += 1
            path = filename + '.%d' % i
        passphrase = os.environ.get('DARC_PASSPHRASE')
        if passphrase is not None:
            passphrase2 = passphrase
        else:
            passphrase, passphrase2 = 1, 2
        while passphrase != passphrase2:
            passphrase = getpass('Enter passphrase (empty for no passphrase):')
            passphrase2 = getpass('Enter same passphrase again: ')
            if passphrase != passphrase2:
                print 'Passphrases do not match'
        key = cls()
        key.store_id = store.id
        key.init_from_random_data(get_random_bytes(100))
        key.save(path, passphrase)
        print 'Key file "%s" created.' % key.path
        print 'Keep this file safe. Your data will be inaccessible without it.'
        return key


class KeyTestCase(unittest.TestCase):

    class MockStore(object):
        id = '\0' * 32

    def test_plaintext(self):
        key = PlaintextKey.create(None, None)
        data = 'foo'
        self.assertEqual(key.id_hash(data).encode('hex'), '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae')
        self.assertEqual(data, key.decrypt(key.id_hash(data), key.encrypt(data)))

    def test_keyfile(self):
        class MockArgs(object):
            class StoreArg(object):
                def to_key_filename(self):
                    return tempfile.mkstemp()[1]
            store = StoreArg()
        os.environ['DARC_PASSPHRASE'] = 'test'
        key = KeyfileKey.create(self.MockStore(), MockArgs())
        data = 'foo'
        self.assertEqual(data, key.decrypt(key.id_hash(data), key.encrypt(data)))

    def test_passphrase(self):
        os.environ['DARC_PASSPHRASE'] = 'test'
        key = PassphraseKey.create(self.MockStore(), None)
        self.assertEqual(key.id_key.encode('hex'), 'f28e915da78a972786da47fee6c4bd2960a421b9bdbdb35a7942eb82552e9a72')
        self.assertEqual(key.enc_hmac_key.encode('hex'), '169c6082f209e524ea97e2c75318936f6e93c101b9345942a95491e9ae1738ca')
        self.assertEqual(key.enc_key.encode('hex'), 'c05dd423843d4dd32a52e4dc07bb11acabe215917fc5cf3a3df6c92b47af79ba')
        self.assertEqual(key.chunk_seed, -324662077)
        data = 'foo'
        self.assertEqual(key.id_hash(data).encode('hex'), '016c27cd40dc8e84f196f3b43a9424e8472897e09f6935d0d3a82fb41664bad7')
        self.assertEqual(data, key.decrypt(key.id_hash(data), key.encrypt(data)))


def suite():
    return unittest.TestLoader().loadTestsFromTestCase(KeyTestCase)

if __name__ == '__main__':
    unittest.main()
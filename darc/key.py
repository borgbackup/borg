from binascii import hexlify, a2b_base64, b2a_base64
from getpass import getpass
import os
import msgpack
import shutil
import tempfile
import unittest
import zlib

from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Util import Counter
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

from .helpers import IntegrityError, get_keys_dir, Location

PREFIX = b'\0' * 8

KEYFILE = b'\0'
PASSPHRASE = b'\1'
PLAINTEXT = b'\2'


def key_creator(store, args):
    if args.keyfile:
        return KeyfileKey.create(store, args)
    elif args.passphrase:
        return PassphraseKey.create(store, args)
    else:
        return PlaintextKey.create(store, args)


def key_factory(store, manifest_data):
    if manifest_data[:1] == KEYFILE:
        return KeyfileKey.detect(store, manifest_data)
    elif manifest_data[:1] == PASSPHRASE:
        return PassphraseKey.detect(store, manifest_data)
    elif manifest_data[:1] == PLAINTEXT:
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


class PlaintextKey(KeyBase):
    TYPE = PLAINTEXT

    chunk_seed = 0

    @classmethod
    def create(cls, store, args):
        print('Encryption NOT enabled.\nUse the --key-file or --passphrase options to enable encryption.')
        return cls()

    @classmethod
    def detect(cls, store, manifest_data):
        return cls()

    def id_hash(self, data):
        return SHA256.new(data).digest()

    def encrypt(self, data):
        return b''.join([self.TYPE, zlib.compress(data)])

    def decrypt(self, id, data):
        if data[:1] != self.TYPE:
            raise IntegrityError('Invalid encryption envelope')
        data = zlib.decompress(memoryview(data)[1:])
        if id and SHA256.new(data).digest() != id:
            raise IntegrityError('Chunk id verification failed')
        return data


class AESKeyBase(KeyBase):

    def id_hash(self, data):
        """Return HMAC hash using the "id" HMAC key
        """
        return HMAC.new(self.id_key, data, SHA256).digest()

    def encrypt(self, data):
        data = zlib.compress(data)
        nonce = long_to_bytes(self.counter.next_value(), 8)
        data = b''.join((nonce, AES.new(self.enc_key, AES.MODE_CTR, b'',
                                       counter=self.counter).encrypt(data)))
        hash = HMAC.new(self.enc_hmac_key, data, SHA256).digest()
        return b''.join((self.TYPE, hash, data))

    def decrypt(self, id, data):
        if data[:1] != self.TYPE:
            raise IntegrityError('Invalid encryption envelope')
        hash = memoryview(data)[1:33]
        if memoryview(HMAC.new(self.enc_hmac_key, memoryview(data)[33:], SHA256).digest()) != hash:
            raise IntegrityError('Encryption envelope checksum mismatch')
        nonce = bytes_to_long(memoryview(data)[33:41])
        counter = Counter.new(64, initial_value=nonce, prefix=PREFIX)
        data = zlib.decompress(AES.new(self.enc_key, AES.MODE_CTR, counter=counter).decrypt(memoryview(data)[41:]))
        if id and HMAC.new(self.id_key, data, SHA256).digest() != id:
            raise IntegrityError('Chunk id verification failed')
        return data

    def extract_iv(self, payload):
        if payload[:1] != self.TYPE:
            raise IntegrityError('Invalid encryption envelope')
        nonce = bytes_to_long(payload[33:41])
        return nonce

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
                print('Passphrase must not be blank')
                continue
            passphrase2 = getpass('Enter same passphrase again: ')
            if passphrase != passphrase2:
                print('Passphrases do not match')
        key.init(store, passphrase)
        if passphrase:
            print('Remember your passphrase. Your data will be inaccessible without it.')
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
                iv = key.extract_iv(manifest_data)
                key.counter = Counter.new(64, initial_value=iv + 1000, prefix=PREFIX)
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
        iv = key.extract_iv(manifest_data)
        key.counter = Counter.new(64, initial_value=iv + 1000, prefix=PREFIX)
        return key

    @classmethod
    def find_key_file(cls, store):
        id = hexlify(store.id).decode('ascii')
        keys_dir = get_keys_dir()
        for name in os.listdir(keys_dir):
            filename = os.path.join(keys_dir, name)
            with open(filename, 'r') as fd:
                line = fd.readline().strip()
                if line and line.startswith(cls.FILE_ID) and line[9:] == id:
                    return filename
        raise Exception('Key file for store with ID %s not found' % id)

    def load(self, filename, passphrase):
        with open(filename, 'r') as fd:
            cdata = a2b_base64(''.join(fd.readlines()[1:]).encode('ascii'))  # .encode needed for Python 3.[0-2]
        data = self.decrypt_key_file(cdata, passphrase)
        if data:
            key = msgpack.unpackb(data)
            if key[b'version'] != 1:
                raise IntegrityError('Invalid key file header')
            self.store_id = key[b'store_id']
            self.enc_key = key[b'enc_key']
            self.enc_hmac_key = key[b'enc_hmac_key']
            self.id_key = key[b'id_key']
            self.chunk_seed = key[b'chunk_seed']
            self.counter = Counter.new(64, initial_value=1, prefix=PREFIX)
            self.path = filename
            return True

    def decrypt_key_file(self, data, passphrase):
        d = msgpack.unpackb(data)
        assert d[b'version'] == 1
        assert d[b'algorithm'] == b'SHA256'
        key = PBKDF2(passphrase, d[b'salt'], 32, d[b'iterations'], SHA256_PDF)
        data = AES.new(key, AES.MODE_CTR, counter=Counter.new(128)).decrypt(d[b'data'])
        if HMAC.new(key, data, SHA256).digest() != d[b'hash']:
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
            'id_key': self.id_key,
            'chunk_seed': self.chunk_seed,
        }
        data = self.encrypt_key_file(msgpack.packb(key), passphrase)
        with open(path, 'w') as fd:
            fd.write('%s %s\n' % (self.FILE_ID, hexlify(self.store_id).decode('ascii')))
            fd.write(b2a_base64(data).decode('ascii'))
        self.path = path

    def change_passphrase(self):
        passphrase, passphrase2 = 1, 2
        while passphrase != passphrase2:
            passphrase = getpass('New passphrase: ')
            passphrase2 = getpass('Enter same passphrase again: ')
            if passphrase != passphrase2:
                print('Passphrases do not match')
        self.save(self.path, passphrase)
        print('Key file "%s" updated' % self.path)

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
                print('Passphrases do not match')
        key = cls()
        key.store_id = store.id
        key.init_from_random_data(get_random_bytes(100))
        key.save(path, passphrase)
        print('Key file "%s" created.' % key.path)
        print('Keep this file safe. Your data will be inaccessible without it.')
        return key


class KeyTestCase(unittest.TestCase):

    def setUp(self):
        self.tmppath = tempfile.mkdtemp()
        os.environ['DARC_KEYS_DIR'] = self.tmppath

    def tearDown(self):
        shutil.rmtree(self.tmppath)

    class MockStore(object):
        class _Location(object):
            orig = '/some/place'

        _location = _Location()
        id = b'\0' * 32

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        os.environ['DARC_KEYS_DIR'] = self.tmpdir

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_plaintext(self):
        key = PlaintextKey.create(None, None)
        data = b'foo'
        self.assertEqual(hexlify(key.id_hash(data)), b'2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae')
        self.assertEqual(data, key.decrypt(key.id_hash(data), key.encrypt(data)))

    def test_keyfile(self):
        class MockArgs(object):
            store = Location(tempfile.mkstemp()[1])
        os.environ['DARC_PASSPHRASE'] = 'test'
        key = KeyfileKey.create(self.MockStore(), MockArgs())
        self.assertEqual(bytes_to_long(key.counter()), 1)
        manifest = key.encrypt(b'')
        iv = key.extract_iv(manifest)
        key2 = KeyfileKey.detect(self.MockStore(), manifest)
        self.assertEqual(bytes_to_long(key2.counter()), iv + 1000)
        # Key data sanity check
        self.assertEqual(len(set([key2.id_key, key2.enc_key, key2.enc_hmac_key])), 3)
        self.assertEqual(key2.chunk_seed == 0, False)
        data = b'foo'
        self.assertEqual(data, key2.decrypt(key.id_hash(data), key.encrypt(data)))

    def test_passphrase(self):
        os.environ['DARC_PASSPHRASE'] = 'test'
        key = PassphraseKey.create(self.MockStore(), None)
        self.assertEqual(bytes_to_long(key.counter()), 1)
        self.assertEqual(hexlify(key.id_key), b'f28e915da78a972786da47fee6c4bd2960a421b9bdbdb35a7942eb82552e9a72')
        self.assertEqual(hexlify(key.enc_hmac_key), b'169c6082f209e524ea97e2c75318936f6e93c101b9345942a95491e9ae1738ca')
        self.assertEqual(hexlify(key.enc_key), b'c05dd423843d4dd32a52e4dc07bb11acabe215917fc5cf3a3df6c92b47af79ba')
        self.assertEqual(key.chunk_seed, -324662077)
        manifest = key.encrypt(b'')
        iv = key.extract_iv(manifest)
        key2 = PassphraseKey.detect(self.MockStore(), manifest)
        self.assertEqual(bytes_to_long(key2.counter()), iv + 1000)
        self.assertEqual(key.id_key, key2.id_key)
        self.assertEqual(key.enc_hmac_key, key2.enc_hmac_key)
        self.assertEqual(key.enc_key, key2.enc_key)
        self.assertEqual(key.chunk_seed, key2.chunk_seed)
        data = b'foo'
        self.assertEqual(hexlify(key.id_hash(data)), b'016c27cd40dc8e84f196f3b43a9424e8472897e09f6935d0d3a82fb41664bad7')
        self.assertEqual(data, key2.decrypt(key2.id_hash(data), key.encrypt(data)))


def suite():
    return unittest.TestLoader().loadTestsFromTestCase(KeyTestCase)

if __name__ == '__main__':
    unittest.main()
from binascii import hexlify, a2b_base64, b2a_base64
from getpass import getpass
import os
import msgpack
import textwrap
import hmac
from hashlib import sha256
import zlib

from attic.crypto import pbkdf2_sha256, get_random_bytes, AES, bytes_to_long, long_to_bytes, bytes_to_int, num_aes_blocks
from attic.helpers import IntegrityError, get_keys_dir, Error

PREFIX = b'\0' * 8


class UnsupportedPayloadError(Error):
    """Unsupported payload type {}. A newer version is required to access this repository.
    """

class KeyfileNotFoundError(Error):
    """No key file for repository {} found in {}.
    """


class HMAC(hmac.HMAC):
    """Workaround a bug in Python < 3.4 Where HMAC does not accept memoryviews
    """
    def update(self, msg):
        self.inner.update(msg)


def key_creator(repository, args):
    if args.encryption == 'keyfile':
        return KeyfileKey.create(repository, args)
    elif args.encryption == 'passphrase':
        return PassphraseKey.create(repository, args)
    else:
        return PlaintextKey.create(repository, args)


def key_factory(repository, manifest_data):
    if manifest_data[0] == KeyfileKey.TYPE:
        return KeyfileKey.detect(repository, manifest_data)
    elif manifest_data[0] == PassphraseKey.TYPE:
        return PassphraseKey.detect(repository, manifest_data)
    elif manifest_data[0] == PlaintextKey.TYPE:
        return PlaintextKey.detect(repository, manifest_data)
    else:
        raise UnsupportedPayloadError(manifest_data[0])


class KeyBase(object):

    def __init__(self):
        self.TYPE_STR = bytes([self.TYPE])

    def id_hash(self, data):
        """Return HMAC hash using the "id" HMAC key
        """

    def encrypt(self, data):
        pass

    def decrypt(self, id, data):
        pass


class PlaintextKey(KeyBase):
    TYPE = 0x02

    chunk_seed = 0

    @classmethod
    def create(cls, repository, args):
        print('Encryption NOT enabled.\nUse the "--encryption=passphrase|keyfile" to enable encryption.')
        return cls()

    @classmethod
    def detect(cls, repository, manifest_data):
        return cls()

    def id_hash(self, data):
        return sha256(data).digest()

    def encrypt(self, data):
        return b''.join([self.TYPE_STR, zlib.compress(data)])

    def decrypt(self, id, data):
        if data[0] != self.TYPE:
            raise IntegrityError('Invalid encryption envelope')
        data = zlib.decompress(memoryview(data)[1:])
        if id and sha256(data).digest() != id:
            raise IntegrityError('Chunk id verification failed')
        return data


class AESKeyBase(KeyBase):
    """Common base class shared by KeyfileKey and PassphraseKey

    Chunks are encrypted using 256bit AES in Counter Mode (CTR)

    Payload layout: TYPE(1) + HMAC(32) + NONCE(8) + CIPHERTEXT

    To reduce payload size only 8 bytes of the 16 bytes nonce is saved
    in the payload, the first 8 bytes are always zeros. This does not
    affect security but limits the maximum repository capacity to
    only 295 exabytes!
    """

    PAYLOAD_OVERHEAD = 1 + 32 + 8  # TYPE + HMAC + NONCE

    def id_hash(self, data):
        """Return HMAC hash using the "id" HMAC key
        """
        return HMAC(self.id_key, data, sha256).digest()

    def encrypt(self, data):
        data = zlib.compress(data)
        self.enc_cipher.reset()
        data = b''.join((self.enc_cipher.iv[8:], self.enc_cipher.encrypt(data)))
        hmac = HMAC(self.enc_hmac_key, data, sha256).digest()
        return b''.join((self.TYPE_STR, hmac, data))

    def decrypt(self, id, data):
        if data[0] != self.TYPE:
            raise IntegrityError('Invalid encryption envelope')
        hmac = memoryview(data)[1:33]
        if memoryview(HMAC(self.enc_hmac_key, memoryview(data)[33:], sha256).digest()) != hmac:
            raise IntegrityError('Encryption envelope checksum mismatch')
        self.dec_cipher.reset(iv=PREFIX + data[33:41])
        data = zlib.decompress(self.dec_cipher.decrypt(data[41:]))  # should use memoryview
        if id and HMAC(self.id_key, data, sha256).digest() != id:
            raise IntegrityError('Chunk id verification failed')
        return data

    def extract_nonce(self, payload):
        if payload[0] != self.TYPE:
            raise IntegrityError('Invalid encryption envelope')
        nonce = bytes_to_long(payload[33:41])
        return nonce

    def init_from_random_data(self, data):
        self.enc_key = data[0:32]
        self.enc_hmac_key = data[32:64]
        self.id_key = data[64:96]
        self.chunk_seed = bytes_to_int(data[96:100])
        # Convert to signed int32
        if self.chunk_seed & 0x80000000:
            self.chunk_seed = self.chunk_seed - 0xffffffff - 1

    def init_ciphers(self, enc_iv=b''):
        self.enc_cipher = AES(self.enc_key, enc_iv)
        self.dec_cipher = AES(self.enc_key)


class PassphraseKey(AESKeyBase):
    TYPE = 0x01
    iterations = 100000

    @classmethod
    def create(cls, repository, args):
        key = cls()
        passphrase = os.environ.get('ATTIC_PASSPHRASE')
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
        key.init(repository, passphrase)
        if passphrase:
            print('Remember your passphrase. Your data will be inaccessible without it.')
        return key

    @classmethod
    def detect(cls, repository, manifest_data):
        prompt = 'Enter passphrase for %s: ' % repository._location.orig
        key = cls()
        passphrase = os.environ.get('ATTIC_PASSPHRASE')
        if passphrase is None:
            passphrase = getpass(prompt)
        while True:
            key.init(repository, passphrase)
            try:
                key.decrypt(None, manifest_data)
                num_blocks = num_aes_blocks(len(manifest_data) - 41)
                key.init_ciphers(PREFIX + long_to_bytes(key.extract_nonce(manifest_data) + num_blocks))
                return key
            except IntegrityError:
                passphrase = getpass(prompt)

    def init(self, repository, passphrase):
        self.init_from_random_data(pbkdf2_sha256(passphrase.encode('utf-8'), repository.id, self.iterations, 100))
        self.init_ciphers()


class KeyfileKey(AESKeyBase):
    FILE_ID = 'ATTIC KEY'
    TYPE = 0x00

    @classmethod
    def detect(cls, repository, manifest_data):
        key = cls()
        path = cls.find_key_file(repository)
        prompt = 'Enter passphrase for key file %s: ' % path
        passphrase = os.environ.get('ATTIC_PASSPHRASE', '')
        while not key.load(path, passphrase):
            passphrase = getpass(prompt)
        num_blocks = num_aes_blocks(len(manifest_data) - 41)
        key.init_ciphers(PREFIX + long_to_bytes(key.extract_nonce(manifest_data) + num_blocks))
        return key

    @classmethod
    def find_key_file(cls, repository):
        id = hexlify(repository.id).decode('ascii')
        keys_dir = get_keys_dir()
        for name in os.listdir(keys_dir):
            filename = os.path.join(keys_dir, name)
            with open(filename, 'r') as fd:
                line = fd.readline().strip()
                if line and line.startswith(cls.FILE_ID) and line[10:] == id:
                    return filename
        raise KeyfileNotFoundError(repository._location.canonical_path(), get_keys_dir())

    def load(self, filename, passphrase):
        with open(filename, 'r') as fd:
            cdata = a2b_base64(''.join(fd.readlines()[1:]).encode('ascii'))  # .encode needed for Python 3.[0-2]
        data = self.decrypt_key_file(cdata, passphrase)
        if data:
            key = msgpack.unpackb(data)
            if key[b'version'] != 1:
                raise IntegrityError('Invalid key file header')
            self.repository_id = key[b'repository_id']
            self.enc_key = key[b'enc_key']
            self.enc_hmac_key = key[b'enc_hmac_key']
            self.id_key = key[b'id_key']
            self.chunk_seed = key[b'chunk_seed']
            self.path = filename
            return True

    def decrypt_key_file(self, data, passphrase):
        d = msgpack.unpackb(data)
        assert d[b'version'] == 1
        assert d[b'algorithm'] == b'sha256'
        key = pbkdf2_sha256(passphrase.encode('utf-8'), d[b'salt'], d[b'iterations'], 32)
        data = AES(key).decrypt(d[b'data'])
        if HMAC(key, data, sha256).digest() != d[b'hash']:
            return None
        return data

    def encrypt_key_file(self, data, passphrase):
        salt = get_random_bytes(32)
        iterations = 100000
        key = pbkdf2_sha256(passphrase.encode('utf-8'), salt, iterations, 32)
        hash = HMAC(key, data, sha256).digest()
        cdata = AES(key).encrypt(data)
        d = {
            'version': 1,
            'salt': salt,
            'iterations': iterations,
            'algorithm': 'sha256',
            'hash': hash,
            'data': cdata,
        }
        return msgpack.packb(d)

    def save(self, path, passphrase):
        key = {
            'version': 1,
            'repository_id': self.repository_id,
            'enc_key': self.enc_key,
            'enc_hmac_key': self.enc_hmac_key,
            'id_key': self.id_key,
            'chunk_seed': self.chunk_seed,
        }
        data = self.encrypt_key_file(msgpack.packb(key), passphrase)
        with open(path, 'w') as fd:
            fd.write('%s %s\n' % (self.FILE_ID, hexlify(self.repository_id).decode('ascii')))
            fd.write('\n'.join(textwrap.wrap(b2a_base64(data).decode('ascii'))))
            fd.write('\n')
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
    def create(cls, repository, args):
        filename = args.repository.to_key_filename()
        path = filename
        i = 1
        while os.path.exists(path):
            i += 1
            path = filename + '.%d' % i
        passphrase = os.environ.get('ATTIC_PASSPHRASE')
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
        key.repository_id = repository.id
        key.init_from_random_data(get_random_bytes(100))
        key.init_ciphers()
        key.save(path, passphrase)
        print('Key file "%s" created.' % key.path)
        print('Keep this file safe. Your data will be inaccessible without it.')
        return key

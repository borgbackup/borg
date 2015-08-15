from binascii import hexlify, a2b_base64, b2a_base64
import configparser
import getpass
import os
import msgpack
import textwrap
import hmac
from hashlib import sha256

from .crypto import pbkdf2_sha256, get_random_bytes, AES, bytes_to_long, long_to_bytes, bytes_to_int, num_aes_blocks
from .compress import Compressor, COMPR_BUFFER
from .helpers import IntegrityError, get_keys_dir, Error

PREFIX = b'\0' * 8


class UnsupportedPayloadError(Error):
    """Unsupported payload type {}. A newer version is required to access this repository.
    """


class KeyfileNotFoundError(Error):
    """No key file for repository {} found in {}.
    """


class RepoKeyNotFoundError(Error):
    """No key entry found in the config of repository {}.
    """


class HMAC(hmac.HMAC):
    """Workaround a bug in Python < 3.4 Where HMAC does not accept memoryviews
    """
    def update(self, msg):
        self.inner.update(msg)


def key_creator(repository, args):
    if args.encryption == 'keyfile':
        return KeyfileKey.create(repository, args)
    elif args.encryption == 'repokey':
        return RepoKey.create(repository, args)
    elif args.encryption == 'passphrase':  # deprecated, kill in 1.x
        return PassphraseKey.create(repository, args)
    else:
        return PlaintextKey.create(repository, args)


def key_factory(repository, manifest_data):
    key_type = manifest_data[0]
    if key_type == KeyfileKey.TYPE:
        return KeyfileKey.detect(repository, manifest_data)
    elif key_type == RepoKey.TYPE:
        return RepoKey.detect(repository, manifest_data)
    elif key_type == PassphraseKey.TYPE:  # deprecated, kill in 1.x
        return PassphraseKey.detect(repository, manifest_data)
    elif key_type == PlaintextKey.TYPE:
        return PlaintextKey.detect(repository, manifest_data)
    else:
        raise UnsupportedPayloadError(key_type)


class KeyBase:
    TYPE = None  # override in subclasses

    def __init__(self, repository):
        self.TYPE_STR = bytes([self.TYPE])
        self.repository = repository
        self.target = None  # key location file path / repo obj
        self.compressor = Compressor('none', buffer=COMPR_BUFFER)

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
        print('Encryption NOT enabled.\nUse the "--encryption=repokey|keyfile|passphrase" to enable encryption.')
        return cls(repository)

    @classmethod
    def detect(cls, repository, manifest_data):
        return cls(repository)

    def id_hash(self, data):
        return sha256(data).digest()

    def encrypt(self, data):
        return b''.join([self.TYPE_STR, self.compressor.compress(data)])

    def decrypt(self, id, data):
        if data[0] != self.TYPE:
            raise IntegrityError('Invalid encryption envelope')
        data = self.compressor.decompress(memoryview(data)[1:])
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
        data = self.compressor.compress(data)
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
        data = self.compressor.decompress(self.dec_cipher.decrypt(data[41:]))
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
        self.enc_cipher = AES(is_encrypt=True, key=self.enc_key, iv=enc_iv)
        self.dec_cipher = AES(is_encrypt=False, key=self.enc_key)


class Passphrase(str):
    @classmethod
    def env_passphrase(cls, default=None):
        passphrase = os.environ.get('BORG_PASSPHRASE', default)
        if passphrase is not None:
            return cls(passphrase)

    @classmethod
    def getpass(cls, prompt):
        return cls(getpass.getpass(prompt))

    @classmethod
    def new(cls, allow_empty=False):
        passphrase = cls.env_passphrase()
        if passphrase is not None:
            return passphrase
        while True:
            passphrase = cls.getpass('Enter new passphrase: ')
            if allow_empty or passphrase:
                passphrase2 = cls.getpass('Enter same passphrase again: ')
                if passphrase == passphrase2:
                    print('Remember your passphrase. Your data will be inaccessible without it.')
                    return passphrase
                else:
                    print('Passphrases do not match')
            else:
                print('Passphrase must not be blank')

    def __repr__(self):
        return '<Passphrase "***hidden***">'

    def kdf(self, salt, iterations, length):
        return pbkdf2_sha256(self.encode('utf-8'), salt, iterations, length)


class PassphraseKey(AESKeyBase):
    # This mode is DEPRECATED and will be killed at 1.0 release.
    # With this mode:
    # - you can never ever change your passphrase for existing repos.
    # - you can never ever use a different iterations count for existing repos.
    TYPE = 0x01
    iterations = 100000  # must not be changed ever!

    @classmethod
    def create(cls, repository, args):
        key = cls(repository)
        print('WARNING: "passphrase" mode is deprecated and will be removed in 1.0.')
        print('If you want something similar (but with less issues), use "repokey" mode.')
        passphrase = Passphrase.new(allow_empty=False)
        key.init(repository, passphrase)
        return key

    @classmethod
    def detect(cls, repository, manifest_data):
        prompt = 'Enter passphrase for %s: ' % repository._location.orig
        key = cls(repository)
        passphrase = Passphrase.env_passphrase()
        if passphrase is None:
            passphrase = Passphrase.getpass(prompt)
        while True:
            key.init(repository, passphrase)
            try:
                key.decrypt(None, manifest_data)
                num_blocks = num_aes_blocks(len(manifest_data) - 41)
                key.init_ciphers(PREFIX + long_to_bytes(key.extract_nonce(manifest_data) + num_blocks))
                return key
            except IntegrityError:
                passphrase = Passphrase.getpass(prompt)

    def change_passphrase(self):
        class ImmutablePassphraseError(Error):
            """The passphrase for this encryption key type can't be changed."""

        raise ImmutablePassphraseError

    def init(self, repository, passphrase):
        self.init_from_random_data(passphrase.kdf(repository.id, self.iterations, 100))
        self.init_ciphers()


class KeyfileKeyBase(AESKeyBase):
    @classmethod
    def detect(cls, repository, manifest_data):
        key = cls(repository)
        target = key.find_key()
        prompt = 'Enter passphrase for key %s: ' % target
        passphrase = Passphrase.env_passphrase(default='')
        while not key.load(target, passphrase):
            passphrase = Passphrase.getpass(prompt)
        num_blocks = num_aes_blocks(len(manifest_data) - 41)
        key.init_ciphers(PREFIX + long_to_bytes(key.extract_nonce(manifest_data) + num_blocks))
        return key

    def find_key(self):
        raise NotImplementedError

    def load(self, target, passphrase):
        raise NotImplementedError

    def _load(self, key_data, passphrase):
        cdata = a2b_base64(key_data.encode('ascii'))  # .encode needed for Python 3.[0-2]
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
            return True
        return False

    def decrypt_key_file(self, data, passphrase):
        d = msgpack.unpackb(data)
        assert d[b'version'] == 1
        assert d[b'algorithm'] == b'sha256'
        key = passphrase.kdf(d[b'salt'], d[b'iterations'], 32)
        data = AES(is_encrypt=False, key=key).decrypt(d[b'data'])
        if HMAC(key, data, sha256).digest() == d[b'hash']:
            return data

    def encrypt_key_file(self, data, passphrase):
        salt = get_random_bytes(32)
        iterations = 100000
        key = passphrase.kdf(salt, iterations, 32)
        hash = HMAC(key, data, sha256).digest()
        cdata = AES(is_encrypt=True, key=key).encrypt(data)
        d = {
            'version': 1,
            'salt': salt,
            'iterations': iterations,
            'algorithm': 'sha256',
            'hash': hash,
            'data': cdata,
        }
        return msgpack.packb(d)

    def _save(self, passphrase):
        key = {
            'version': 1,
            'repository_id': self.repository_id,
            'enc_key': self.enc_key,
            'enc_hmac_key': self.enc_hmac_key,
            'id_key': self.id_key,
            'chunk_seed': self.chunk_seed,
        }
        data = self.encrypt_key_file(msgpack.packb(key), passphrase)
        key_data = '\n'.join(textwrap.wrap(b2a_base64(data).decode('ascii')))
        return key_data

    def change_passphrase(self):
        passphrase = Passphrase.new(allow_empty=True)
        self.save(self.target, passphrase)
        print('Key updated')

    @classmethod
    def create(cls, repository, args):
        passphrase = Passphrase.new(allow_empty=True)
        key = cls(repository)
        key.repository_id = repository.id
        key.init_from_random_data(get_random_bytes(100))
        key.init_ciphers()
        target = key.get_new_target(args)
        key.save(target, passphrase)
        print('Key in "%s" created.' % target)
        print('Keep this key safe. Your data will be inaccessible without it.')
        return key

    def save(self, target, passphrase):
        raise NotImplementedError

    def get_new_target(self, args):
        raise NotImplementedError


class KeyfileKey(KeyfileKeyBase):
    TYPE = 0x00
    FILE_ID = 'BORG_KEY'

    def find_key(self):
        id = hexlify(self.repository.id).decode('ascii')
        keys_dir = get_keys_dir()
        for name in os.listdir(keys_dir):
            filename = os.path.join(keys_dir, name)
            with open(filename, 'r') as fd:
                line = fd.readline().strip()
                if line.startswith(self.FILE_ID) and line[len(self.FILE_ID)+1:] == id:
                    return filename
        raise KeyfileNotFoundError(self.repository._location.canonical_path(), get_keys_dir())

    def get_new_target(self, args):
        filename = args.repository.to_key_filename()
        path = filename
        i = 1
        while os.path.exists(path):
            i += 1
            path = filename + '.%d' % i
        return path

    def load(self, target, passphrase):
        with open(target, 'r') as fd:
            key_data = ''.join(fd.readlines()[1:])
        success = self._load(key_data, passphrase)
        if success:
            self.target = target
        return success

    def save(self, target, passphrase):
        key_data = self._save(passphrase)
        with open(target, 'w') as fd:
            fd.write('%s %s\n' % (self.FILE_ID, hexlify(self.repository_id).decode('ascii')))
            fd.write(key_data)
            fd.write('\n')
        self.target = target


class RepoKey(KeyfileKeyBase):
    TYPE = 0x03

    def find_key(self):
        loc = self.repository._location.canonical_path()
        try:
            self.repository.load_key()
            return loc
        except configparser.NoOptionError:
            raise RepoKeyNotFoundError(loc)

    def get_new_target(self, args):
        return self.repository

    def load(self, target, passphrase):
        # what we get in target is just a repo location, but we already have the repo obj:
        target = self.repository
        key_data = target.load_key()
        key_data = key_data.decode('utf-8')  # remote repo: msgpack issue #99, getting bytes
        success = self._load(key_data, passphrase)
        if success:
            self.target = target
        return success

    def save(self, target, passphrase):
        key_data = self._save(passphrase)
        key_data = key_data.encode('utf-8')  # remote repo: msgpack issue #99, giving bytes
        target.save_key(key_data)
        self.target = target

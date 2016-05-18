from binascii import hexlify, a2b_base64, b2a_base64
import configparser
import getpass
import os
import sys
import textwrap
from hmac import HMAC, compare_digest
from hashlib import sha256, pbkdf2_hmac

from .helpers import IntegrityError, get_keys_dir, Error, yes
from .logger import create_logger
logger = create_logger()

from .crypto import AES, bytes_to_long, long_to_bytes, bytes_to_int, num_aes_blocks
from .compress import Compressor, COMPR_BUFFER
import msgpack

PREFIX = b'\0' * 8


class PassphraseWrong(Error):
    """passphrase supplied in BORG_PASSPHRASE is incorrect"""


class PasswordRetriesExceeded(Error):
    """exceeded the maximum password retries"""


class UnsupportedPayloadError(Error):
    """Unsupported payload type {}. A newer version is required to access this repository."""


class KeyfileNotFoundError(Error):
    """No key file for repository {} found in {}."""


class RepoKeyNotFoundError(Error):
    """No key entry found in the config of repository {}."""


def key_creator(repository, args):
    if args.encryption == 'keyfile':
        return KeyfileKey.create(repository, args)
    elif args.encryption == 'repokey':
        return RepoKey.create(repository, args)
    else:
        return PlaintextKey.create(repository, args)


def key_factory(repository, manifest_data):
    key_type = manifest_data[0]
    if key_type == KeyfileKey.TYPE:
        return KeyfileKey.detect(repository, manifest_data)
    elif key_type == RepoKey.TYPE:
        return RepoKey.detect(repository, manifest_data)
    elif key_type == PassphraseKey.TYPE:
        # we just dispatch to repokey mode and assume the passphrase was migrated to a repokey.
        # see also comment in PassphraseKey class.
        return RepoKey.detect(repository, manifest_data)
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
        logger.info('Encryption NOT enabled.\nUse the "--encryption=repokey|keyfile" to enable encryption.')
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
        if not (data[0] == self.TYPE or
            data[0] == PassphraseKey.TYPE and isinstance(self, RepoKey)):
            raise IntegrityError('Invalid encryption envelope')
        hmac_given = memoryview(data)[1:33]
        hmac_computed = memoryview(HMAC(self.enc_hmac_key, memoryview(data)[33:], sha256).digest())
        if not compare_digest(hmac_computed, hmac_given):
            raise IntegrityError('Encryption envelope checksum mismatch')
        self.dec_cipher.reset(iv=PREFIX + data[33:41])
        data = self.compressor.decompress(self.dec_cipher.decrypt(data[41:]))
        if id:
            hmac_given = id
            hmac_computed = HMAC(self.id_key, data, sha256).digest()
            if not compare_digest(hmac_computed, hmac_given):
                raise IntegrityError('Chunk id verification failed')
        return data

    def extract_nonce(self, payload):
        if not (payload[0] == self.TYPE or
            payload[0] == PassphraseKey.TYPE and isinstance(self, RepoKey)):
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
    def verification(cls, passphrase):
        if yes('Do you want your passphrase to be displayed for verification? [yN]: ',
               env_var_override='BORG_DISPLAY_PASSPHRASE'):
            print('Your passphrase (between double-quotes): "%s"' % passphrase,
                  file=sys.stderr)
            print('Make sure the passphrase displayed above is exactly what you wanted.',
                  file=sys.stderr)
            try:
                passphrase.encode('ascii')
            except UnicodeEncodeError:
                print('Your passphrase (UTF-8 encoding in hex): %s' %
                      hexlify(passphrase.encode('utf-8')).decode('ascii'),
                      file=sys.stderr)
                print('As you have a non-ASCII passphrase, it is recommended to keep the UTF-8 encoding in hex together with the passphrase at a safe place.',
                      file=sys.stderr)

    @classmethod
    def new(cls, allow_empty=False):
        passphrase = cls.env_passphrase()
        if passphrase is not None:
            return passphrase
        for retry in range(1, 11):
            passphrase = cls.getpass('Enter new passphrase: ')
            if allow_empty or passphrase:
                passphrase2 = cls.getpass('Enter same passphrase again: ')
                if passphrase == passphrase2:
                    cls.verification(passphrase)
                    logger.info('Remember your passphrase. Your data will be inaccessible without it.')
                    return passphrase
                else:
                    print('Passphrases do not match', file=sys.stderr)
            else:
                print('Passphrase must not be blank', file=sys.stderr)
        else:
            raise PasswordRetriesExceeded

    def __repr__(self):
        return '<Passphrase "***hidden***">'

    def kdf(self, salt, iterations, length):
        return pbkdf2_hmac('sha256', self.encode('utf-8'), salt, iterations, length)


class PassphraseKey(AESKeyBase):
    # This mode was killed in borg 1.0, see: https://github.com/borgbackup/borg/issues/97
    # Reasons:
    # - you can never ever change your passphrase for existing repos.
    # - you can never ever use a different iterations count for existing repos.
    # "Killed" means:
    # - there is no automatic dispatch to this class via type byte
    # - --encryption=passphrase is an invalid argument now
    # This class is kept for a while to support migration from passphrase to repokey mode.
    TYPE = 0x01
    iterations = 100000  # must not be changed ever!

    @classmethod
    def create(cls, repository, args):
        key = cls(repository)
        logger.warning('WARNING: "passphrase" mode is unsupported since borg 1.0.')
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
        for retry in range(1, 3):
            key.init(repository, passphrase)
            try:
                key.decrypt(None, manifest_data)
                num_blocks = num_aes_blocks(len(manifest_data) - 41)
                key.init_ciphers(PREFIX + long_to_bytes(key.extract_nonce(manifest_data) + num_blocks))
                return key
            except IntegrityError:
                passphrase = Passphrase.getpass(prompt)
        else:
            raise PasswordRetriesExceeded

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
        passphrase = Passphrase.env_passphrase()
        if passphrase is None:
            passphrase = Passphrase()
            if not key.load(target, passphrase):
                for retry in range(0, 3):
                    passphrase = Passphrase.getpass(prompt)
                    if key.load(target, passphrase):
                        break
                else:
                    raise PasswordRetriesExceeded
        else:
            if not key.load(target, passphrase):
                raise PassphraseWrong
        num_blocks = num_aes_blocks(len(manifest_data) - 41)
        key.init_ciphers(PREFIX + long_to_bytes(key.extract_nonce(manifest_data) + num_blocks))
        return key

    def find_key(self):
        raise NotImplementedError

    def load(self, target, passphrase):
        raise NotImplementedError

    def _load(self, key_data, passphrase):
        cdata = a2b_base64(key_data)
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
        salt = os.urandom(32)
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
        logger.info('Key updated')

    @classmethod
    def create(cls, repository, args):
        passphrase = Passphrase.new(allow_empty=True)
        key = cls(repository)
        key.repository_id = repository.id
        key.init_from_random_data(os.urandom(100))
        key.init_ciphers()
        target = key.get_new_target(args)
        key.save(target, passphrase)
        logger.info('Key in "%s" created.' % target)
        logger.info('Keep this key safe. Your data will be inaccessible without it.')
        return key

    def save(self, target, passphrase):
        raise NotImplementedError

    def get_new_target(self, args):
        raise NotImplementedError


class KeyfileKey(KeyfileKeyBase):
    TYPE = 0x00
    FILE_ID = 'BORG_KEY'

    def find_key(self):
        file_id = self.FILE_ID.encode()
        first_line = file_id + b' ' + hexlify(self.repository.id)
        keys_dir = get_keys_dir()
        for name in os.listdir(keys_dir):
            filename = os.path.join(keys_dir, name)
            # we do the magic / id check in binary mode to avoid stumbling over
            # decoding errors if somebody has binary files in the keys dir for some reason.
            with open(filename, 'rb') as fd:
                if fd.read(len(first_line)) == first_line:
                    return filename
        raise KeyfileNotFoundError(self.repository._location.canonical_path(), get_keys_dir())

    def get_new_target(self, args):
        filename = args.location.to_key_filename()
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
            raise RepoKeyNotFoundError(loc) from None

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

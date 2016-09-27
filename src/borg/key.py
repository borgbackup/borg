import configparser
import getpass
import os
import sys
import textwrap
from binascii import a2b_base64, b2a_base64, hexlify, unhexlify
from hashlib import sha256, pbkdf2_hmac
from hmac import compare_digest

import msgpack

from .logger import create_logger
logger = create_logger()

from .constants import *  # NOQA
from .compress import Compressor, get_compressor
from .crypto import AES, bytes_to_long, long_to_bytes, bytes_to_int, num_aes_blocks, hmac_sha256
from .helpers import Chunk
from .helpers import Error, IntegrityError
from .helpers import yes
from .helpers import get_keys_dir
from .helpers import bin_to_hex
from .helpers import CompressionDecider2, CompressionSpec
from .item import Key, EncryptedKey
from .platform import SaveFile
from .nonces import NonceManager


PREFIX = b'\0' * 8


class PassphraseWrong(Error):
    """passphrase supplied in BORG_PASSPHRASE is incorrect"""


class PasswordRetriesExceeded(Error):
    """exceeded the maximum password retries"""


class UnsupportedPayloadError(Error):
    """Unsupported payload type {}. A newer version is required to access this repository."""


class KeyfileNotFoundError(Error):
    """No key file for repository {} found in {}."""


class KeyfileInvalidError(Error):
    """Invalid key file for repository {} found in {}."""


class KeyfileMismatchError(Error):
    """Mismatch between repository {} and key file {}."""


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
        self.compression_decider2 = CompressionDecider2(CompressionSpec('none'))
        self.compressor = Compressor('none')  # for decompression

    def id_hash(self, data):
        """Return HMAC hash using the "id" HMAC key
        """

    def compress(self, chunk):
        compr_args, chunk = self.compression_decider2.decide(chunk)
        compressor = Compressor(**compr_args)
        meta, data = chunk
        data = compressor.compress(data)
        return Chunk(data, **meta)

    def encrypt(self, chunk):
        pass

    def decrypt(self, id, data, decompress=True):
        pass

    def assert_id(self, id, data):
        if id:
            id_computed = self.id_hash(data)
            if not compare_digest(id_computed, id):
                raise IntegrityError('Chunk id verification failed')


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

    def encrypt(self, chunk):
        chunk = self.compress(chunk)
        return b''.join([self.TYPE_STR, chunk.data])

    def decrypt(self, id, data, decompress=True):
        if data[0] != self.TYPE:
            raise IntegrityError('Invalid encryption envelope')
        payload = memoryview(data)[1:]
        if not decompress:
            return Chunk(payload)
        data = self.compressor.decompress(payload)
        self.assert_id(id, data)
        return Chunk(data)


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
        return hmac_sha256(self.id_key, data)

    def encrypt(self, chunk):
        chunk = self.compress(chunk)
        self.nonce_manager.ensure_reservation(num_aes_blocks(len(chunk.data)))
        self.enc_cipher.reset()
        data = b''.join((self.enc_cipher.iv[8:], self.enc_cipher.encrypt(chunk.data)))
        hmac = hmac_sha256(self.enc_hmac_key, data)
        return b''.join((self.TYPE_STR, hmac, data))

    def decrypt(self, id, data, decompress=True):
        if not (data[0] == self.TYPE or
            data[0] == PassphraseKey.TYPE and isinstance(self, RepoKey)):
            raise IntegrityError('Invalid encryption envelope')
        data_view = memoryview(data)
        hmac_given = data_view[1:33]
        hmac_computed = memoryview(hmac_sha256(self.enc_hmac_key, data_view[33:]))
        if not compare_digest(hmac_computed, hmac_given):
            raise IntegrityError('Encryption envelope checksum mismatch')
        self.dec_cipher.reset(iv=PREFIX + data[33:41])
        payload = self.dec_cipher.decrypt(data_view[41:])
        if not decompress:
            return Chunk(payload)
        data = self.compressor.decompress(payload)
        self.assert_id(id, data)
        return Chunk(data)

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

    def init_ciphers(self, manifest_nonce=0):
        self.enc_cipher = AES(is_encrypt=True, key=self.enc_key, iv=manifest_nonce.to_bytes(16, byteorder='big'))
        self.nonce_manager = NonceManager(self.repository, self.enc_cipher, manifest_nonce)
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
        msg = 'Do you want your passphrase to be displayed for verification? [yN]: '
        if yes(msg, retry_msg=msg, invalid_msg='Invalid answer, try again.',
               retry=True, env_var_override='BORG_DISPLAY_PASSPHRASE'):
            print('Your passphrase (between double-quotes): "%s"' % passphrase,
                  file=sys.stderr)
            print('Make sure the passphrase displayed above is exactly what you wanted.',
                  file=sys.stderr)
            try:
                passphrase.encode('ascii')
            except UnicodeEncodeError:
                print('Your passphrase (UTF-8 encoding in hex): %s' %
                      bin_to_hex(passphrase.encode('utf-8')),
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
                key.init_ciphers(key.extract_nonce(manifest_data) + num_blocks)
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
        key.init_ciphers(key.extract_nonce(manifest_data) + num_blocks)
        return key

    def find_key(self):
        raise NotImplementedError

    def load(self, target, passphrase):
        raise NotImplementedError

    def _load(self, key_data, passphrase):
        cdata = a2b_base64(key_data)
        data = self.decrypt_key_file(cdata, passphrase)
        if data:
            data = msgpack.unpackb(data)
            key = Key(internal_dict=data)
            if key.version != 1:
                raise IntegrityError('Invalid key file header')
            self.repository_id = key.repository_id
            self.enc_key = key.enc_key
            self.enc_hmac_key = key.enc_hmac_key
            self.id_key = key.id_key
            self.chunk_seed = key.chunk_seed
            return True
        return False

    def decrypt_key_file(self, data, passphrase):
        data = msgpack.unpackb(data)
        enc_key = EncryptedKey(internal_dict=data)
        assert enc_key.version == 1
        assert enc_key.algorithm == 'sha256'
        key = passphrase.kdf(enc_key.salt, enc_key.iterations, 32)
        data = AES(is_encrypt=False, key=key).decrypt(enc_key.data)
        if hmac_sha256(key, data) == enc_key.hash:
            return data

    def encrypt_key_file(self, data, passphrase):
        salt = os.urandom(32)
        iterations = PBKDF2_ITERATIONS
        key = passphrase.kdf(salt, iterations, 32)
        hash = hmac_sha256(key, data)
        cdata = AES(is_encrypt=True, key=key).encrypt(data)
        enc_key = EncryptedKey(
            version=1,
            salt=salt,
            iterations=iterations,
            algorithm='sha256',
            hash=hash,
            data=cdata,
        )
        return msgpack.packb(enc_key.as_dict())

    def _save(self, passphrase):
        key = Key(
            version=1,
            repository_id=self.repository_id,
            enc_key=self.enc_key,
            enc_hmac_key=self.enc_hmac_key,
            id_key=self.id_key,
            chunk_seed=self.chunk_seed,
        )
        data = self.encrypt_key_file(msgpack.packb(key.as_dict()), passphrase)
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

    def sanity_check(self, filename, id):
        file_id = self.FILE_ID.encode() + b' '
        repo_id = hexlify(id)
        with open(filename, 'rb') as fd:
            # we do the magic / id check in binary mode to avoid stumbling over
            # decoding errors if somebody has binary files in the keys dir for some reason.
            if fd.read(len(file_id)) != file_id:
                raise KeyfileInvalidError(self.repository._location.canonical_path(), filename)
            if fd.read(len(repo_id)) != repo_id:
                raise KeyfileMismatchError(self.repository._location.canonical_path(), filename)
            return filename

    def find_key(self):
        id = self.repository.id
        keyfile = os.environ.get('BORG_KEY_FILE')
        if keyfile:
            return self.sanity_check(keyfile, id)
        keys_dir = get_keys_dir()
        for name in os.listdir(keys_dir):
            filename = os.path.join(keys_dir, name)
            try:
                return self.sanity_check(filename, id)
            except (KeyfileInvalidError, KeyfileMismatchError):
                pass
        raise KeyfileNotFoundError(self.repository._location.canonical_path(), get_keys_dir())

    def get_new_target(self, args):
        keyfile = os.environ.get('BORG_KEY_FILE')
        if keyfile:
            return keyfile
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
        with SaveFile(target) as fd:
            fd.write('%s %s\n' % (self.FILE_ID, bin_to_hex(self.repository_id)))
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

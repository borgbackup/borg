import configparser
import getpass
import os
import sys
import textwrap
from binascii import a2b_base64, b2a_base64, hexlify, unhexlify
from hashlib import sha256, sha512, pbkdf2_hmac
from hmac import HMAC, compare_digest

import msgpack

from .logger import create_logger
logger = create_logger()

from .constants import *  # NOQA
from .compress import Compressor, get_compressor
from .crypto import AES, bytes_to_long, bytes_to_int, num_aes_blocks, hmac_sha256, blake2b_256, hkdf_hmac_sha512
from .helpers import Chunk, StableDict
from .helpers import Error, IntegrityError
from .helpers import yes
from .helpers import get_keys_dir, get_security_dir
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


class UnsupportedManifestError(Error):
    """Unsupported manifest envelope. A newer version is required to access this repository."""


class KeyfileNotFoundError(Error):
    """No key file for repository {} found in {}."""


class KeyfileInvalidError(Error):
    """Invalid key file for repository {} found in {}."""


class KeyfileMismatchError(Error):
    """Mismatch between repository {} and key file {}."""


class RepoKeyNotFoundError(Error):
    """No key entry found in the config of repository {}."""


class TAMRequiredError(IntegrityError):
    __doc__ = textwrap.dedent("""
    Manifest is unauthenticated, but it is required for this repository.

    This either means that you are under attack, or that you modified this repository
    with a Borg version older than 1.0.9 after TAM authentication was enabled.

    In the latter case, use "borg upgrade --tam --force '{}'" to re-authenticate the manifest.
    """).strip()
    traceback = False


class TAMInvalid(IntegrityError):
    __doc__ = IntegrityError.__doc__
    traceback = False

    def __init__(self):
        # Error message becomes: "Data integrity error: Manifest authentication did not verify"
        super().__init__('Manifest authentication did not verify')


class TAMUnsupportedSuiteError(IntegrityError):
    """Could not verify manifest: Unsupported suite {!r}; a newer version is needed."""
    traceback = False


def key_creator(repository, args):
    if args.encryption == 'keyfile':
        return KeyfileKey.create(repository, args)
    elif args.encryption == 'repokey':
        return RepoKey.create(repository, args)
    elif args.encryption == 'keyfile-blake2':
        return Blake2KeyfileKey.create(repository, args)
    elif args.encryption == 'repokey-blake2':
        return Blake2RepoKey.create(repository, args)
    elif args.encryption == 'authenticated':
        return AuthenticatedKey.create(repository, args)
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
    elif key_type == Blake2KeyfileKey.TYPE:
        return Blake2KeyfileKey.detect(repository, manifest_data)
    elif key_type == Blake2RepoKey.TYPE:
        return Blake2RepoKey.detect(repository, manifest_data)
    elif key_type == AuthenticatedKey.TYPE:
        return AuthenticatedKey.detect(repository, manifest_data)
    else:
        raise UnsupportedPayloadError(key_type)


def tam_required_file(repository):
    security_dir = get_security_dir(bin_to_hex(repository.id))
    return os.path.join(security_dir, 'tam_required')


def tam_required(repository):
    file = tam_required_file(repository)
    return os.path.isfile(file)


class KeyBase:
    TYPE = None  # override in subclasses

    def __init__(self, repository):
        self.TYPE_STR = bytes([self.TYPE])
        self.repository = repository
        self.target = None  # key location file path / repo obj
        self.compression_decider2 = CompressionDecider2(CompressionSpec('none'))
        self.compressor = Compressor('none')  # for decompression
        self.tam_required = True

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
                raise IntegrityError('Chunk %s: id verification failed' % bin_to_hex(id))

    def _tam_key(self, salt, context):
        return hkdf_hmac_sha512(
            ikm=self.id_key + self.enc_key + self.enc_hmac_key,
            salt=salt,
            info=b'borg-metadata-authentication-' + context,
            output_length=64
        )

    def pack_and_authenticate_metadata(self, metadata_dict, context=b'manifest'):
        metadata_dict = StableDict(metadata_dict)
        tam = metadata_dict['tam'] = StableDict({
            'type': 'HKDF_HMAC_SHA512',
            'hmac': bytes(64),
            'salt': os.urandom(64),
        })
        packed = msgpack.packb(metadata_dict, unicode_errors='surrogateescape')
        tam_key = self._tam_key(tam['salt'], context)
        tam['hmac'] = HMAC(tam_key, packed, sha512).digest()
        return msgpack.packb(metadata_dict, unicode_errors='surrogateescape')

    def unpack_and_verify_manifest(self, data, force_tam_not_required=False):
        """Unpack msgpacked *data* and return (object, did_verify)."""
        if data.startswith(b'\xc1' * 4):
            # This is a manifest from the future, we can't read it.
            raise UnsupportedManifestError()
        tam_required = self.tam_required
        if force_tam_not_required and tam_required:
            logger.warning('Manifest authentication DISABLED.')
            tam_required = False
        data = bytearray(data)
        # Since we don't trust these bytes we use the slower Python unpacker,
        # which is assumed to have a lower probability of security issues.
        unpacked = msgpack.fallback.unpackb(data, object_hook=StableDict, unicode_errors='surrogateescape')
        if b'tam' not in unpacked:
            if tam_required:
                raise TAMRequiredError(self.repository._location.canonical_path())
            else:
                logger.debug('TAM not found and not required')
                return unpacked, False
        tam = unpacked.pop(b'tam', None)
        if not isinstance(tam, dict):
            raise TAMInvalid()
        tam_type = tam.get(b'type', b'<none>').decode('ascii', 'replace')
        if tam_type != 'HKDF_HMAC_SHA512':
            if tam_required:
                raise TAMUnsupportedSuiteError(repr(tam_type))
            else:
                logger.debug('Ignoring TAM made with unsupported suite, since TAM is not required: %r', tam_type)
                return unpacked, False
        tam_hmac = tam.get(b'hmac')
        tam_salt = tam.get(b'salt')
        if not isinstance(tam_salt, bytes) or not isinstance(tam_hmac, bytes):
            raise TAMInvalid()
        offset = data.index(tam_hmac)
        data[offset:offset + 64] = bytes(64)
        tam_key = self._tam_key(tam_salt, context=b'manifest')
        calculated_hmac = HMAC(tam_key, data, sha512).digest()
        if not compare_digest(calculated_hmac, tam_hmac):
            raise TAMInvalid()
        logger.debug('TAM-verified manifest')
        return unpacked, True


class PlaintextKey(KeyBase):
    TYPE = 0x02
    NAME = 'plaintext'

    chunk_seed = 0

    def __init__(self, repository):
        super().__init__(repository)
        self.tam_required = False

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
            id_str = bin_to_hex(id) if id is not None else '(unknown)'
            raise IntegrityError('Chunk %s: Invalid encryption envelope' % id_str)
        payload = memoryview(data)[1:]
        if not decompress:
            return Chunk(payload)
        data = self.compressor.decompress(payload)
        self.assert_id(id, data)
        return Chunk(data)

    def _tam_key(self, salt, context):
        return salt + context


def random_blake2b_256_key():
    # This might look a bit curious, but is the same construction used in the keyed mode of BLAKE2b.
    # Why limit the key to 64 bytes and pad it with 64 nulls nonetheless? The answer is that BLAKE2b
    # has a 128 byte block size, but only 64 bytes of internal state (this is also referred to as a
    # "local wide pipe" design, because the compression function transforms (block, state) => state,
    # and len(block) >= len(state), hence wide.)
    # In other words, a key longer than 64 bytes would have simply no advantage, since the function
    # has no way of propagating more than 64 bytes of entropy internally.
    # It's padded to a full block so that the key is never buffered internally by blake2b_update, ie.
    # it remains in a single memory location that can be tracked and could be erased securely, if we
    # wanted to.
    return os.urandom(64) + bytes(64)


class ID_BLAKE2b_256:
    """
    Key mix-in class for using BLAKE2b-256 for the id key.

    The id_key length must be 32 bytes.
    """

    def id_hash(self, data):
        return blake2b_256(self.id_key, data)

    def init_from_random_data(self, data=None):
        assert data is None  # PassphraseKey is the only caller using *data*
        super().init_from_random_data()
        self.enc_hmac_key = random_blake2b_256_key()
        self.id_key = random_blake2b_256_key()


class ID_HMAC_SHA_256:
    """
    Key mix-in class for using HMAC-SHA-256 for the id key.

    The id_key length must be 32 bytes.
    """

    def id_hash(self, data):
        return hmac_sha256(self.id_key, data)


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

    MAC = hmac_sha256

    def encrypt(self, chunk):
        chunk = self.compress(chunk)
        self.nonce_manager.ensure_reservation(num_aes_blocks(len(chunk.data)))
        self.enc_cipher.reset()
        data = b''.join((self.enc_cipher.iv[8:], self.enc_cipher.encrypt(chunk.data)))
        assert (self.MAC is blake2b_256 and len(self.enc_hmac_key) == 128 or
                self.MAC is hmac_sha256 and len(self.enc_hmac_key) == 32)
        hmac = self.MAC(self.enc_hmac_key, data)
        return b''.join((self.TYPE_STR, hmac, data))

    def decrypt(self, id, data, decompress=True):
        if not (data[0] == self.TYPE or
            data[0] == PassphraseKey.TYPE and isinstance(self, RepoKey)):
            id_str = bin_to_hex(id) if id is not None else '(unknown)'
            raise IntegrityError('Chunk %s: Invalid encryption envelope' % id_str)
        data_view = memoryview(data)
        hmac_given = data_view[1:33]
        assert (self.MAC is blake2b_256 and len(self.enc_hmac_key) == 128 or
                self.MAC is hmac_sha256 and len(self.enc_hmac_key) == 32)
        hmac_computed = memoryview(self.MAC(self.enc_hmac_key, data_view[33:]))
        if not compare_digest(hmac_computed, hmac_given):
            id_str = bin_to_hex(id) if id is not None else '(unknown)'
            raise IntegrityError('Chunk %s: Encryption envelope checksum mismatch' % id_str)
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
            raise IntegrityError('Manifest: Invalid encryption envelope')
        nonce = bytes_to_long(payload[33:41])
        return nonce

    def init_from_random_data(self, data=None):
        if data is None:
            data = os.urandom(100)
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
    def _env_passphrase(cls, env_var, default=None):
        passphrase = os.environ.get(env_var, default)
        if passphrase is not None:
            return cls(passphrase)

    @classmethod
    def env_passphrase(cls, default=None):
        return cls._env_passphrase('BORG_PASSPHRASE', default)

    @classmethod
    def env_new_passphrase(cls, default=None):
        return cls._env_passphrase('BORG_NEW_PASSPHRASE', default)

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
        passphrase = cls.env_new_passphrase()
        if passphrase is not None:
            return passphrase
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


class PassphraseKey(ID_HMAC_SHA_256, AESKeyBase):
    # This mode was killed in borg 1.0, see: https://github.com/borgbackup/borg/issues/97
    # Reasons:
    # - you can never ever change your passphrase for existing repos.
    # - you can never ever use a different iterations count for existing repos.
    # "Killed" means:
    # - there is no automatic dispatch to this class via type byte
    # - --encryption=passphrase is an invalid argument now
    # This class is kept for a while to support migration from passphrase to repokey mode.
    TYPE = 0x01
    NAME = 'passphrase'
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
                key._passphrase = passphrase
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
        self.tam_required = False


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
        key._passphrase = passphrase
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
            self.tam_required = key.get('tam_required', tam_required(self.repository))
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
            tam_required=self.tam_required,
        )
        data = self.encrypt_key_file(msgpack.packb(key.as_dict()), passphrase)
        key_data = '\n'.join(textwrap.wrap(b2a_base64(data).decode('ascii')))
        return key_data

    def change_passphrase(self, passphrase=None):
        if passphrase is None:
            passphrase = Passphrase.new(allow_empty=True)
        self.save(self.target, passphrase)

    @classmethod
    def create(cls, repository, args):
        passphrase = Passphrase.new(allow_empty=True)
        key = cls(repository)
        key.repository_id = repository.id
        key.init_from_random_data()
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


class KeyfileKey(ID_HMAC_SHA_256, KeyfileKeyBase):
    TYPE = 0x00
    NAME = 'key file'
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


class RepoKey(ID_HMAC_SHA_256, KeyfileKeyBase):
    TYPE = 0x03
    NAME = 'repokey'

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


class Blake2KeyfileKey(ID_BLAKE2b_256, KeyfileKey):
    TYPE = 0x04
    NAME = 'key file BLAKE2b'
    FILE_ID = 'BORG_KEY'
    MAC = blake2b_256


class Blake2RepoKey(ID_BLAKE2b_256, RepoKey):
    TYPE = 0x05
    NAME = 'repokey BLAKE2b'
    MAC = blake2b_256


class AuthenticatedKey(ID_BLAKE2b_256, RepoKey):
    TYPE = 0x06
    NAME = 'authenticated BLAKE2b'

    def encrypt(self, chunk):
        chunk = self.compress(chunk)
        return b''.join([self.TYPE_STR, chunk.data])

    def decrypt(self, id, data, decompress=True):
        if data[0] != self.TYPE:
            raise IntegrityError('Chunk %s: Invalid envelope' % bin_to_hex(id))
        payload = memoryview(data)[1:]
        if not decompress:
            return Chunk(payload)
        data = self.compressor.decompress(payload)
        self.assert_id(id, data)
        return Chunk(data)

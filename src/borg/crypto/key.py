import configparser
import getpass
import os
import shlex
import sys
import textwrap
import subprocess
from binascii import a2b_base64, b2a_base64, hexlify
from hashlib import sha256, sha512, pbkdf2_hmac
from hmac import HMAC, compare_digest

from borg.logger import create_logger

logger = create_logger()

from ..constants import *  # NOQA
from ..compress import Compressor
from ..helpers import StableDict
from ..helpers import Error, IntegrityError
from ..helpers import yes
from ..helpers import get_keys_dir, get_security_dir
from ..helpers import get_limited_unpacker
from ..helpers import bin_to_hex
from ..helpers import prepare_subprocess_env
from ..helpers import msgpack
from ..item import Key, EncryptedKey
from ..platform import SaveFile
from .nonces import NonceManager
from .low_level import AES, bytes_to_long, bytes_to_int, num_aes_blocks, hmac_sha256, blake2b_256, hkdf_hmac_sha512

PREFIX = b'\0' * 8


class NoPassphraseFailure(Error):
    """can not acquire a passphrase: {}"""


class PassphraseWrong(Error):
    """passphrase supplied in BORG_PASSPHRASE, by BORG_PASSCOMMAND or via BORG_PASSPHRASE_FD is incorrect."""


class PasscommandFailure(Error):
    """passcommand supplied in BORG_PASSCOMMAND failed: {}"""


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


class KeyBlobStorage:
    NO_STORAGE = 'no_storage'
    KEYFILE = 'keyfile'
    REPO = 'repository'


def key_creator(repository, args):
    for key in AVAILABLE_KEY_TYPES:
        if key.ARG_NAME == args.encryption:
            assert key.ARG_NAME is not None
            return key.create(repository, args)
    else:
        raise ValueError('Invalid encryption mode "%s"' % args.encryption)


def key_argument_names():
    return [key.ARG_NAME for key in AVAILABLE_KEY_TYPES if key.ARG_NAME]


def identify_key(manifest_data):
    key_type = manifest_data[0]
    if key_type == PassphraseKey.TYPE:
        # we just dispatch to repokey mode and assume the passphrase was migrated to a repokey.
        # see also comment in PassphraseKey class.
        return RepoKey

    for key in AVAILABLE_KEY_TYPES:
        if key.TYPE == key_type:
            return key
    else:
        raise UnsupportedPayloadError(key_type)


def key_factory(repository, manifest_data):
    return identify_key(manifest_data).detect(repository, manifest_data)


def tam_required_file(repository):
    security_dir = get_security_dir(bin_to_hex(repository.id))
    return os.path.join(security_dir, 'tam_required')


def tam_required(repository):
    file = tam_required_file(repository)
    return os.path.isfile(file)


class KeyBase:
    # Numeric key type ID, must fit in one byte.
    TYPE = None  # override in subclasses

    # Human-readable name
    NAME = 'UNDEFINED'

    # Name used in command line / API (e.g. borg init --encryption=...)
    ARG_NAME = 'UNDEFINED'

    # Storage type (no key blob storage / keyfile / repo)
    STORAGE = KeyBlobStorage.NO_STORAGE

    # Seed for the buzhash chunker (borg.algorithms.chunker.Chunker)
    # type: int
    chunk_seed = None

    # Whether this *particular instance* is encrypted from a practical point of view,
    # i.e. when it's using encryption with a empty passphrase, then
    # that may be *technically* called encryption, but for all intents and purposes
    # that's as good as not encrypting in the first place, and this member should be False.
    #
    # The empty passphrase is also special because Borg tries it first when no passphrase
    # was supplied, and if an empty passphrase works, then Borg won't ask for one.
    logically_encrypted = False

    def __init__(self, repository):
        self.TYPE_STR = bytes([self.TYPE])
        self.repository = repository
        self.target = None  # key location file path / repo obj
        # Some commands write new chunks (e.g. rename) but don't take a --compression argument. This duplicates
        # the default used by those commands who do take a --compression argument.
        self.compressor = Compressor('lz4')
        self.decompress = self.compressor.decompress
        self.tam_required = True

    def id_hash(self, data):
        """Return HMAC hash using the "id" HMAC key
        """

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
        unpacker = get_limited_unpacker('manifest')
        unpacker.feed(data)
        unpacked = unpacker.unpack()
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
    ARG_NAME = 'none'
    STORAGE = KeyBlobStorage.NO_STORAGE

    chunk_seed = 0
    logically_encrypted = False

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
        data = self.compressor.compress(chunk)
        return b''.join([self.TYPE_STR, data])

    def decrypt(self, id, data, decompress=True):
        if data[0] != self.TYPE:
            id_str = bin_to_hex(id) if id is not None else '(unknown)'
            raise IntegrityError('Chunk %s: Invalid encryption envelope' % id_str)
        payload = memoryview(data)[1:]
        if not decompress:
            return payload
        data = self.decompress(payload)
        self.assert_id(id, data)
        return data

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
    """
    Common base class shared by KeyfileKey and PassphraseKey

    Chunks are encrypted using 256bit AES in Counter Mode (CTR)

    Payload layout: TYPE(1) + HMAC(32) + NONCE(8) + CIPHERTEXT

    To reduce payload size only 8 bytes of the 16 bytes nonce is saved
    in the payload, the first 8 bytes are always zeros. This does not
    affect security but limits the maximum repository capacity to
    only 295 exabytes!
    """

    PAYLOAD_OVERHEAD = 1 + 32 + 8  # TYPE + HMAC + NONCE

    MAC = hmac_sha256

    logically_encrypted = True

    def encrypt(self, chunk):
        data = self.compressor.compress(chunk)
        self.nonce_manager.ensure_reservation(num_aes_blocks(len(data)))
        self.enc_cipher.reset()
        data = b''.join((self.enc_cipher.iv[8:], self.enc_cipher.encrypt(data)))
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
            return payload
        data = self.decompress(payload)
        self.assert_id(id, data)
        return data

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
        passphrase = cls._env_passphrase('BORG_PASSPHRASE', default)
        if passphrase is not None:
            return passphrase
        passphrase = cls.env_passcommand()
        if passphrase is not None:
            return passphrase
        passphrase = cls.fd_passphrase()
        if passphrase is not None:
            return passphrase

    @classmethod
    def env_passcommand(cls, default=None):
        passcommand = os.environ.get('BORG_PASSCOMMAND', None)
        if passcommand is not None:
            # passcommand is a system command (not inside pyinstaller env)
            env = prepare_subprocess_env(system=True)
            try:
                passphrase = subprocess.check_output(shlex.split(passcommand), universal_newlines=True, env=env)
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                raise PasscommandFailure(e)
            return cls(passphrase.rstrip('\n'))

    @classmethod
    def fd_passphrase(cls):
        try:
            fd = int(os.environ.get('BORG_PASSPHRASE_FD'))
        except (ValueError, TypeError):
            return None
        with os.fdopen(fd, mode='r') as f:
            passphrase = f.read()
        return cls(passphrase.rstrip('\n'))

    @classmethod
    def env_new_passphrase(cls, default=None):
        return cls._env_passphrase('BORG_NEW_PASSPHRASE', default)

    @classmethod
    def getpass(cls, prompt):
        try:
            pw = getpass.getpass(prompt)
        except EOFError:
            if prompt:
                print()  # avoid err msg appearing right of prompt
            msg = []
            for env_var in 'BORG_PASSPHRASE', 'BORG_PASSCOMMAND':
                env_var_set = os.environ.get(env_var) is not None
                msg.append('%s is %s.' % (env_var, 'set' if env_var_set else 'not set'))
            msg.append('Interactive password query failed.')
            raise NoPassphraseFailure(' '.join(msg)) from None
        else:
            return cls(pw)

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
    ARG_NAME = None
    STORAGE = KeyBlobStorage.NO_STORAGE

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
        prompt = 'Enter passphrase for %s: ' % repository._location.canonical_path()
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
        unpacker = get_limited_unpacker('key')
        unpacker.feed(data)
        data = unpacker.unpack()
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
    ARG_NAME = 'keyfile'
    STORAGE = KeyBlobStorage.KEYFILE

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
            return self.sanity_check(os.path.abspath(keyfile), id)
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
            return os.path.abspath(keyfile)
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
    ARG_NAME = 'repokey'
    STORAGE = KeyBlobStorage.REPO

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
        # While the repository is encrypted, we consider a repokey repository with a blank
        # passphrase an unencrypted repository.
        self.logically_encrypted = passphrase != ''

        # what we get in target is just a repo location, but we already have the repo obj:
        target = self.repository
        key_data = target.load_key()
        key_data = key_data.decode('utf-8')  # remote repo: msgpack issue #99, getting bytes
        success = self._load(key_data, passphrase)
        if success:
            self.target = target
        return success

    def save(self, target, passphrase):
        self.logically_encrypted = passphrase != ''
        key_data = self._save(passphrase)
        key_data = key_data.encode('utf-8')  # remote repo: msgpack issue #99, giving bytes
        target.save_key(key_data)
        self.target = target


class Blake2KeyfileKey(ID_BLAKE2b_256, KeyfileKey):
    TYPE = 0x04
    NAME = 'key file BLAKE2b'
    ARG_NAME = 'keyfile-blake2'
    STORAGE = KeyBlobStorage.KEYFILE

    FILE_ID = 'BORG_KEY'
    MAC = blake2b_256


class Blake2RepoKey(ID_BLAKE2b_256, RepoKey):
    TYPE = 0x05
    NAME = 'repokey BLAKE2b'
    ARG_NAME = 'repokey-blake2'
    STORAGE = KeyBlobStorage.REPO

    MAC = blake2b_256


class AuthenticatedKeyBase(RepoKey):
    STORAGE = KeyBlobStorage.REPO

    # It's only authenticated, not encrypted.
    logically_encrypted = False

    def load(self, target, passphrase):
        success = super().load(target, passphrase)
        self.logically_encrypted = False
        return success

    def save(self, target, passphrase):
        super().save(target, passphrase)
        self.logically_encrypted = False

    def extract_nonce(self, payload):
        # This is called during set-up of the AES ciphers we're not actually using for this
        # key. Therefore the return value of this method doesn't matter; it's just around
        # to not have it crash should key identification be run against a very small chunk
        # by "borg check" when the manifest is lost. (The manifest is always large enough
        # to have the original method read some garbage from bytes 33-41). (Also, the return
        # value must be larger than the 41 byte bloat of the original format).
        if payload[0] != self.TYPE:
            raise IntegrityError('Manifest: Invalid encryption envelope')
        return 42

    def encrypt(self, chunk):
        data = self.compressor.compress(chunk)
        return b''.join([self.TYPE_STR, data])

    def decrypt(self, id, data, decompress=True):
        if data[0] != self.TYPE:
            raise IntegrityError('Chunk %s: Invalid envelope' % bin_to_hex(id))
        payload = memoryview(data)[1:]
        if not decompress:
            return payload
        data = self.decompress(payload)
        self.assert_id(id, data)
        return data


class AuthenticatedKey(AuthenticatedKeyBase):
    TYPE = 0x07
    NAME = 'authenticated'
    ARG_NAME = 'authenticated'


class Blake2AuthenticatedKey(ID_BLAKE2b_256, AuthenticatedKeyBase):
    TYPE = 0x06
    NAME = 'authenticated BLAKE2b'
    ARG_NAME = 'authenticated-blake2'


AVAILABLE_KEY_TYPES = (
    PlaintextKey,
    PassphraseKey,
    KeyfileKey, RepoKey, AuthenticatedKey,
    Blake2KeyfileKey, Blake2RepoKey, Blake2AuthenticatedKey,
)

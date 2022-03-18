import configparser
import hmac
import os
import textwrap
from binascii import a2b_base64, b2a_base64, hexlify
from hashlib import sha256

from ..logger import create_logger

logger = create_logger()

from ..constants import *  # NOQA
from ..compress import Compressor
from ..helpers import StableDict
from ..helpers import Error, IntegrityError
from ..helpers import get_keys_dir, get_security_dir
from ..helpers import get_limited_unpacker
from ..helpers import bin_to_hex
from ..helpers.passphrase import Passphrase, PasswordRetriesExceeded, PassphraseWrong
from ..helpers import msgpack
from ..item import Key, EncryptedKey
from ..platform import SaveFile

from .nonces import NonceManager
from .low_level import AES, bytes_to_long, long_to_bytes, bytes_to_int, num_cipher_blocks, hmac_sha256, blake2b_256, hkdf_hmac_sha512
from .low_level import AES256_CTR_HMAC_SHA256, AES256_CTR_BLAKE2b


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
    if key_type == KeyType.PASSPHRASE:  # legacy, see comment in KeyType class.
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
    # set of key type IDs the class can handle as input
    TYPES_ACCEPTABLE = None  # override in subclasses

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
        raise NotImplementedError

    def encrypt(self, chunk):
        pass

    def decrypt(self, id, data, decompress=True):
        pass

    def assert_id(self, id, data):
        if id:
            id_computed = self.id_hash(data)
            if not hmac.compare_digest(id_computed, id):
                raise IntegrityError('Chunk %s: id verification failed' % bin_to_hex(id))

    def assert_type(self, type_byte, id=None):
        if type_byte not in self.TYPES_ACCEPTABLE:
            id_str = bin_to_hex(id) if id is not None else '(unknown)'
            raise IntegrityError(f'Chunk {id_str}: Invalid encryption envelope')

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
        packed = msgpack.packb(metadata_dict)
        tam_key = self._tam_key(tam['salt'], context)
        tam['hmac'] = hmac.digest(tam_key, packed, 'sha512')
        return msgpack.packb(metadata_dict)

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
        calculated_hmac = hmac.digest(tam_key, data, 'sha512')
        if not hmac.compare_digest(calculated_hmac, tam_hmac):
            raise TAMInvalid()
        logger.debug('TAM-verified manifest')
        return unpacked, True


class PlaintextKey(KeyBase):
    TYPE = KeyType.PLAINTEXT
    TYPES_ACCEPTABLE = {TYPE}
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
        self.assert_type(data[0], id)
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

    def init_from_random_data(self):
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
    Chunks are encrypted using 256bit AES in Counter Mode (CTR)

    Payload layout: TYPE(1) + HMAC(32) + NONCE(8) + CIPHERTEXT

    To reduce payload size only 8 bytes of the 16 bytes nonce is saved
    in the payload, the first 8 bytes are always zeros. This does not
    affect security but limits the maximum repository capacity to
    only 295 exabytes!
    """

    PAYLOAD_OVERHEAD = 1 + 32 + 8  # TYPE + HMAC + NONCE

    CIPHERSUITE = AES256_CTR_HMAC_SHA256

    logically_encrypted = True

    def encrypt(self, chunk):
        data = self.compressor.compress(chunk)
        next_iv = self.nonce_manager.ensure_reservation(self.cipher.next_iv(),
                                                        self.cipher.block_count(len(data)))
        return self.cipher.encrypt(data, header=self.TYPE_STR, iv=next_iv)

    def decrypt(self, id, data, decompress=True):
        self.assert_type(data[0], id)
        try:
            payload = self.cipher.decrypt(data)
        except IntegrityError as e:
            raise IntegrityError(f"Chunk {bin_to_hex(id)}: Could not decrypt [{str(e)}]")
        if not decompress:
            return payload
        data = self.decompress(payload)
        self.assert_id(id, data)
        return data

    def init_from_random_data(self):
        data = os.urandom(100)
        self.enc_key = data[0:32]
        self.enc_hmac_key = data[32:64]
        self.id_key = data[64:96]
        self.chunk_seed = bytes_to_int(data[96:100])
        # Convert to signed int32
        if self.chunk_seed & 0x80000000:
            self.chunk_seed = self.chunk_seed - 0xffffffff - 1

    def init_ciphers(self, manifest_data=None):
        self.cipher = self.CIPHERSUITE(mac_key=self.enc_hmac_key, enc_key=self.enc_key, header_len=1, aad_offset=1)
        if manifest_data is None:
            nonce = 0
        else:
            self.assert_type(manifest_data[0])
            # manifest_blocks is a safe upper bound on the amount of cipher blocks needed
            # to encrypt the manifest. depending on the ciphersuite and overhead, it might
            # be a bit too high, but that does not matter.
            manifest_blocks = num_cipher_blocks(len(manifest_data))
            nonce = self.cipher.extract_iv(manifest_data) + manifest_blocks
        self.cipher.set_iv(nonce)
        self.nonce_manager = NonceManager(self.repository, nonce)


class FlexiKeyBase(AESKeyBase):
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
        key.init_ciphers(manifest_data)
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
        data = AES(key, b'\0'*16).decrypt(enc_key.data)
        if hmac_sha256(key, data) == enc_key.hash:
            return data

    def encrypt_key_file(self, data, passphrase):
        salt = os.urandom(32)
        iterations = PBKDF2_ITERATIONS
        key = passphrase.kdf(salt, iterations, 32)
        hash = hmac_sha256(key, data)
        cdata = AES(key, b'\0'*16).encrypt(data)
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
        key.save(target, passphrase, create=True)
        logger.info('Key in "%s" created.' % target)
        logger.info('Keep this key safe. Your data will be inaccessible without it.')
        return key

    def save(self, target, passphrase, create=False):
        raise NotImplementedError

    def get_new_target(self, args):
        raise NotImplementedError


class FlexiKey(ID_HMAC_SHA_256, FlexiKeyBase):
    TYPES_ACCEPTABLE = {KeyType.KEYFILE, KeyType.REPO, KeyType.PASSPHRASE}

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
        if self.STORAGE == KeyBlobStorage.KEYFILE:
            keyfile = self._find_key_file_from_environment()
            if keyfile is not None:
                return self.sanity_check(keyfile, self.repository.id)
            keyfile = self._find_key_in_keys_dir()
            if keyfile is not None:
                return keyfile
            raise KeyfileNotFoundError(self.repository._location.canonical_path(), get_keys_dir())
        elif self.STORAGE == KeyBlobStorage.REPO:
            loc = self.repository._location.canonical_path()
            try:
                self.repository.load_key()
                return loc
            except configparser.NoOptionError:
                raise RepoKeyNotFoundError(loc) from None
        else:
            raise TypeError('Unsupported borg key storage type')

    def get_existing_or_new_target(self, args):
        keyfile = self._find_key_file_from_environment()
        if keyfile is not None:
            return keyfile
        keyfile = self._find_key_in_keys_dir()
        if keyfile is not None:
            return keyfile
        return self._get_new_target_in_keys_dir(args)

    def _find_key_in_keys_dir(self):
        id = self.repository.id
        keys_dir = get_keys_dir()
        for name in os.listdir(keys_dir):
            filename = os.path.join(keys_dir, name)
            try:
                return self.sanity_check(filename, id)
            except (KeyfileInvalidError, KeyfileMismatchError):
                pass

    def get_new_target(self, args):
        if self.STORAGE == KeyBlobStorage.KEYFILE:
            keyfile = self._find_key_file_from_environment()
            if keyfile is not None:
                return keyfile
            return self._get_new_target_in_keys_dir(args)
        elif self.STORAGE == KeyBlobStorage.REPO:
            return self.repository
        else:
            raise TypeError('Unsupported borg key storage type')

    def _find_key_file_from_environment(self):
        keyfile = os.environ.get('BORG_KEY_FILE')
        if keyfile:
            return os.path.abspath(keyfile)

    def _get_new_target_in_keys_dir(self, args):
        filename = args.location.to_key_filename()
        path = filename
        i = 1
        while os.path.exists(path):
            i += 1
            path = filename + '.%d' % i
        return path

    def load(self, target, passphrase):
        if self.STORAGE == KeyBlobStorage.KEYFILE:
            with open(target) as fd:
                key_data = ''.join(fd.readlines()[1:])
        elif self.STORAGE == KeyBlobStorage.REPO:
            # While the repository is encrypted, we consider a repokey repository with a blank
            # passphrase an unencrypted repository.
            self.logically_encrypted = passphrase != ''

            # what we get in target is just a repo location, but we already have the repo obj:
            target = self.repository
            key_data = target.load_key()
            key_data = key_data.decode('utf-8')  # remote repo: msgpack issue #99, getting bytes
        else:
            raise TypeError('Unsupported borg key storage type')
        success = self._load(key_data, passphrase)
        if success:
            self.target = target
        return success

    def save(self, target, passphrase, create=False):
        key_data = self._save(passphrase)
        if self.STORAGE == KeyBlobStorage.KEYFILE:
            if create and os.path.isfile(target):
                # if a new keyfile key repository is created, ensure that an existing keyfile of another
                # keyfile key repo is not accidentally overwritten by careless use of the BORG_KEY_FILE env var.
                # see issue #6036
                raise Error('Aborting because key in "%s" already exists.' % target)
            with SaveFile(target) as fd:
                fd.write(f'{self.FILE_ID} {bin_to_hex(self.repository_id)}\n')
                fd.write(key_data)
                fd.write('\n')
        elif self.STORAGE == KeyBlobStorage.REPO:
            self.logically_encrypted = passphrase != ''
            key_data = key_data.encode('utf-8')  # remote repo: msgpack issue #99, giving bytes
            target.save_key(key_data)
        else:
            raise TypeError('Unsupported borg key storage type')
        self.target = target

    def remove(self, target):
        if self.STORAGE == KeyBlobStorage.KEYFILE:
            os.remove(target)
        elif self.STORAGE == KeyBlobStorage.REPO:
            target.save_key(b'')  # save empty key (no new api at remote repo necessary)
        else:
            raise TypeError('Unsupported borg key storage type')


class KeyfileKey(FlexiKey):
    TYPE = KeyType.KEYFILE
    NAME = 'key file'
    ARG_NAME = 'keyfile'
    STORAGE = KeyBlobStorage.KEYFILE


class RepoKey(FlexiKey):
    TYPE = KeyType.REPO
    NAME = 'repokey'
    ARG_NAME = 'repokey'
    STORAGE = KeyBlobStorage.REPO


class Blake2FlexiKey(ID_BLAKE2b_256, FlexiKey):
    TYPES_ACCEPTABLE = {KeyType.BLAKE2KEYFILE, KeyType.BLAKE2REPO}
    CIPHERSUITE = AES256_CTR_BLAKE2b


class Blake2KeyfileKey(Blake2FlexiKey):
    TYPE = KeyType.BLAKE2KEYFILE
    NAME = 'key file BLAKE2b'
    ARG_NAME = 'keyfile-blake2'
    STORAGE = KeyBlobStorage.KEYFILE


class Blake2RepoKey(Blake2FlexiKey):
    TYPE = KeyType.BLAKE2REPO
    NAME = 'repokey BLAKE2b'
    ARG_NAME = 'repokey-blake2'
    STORAGE = KeyBlobStorage.REPO


class AuthenticatedKeyBase(FlexiKey):
    STORAGE = KeyBlobStorage.REPO

    # It's only authenticated, not encrypted.
    logically_encrypted = False

    def load(self, target, passphrase):
        success = super().load(target, passphrase)
        self.logically_encrypted = False
        return success

    def save(self, target, passphrase, create=False):
        super().save(target, passphrase, create=create)
        self.logically_encrypted = False

    def init_ciphers(self, manifest_data=None):
        if manifest_data is not None:
            self.assert_type(manifest_data[0])

    def encrypt(self, chunk):
        data = self.compressor.compress(chunk)
        return b''.join([self.TYPE_STR, data])

    def decrypt(self, id, data, decompress=True):
        self.assert_type(data[0], id)
        payload = memoryview(data)[1:]
        if not decompress:
            return payload
        data = self.decompress(payload)
        self.assert_id(id, data)
        return data


class AuthenticatedKey(AuthenticatedKeyBase):
    TYPE = KeyType.AUTHENTICATED
    TYPES_ACCEPTABLE = {TYPE}
    NAME = 'authenticated'
    ARG_NAME = 'authenticated'


class Blake2AuthenticatedKey(ID_BLAKE2b_256, AuthenticatedKeyBase):
    TYPE = KeyType.BLAKE2AUTHENTICATED
    TYPES_ACCEPTABLE = {TYPE}
    NAME = 'authenticated BLAKE2b'
    ARG_NAME = 'authenticated-blake2'


AVAILABLE_KEY_TYPES = (
    PlaintextKey,
    KeyfileKey, RepoKey, AuthenticatedKey,
    Blake2KeyfileKey, Blake2RepoKey, Blake2AuthenticatedKey,
)

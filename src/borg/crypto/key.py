import binascii
import hmac
import os
import textwrap
from hashlib import sha256, pbkdf2_hmac
from pathlib import Path
from typing import Literal, ClassVar
from collections.abc import Callable

from ..logger import create_logger

logger = create_logger()

import argon2.low_level

from ..constants import *  # NOQA
from ..helpers import StableDict
from ..helpers import Error, IntegrityError
from ..helpers import get_keys_dir
from ..helpers import get_limited_unpacker
from ..helpers import bin_to_hex
from ..helpers.passphrase import Passphrase, PasswordRetriesExceeded, PassphraseWrong
from ..helpers import msgpack
from ..helpers import workarounds
from ..item import Key, EncryptedKey
from ..manifest import Manifest
from ..platform import SaveFile
from ..repoobj import RepoObj


from .low_level import AES, bytes_to_int, num_cipher_blocks, hmac_sha256, blake2b_256
from .low_level import AES256_CTR_HMAC_SHA256, AES256_CTR_BLAKE2b, AES256_OCB, CHACHA20_POLY1305
from . import low_level

# workaround for lost passphrase or key in "authenticated" or "authenticated-blake2" mode
AUTHENTICATED_NO_KEY = "authenticated_no_key" in workarounds


class UnsupportedPayloadError(Error):
    """Unsupported payload type {}. A newer version is required to access this repository."""

    exit_mcode = 48


class UnsupportedManifestError(Error):
    """Unsupported manifest envelope. A newer version is required to access this repository."""

    exit_mcode = 27


class KeyfileNotFoundError(Error):
    """No key file for repository {} found in {}."""

    exit_mcode = 42


class KeyfileInvalidError(Error):
    """Invalid key data for repository {} found in {}."""

    exit_mcode = 40


class KeyfileMismatchError(Error):
    """Mismatch between repository {} and key file {}."""

    exit_mcode = 41


class RepoKeyNotFoundError(Error):
    """No key entry found in the config of repository {}."""

    exit_mcode = 44


class UnsupportedKeyFormatError(Error):
    """Your borg key is stored in an unsupported format. Try using a newer version of borg."""

    exit_mcode = 49


def key_creator(repository, args, *, other_key=None):
    for key in AVAILABLE_KEY_TYPES:
        if key.ARG_NAME == args.encryption:
            assert key.ARG_NAME is not None
            return key.create(repository, args, other_key=other_key)
    else:
        raise ValueError('Invalid encryption mode "%s"' % args.encryption)


def key_argument_names():
    return [key.ARG_NAME for key in AVAILABLE_KEY_TYPES if key.ARG_NAME]


def identify_key(manifest_data):
    key_type = manifest_data[0]
    if key_type == KeyType.PASSPHRASE:  # legacy, see comment in KeyType class.
        return RepoKey

    for key in LEGACY_KEY_TYPES + AVAILABLE_KEY_TYPES:
        if key.TYPE == key_type:
            return key
    else:
        raise UnsupportedPayloadError(key_type)


def key_factory(repository, manifest_chunk, *, other=False, ro_cls=RepoObj):
    manifest_data = ro_cls.extract_crypted_data(manifest_chunk)
    assert manifest_data, "manifest data must not be zero bytes long"
    return identify_key(manifest_data).detect(repository, manifest_data, other=other)


def uses_same_chunker_secret(other_key, key):
    """is the chunker secret the same?"""
    # avoid breaking the deduplication by a different chunker secret
    same_chunker_secret = other_key.chunk_seed == key.chunk_seed
    return same_chunker_secret


def uses_same_id_hash(other_key, key):
    """other_key -> key upgrade: is the id hash the same?"""
    # avoid breaking the deduplication by changing the id hash
    old_sha256_ids = (PlaintextKey,)
    new_sha256_ids = (PlaintextKey,)
    old_hmac_sha256_ids = (RepoKey, KeyfileKey, AuthenticatedKey)
    new_hmac_sha256_ids = (AESOCBRepoKey, AESOCBKeyfileKey, CHPORepoKey, CHPOKeyfileKey, AuthenticatedKey)
    old_blake2_ids = (Blake2RepoKey, Blake2KeyfileKey, Blake2AuthenticatedKey)
    new_blake2_ids = (
        Blake2AESOCBRepoKey,
        Blake2AESOCBKeyfileKey,
        Blake2CHPORepoKey,
        Blake2CHPOKeyfileKey,
        Blake2AuthenticatedKey,
    )
    same_ids = (
        isinstance(other_key, old_hmac_sha256_ids + new_hmac_sha256_ids)
        and isinstance(key, new_hmac_sha256_ids)
        or isinstance(other_key, old_blake2_ids + new_blake2_ids)
        and isinstance(key, new_blake2_ids)
        or isinstance(other_key, old_sha256_ids + new_sha256_ids)
        and isinstance(key, new_sha256_ids)
    )
    return same_ids


class KeyBase:
    # Numeric key type ID, must fit in one byte.
    TYPE: int = None  # override in subclasses
    # set of key type IDs the class can handle as input
    TYPES_ACCEPTABLE: set[int] = None  # override in subclasses

    # Human-readable name
    NAME = "UNDEFINED"

    # Name used in command line / API (e.g. borg init --encryption=...)
    ARG_NAME = "UNDEFINED"

    # Storage type (no key blob storage / keyfile / repo)
    STORAGE: ClassVar[str] = KeyBlobStorage.NO_STORAGE

    # Seed for the buzhash chunker (borg.algorithms.chunker.Chunker)
    # type is int
    chunk_seed: int = None

    # crypt_key dummy, needs to be overwritten by subclass
    crypt_key: bytes = None

    # id_key dummy, needs to be overwritten by subclass
    id_key: bytes = None

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
        self.copy_crypt_key = False

    def id_hash(self, data):
        """Return HMAC hash using the "id" HMAC key"""
        raise NotImplementedError

    def encrypt(self, id, data):
        pass

    def decrypt(self, id, data):
        pass

    def assert_id(self, id, data):
        if id and id != Manifest.MANIFEST_ID:
            id_computed = self.id_hash(data)
            if not hmac.compare_digest(id_computed, id):
                raise IntegrityError("Chunk %s: id verification failed" % bin_to_hex(id))

    def assert_type(self, type_byte, id=None):
        if type_byte not in self.TYPES_ACCEPTABLE:
            id_str = bin_to_hex(id) if id is not None else "(unknown)"
            raise IntegrityError(f"Chunk {id_str}: Invalid encryption envelope")

    def derive_key(self, *, salt, domain, size, from_id_key=False):
        """
        create a new crypto key (<size> bytes long) from existing key material, a given salt and domain.
        from_id_key == False: derive from self.crypt_key (default)
        from_id_key == True: derive from self.id_key (note: related repos have same ID key)
        """
        from_key = self.id_key if from_id_key else self.crypt_key
        assert isinstance(from_key, bytes)
        assert isinstance(salt, bytes)
        assert isinstance(domain, bytes)
        assert size <= 32  # sha256 gives us 32 bytes
        # Because crypt_key is already a PRK, we do not need KDF security here, PRF security is good enough.
        # See https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf section 4 "one-step KDF".
        return sha256(from_key + salt + domain).digest()[:size]

    def pack_metadata(self, metadata_dict):
        metadata_dict = StableDict(metadata_dict)
        return msgpack.packb(metadata_dict)

    def unpack_manifest(self, data):
        """Unpack msgpacked *data* and return manifest."""
        if data.startswith(b"\xc1" * 4):
            # This is a manifest from the future, we can't read it.
            raise UnsupportedManifestError()
        data = bytearray(data)
        unpacker = get_limited_unpacker("manifest")
        unpacker.feed(data)
        unpacked = unpacker.unpack()
        unpacked.pop("tam", None)  # legacy
        return unpacked

    def unpack_archive(self, data):
        """Unpack msgpacked *data* and return archive metadata dict."""
        data = bytearray(data)
        unpacker = get_limited_unpacker("archive")
        unpacker.feed(data)
        unpacked = unpacker.unpack()
        unpacked.pop("tam", None)  # legacy
        return unpacked


class PlaintextKey(KeyBase):
    TYPE = KeyType.PLAINTEXT
    TYPES_ACCEPTABLE = {TYPE}
    NAME = "plaintext"
    ARG_NAME = "none"

    chunk_seed = 0
    crypt_key = b""  # makes .derive_key() work, nothing secret here
    id_key = b""  # makes .derive_key() work, nothing secret here

    logically_encrypted = False

    @classmethod
    def create(cls, repository, args, **kw):
        logger.info('Encryption NOT enabled.\nUse the "--encryption=repokey|keyfile" to enable encryption.')
        return cls(repository)

    @classmethod
    def detect(cls, repository, manifest_data, *, other=False):
        return cls(repository)

    def id_hash(self, data):
        return sha256(data).digest()

    def encrypt(self, id, data):
        return b"".join([self.TYPE_STR, data])

    def decrypt(self, id, data):
        self.assert_type(data[0], id)
        return memoryview(data)[1:]


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
        enc_key = os.urandom(32)
        enc_hmac_key = random_blake2b_256_key()
        self.crypt_key = enc_key + enc_hmac_key
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

    CIPHERSUITE: Callable = None  # override in derived class

    logically_encrypted = True

    def encrypt(self, id, data):
        # legacy, this is only used by the tests.
        next_iv = self.cipher.next_iv()
        return self.cipher.encrypt(data, header=self.TYPE_STR, iv=next_iv)

    def decrypt(self, id, data):
        self.assert_type(data[0], id)
        try:
            return self.cipher.decrypt(data)
        except IntegrityError as e:
            raise IntegrityError(f"Chunk {bin_to_hex(id)}: Could not decrypt [{str(e)}]")

    def init_from_given_data(self, *, crypt_key, id_key, chunk_seed):
        assert len(crypt_key) in (32 + 32, 32 + 128)
        assert len(id_key) in (32, 128)
        assert isinstance(chunk_seed, int)
        self.crypt_key = crypt_key
        self.id_key = id_key
        self.chunk_seed = chunk_seed

    def init_from_random_data(self):
        data = os.urandom(100)
        chunk_seed = bytes_to_int(data[96:100])
        # Convert to signed int32
        if chunk_seed & 0x80000000:
            chunk_seed = chunk_seed - 0xFFFFFFFF - 1
        self.init_from_given_data(crypt_key=data[0:64], id_key=data[64:96], chunk_seed=chunk_seed)

    def init_ciphers(self, manifest_data=None):
        enc_key, enc_hmac_key = self.crypt_key[0:32], self.crypt_key[32:]
        self.cipher = self.CIPHERSUITE(mac_key=enc_hmac_key, enc_key=enc_key, header_len=1, aad_offset=1)
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


class FlexiKey:
    FILE_ID = "BORG_KEY"
    STORAGE: ClassVar[str] = KeyBlobStorage.NO_STORAGE  # override in subclass

    @classmethod
    def detect(cls, repository, manifest_data, *, other=False):
        key = cls(repository)
        target = key.find_key()
        prompt = "Enter passphrase for key %s: " % target
        passphrase = Passphrase.env_passphrase(other=other)
        if passphrase is None:
            passphrase = Passphrase()
            if not key.load(target, passphrase):
                for retry in range(0, 3):
                    passphrase = Passphrase.getpass(prompt)
                    if key.load(target, passphrase):
                        break
                    Passphrase.display_debug_info(passphrase)
                else:
                    raise PasswordRetriesExceeded
        else:
            if not key.load(target, passphrase):
                Passphrase.display_debug_info(passphrase)
                raise PassphraseWrong
        key.init_ciphers(manifest_data)
        key._passphrase = passphrase
        return key

    def _load(self, key_data, passphrase):
        try:
            key = binascii.a2b_base64(key_data)
        except (ValueError, binascii.Error):
            raise KeyfileInvalidError(self.repository._location.canonical_path(), "(repokey)") from None
        if len(key) < 20:
            # this is in no way a precise check, usually we have about 400b key data.
            raise KeyfileInvalidError(self.repository._location.canonical_path(), "(repokey)")
        data = self.decrypt_key_file(key, passphrase)
        if data:
            data = msgpack.unpackb(data)
            key = Key(internal_dict=data)
            if key.version not in (1, 2):  # legacy: item.Key can still process v1 keys
                raise UnsupportedKeyFormatError()
            self.repository_id = key.repository_id
            self.crypt_key = key.crypt_key
            self.id_key = key.id_key
            self.chunk_seed = key.chunk_seed
            return True
        return False

    def decrypt_key_file(self, data, passphrase):
        unpacker = get_limited_unpacker("key")
        unpacker.feed(data)
        data = unpacker.unpack()
        encrypted_key = EncryptedKey(internal_dict=data)
        if encrypted_key.version != 1:
            raise UnsupportedKeyFormatError()
        else:
            self._encrypted_key_algorithm = encrypted_key.algorithm
            if encrypted_key.algorithm == "sha256":
                return self.decrypt_key_file_pbkdf2(encrypted_key, passphrase)
            elif encrypted_key.algorithm == "argon2 chacha20-poly1305":
                return self.decrypt_key_file_argon2(encrypted_key, passphrase)
            else:
                raise UnsupportedKeyFormatError()

    @staticmethod
    def pbkdf2(passphrase, salt, iterations, output_len_in_bytes):
        if os.environ.get("BORG_TESTONLY_WEAKEN_KDF") == "1":
            iterations = 1
        return pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations, output_len_in_bytes)

    @staticmethod
    def argon2(
        passphrase: str,
        output_len_in_bytes: int,
        salt: bytes,
        time_cost: int,
        memory_cost: int,
        parallelism: int,
        type: Literal["i", "d", "id"],
    ) -> bytes:
        if os.environ.get("BORG_TESTONLY_WEAKEN_KDF") == "1":
            time_cost = 1
            parallelism = 1
            # 8 is the smallest value that avoids the "Memory cost is too small" exception
            memory_cost = 8
        type_map = {"i": argon2.low_level.Type.I, "d": argon2.low_level.Type.D, "id": argon2.low_level.Type.ID}
        key = argon2.low_level.hash_secret_raw(
            secret=passphrase.encode("utf-8"),
            hash_len=output_len_in_bytes,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            type=type_map[type],
        )
        return key

    def decrypt_key_file_pbkdf2(self, encrypted_key, passphrase):
        key = self.pbkdf2(passphrase, encrypted_key.salt, encrypted_key.iterations, 32)
        data = AES(key, b"\0" * 16).decrypt(encrypted_key.data)
        if hmac.compare_digest(hmac_sha256(key, data), encrypted_key.hash):
            return data
        return None

    def decrypt_key_file_argon2(self, encrypted_key, passphrase):
        key = self.argon2(
            passphrase,
            output_len_in_bytes=32,
            salt=encrypted_key.salt,
            time_cost=encrypted_key.argon2_time_cost,
            memory_cost=encrypted_key.argon2_memory_cost,
            parallelism=encrypted_key.argon2_parallelism,
            type=encrypted_key.argon2_type,
        )
        ae_cipher = CHACHA20_POLY1305(key=key, iv=0, header_len=0, aad_offset=0)
        try:
            return ae_cipher.decrypt(encrypted_key.data)
        except low_level.IntegrityError:
            return None

    def encrypt_key_file(self, data, passphrase, algorithm):
        if algorithm == "sha256":
            return self.encrypt_key_file_pbkdf2(data, passphrase)
        elif algorithm == "argon2 chacha20-poly1305":
            return self.encrypt_key_file_argon2(data, passphrase)
        else:
            raise ValueError(f"Unexpected algorithm: {algorithm}")

    def encrypt_key_file_pbkdf2(self, data, passphrase):
        salt = os.urandom(32)
        iterations = PBKDF2_ITERATIONS
        key = self.pbkdf2(passphrase, salt, iterations, 32)
        hash = hmac_sha256(key, data)
        cdata = AES(key, b"\0" * 16).encrypt(data)
        enc_key = EncryptedKey(version=1, salt=salt, iterations=iterations, algorithm="sha256", hash=hash, data=cdata)
        return msgpack.packb(enc_key.as_dict())

    def encrypt_key_file_argon2(self, data, passphrase):
        salt = os.urandom(ARGON2_SALT_BYTES)
        key = self.argon2(passphrase, output_len_in_bytes=32, salt=salt, **ARGON2_ARGS)
        ae_cipher = CHACHA20_POLY1305(key=key, iv=0, header_len=0, aad_offset=0)
        encrypted_key = EncryptedKey(
            version=1,
            algorithm="argon2 chacha20-poly1305",
            salt=salt,
            data=ae_cipher.encrypt(data),
            **{"argon2_" + k: v for k, v in ARGON2_ARGS.items()},
        )
        return msgpack.packb(encrypted_key.as_dict())

    def _save(self, passphrase, algorithm):
        key = Key(
            version=2,
            repository_id=self.repository_id,
            crypt_key=self.crypt_key,
            id_key=self.id_key,
            chunk_seed=self.chunk_seed,
        )
        data = self.encrypt_key_file(msgpack.packb(key.as_dict()), passphrase, algorithm)
        key_data = "\n".join(textwrap.wrap(binascii.b2a_base64(data).decode("ascii")))
        return key_data

    def change_passphrase(self, passphrase=None):
        if passphrase is None:
            passphrase = Passphrase.new(allow_empty=True)
        self.save(self.target, passphrase, algorithm=self._encrypted_key_algorithm)

    @classmethod
    def create(cls, repository, args, *, other_key=None):
        key = cls(repository)
        key.repository_id = repository.id
        if other_key is not None:
            if isinstance(other_key, PlaintextKey):
                raise Error("Copying key material from an unencrypted repository is not possible.")
            if isinstance(key, AESKeyBase):
                # user must use an AEADKeyBase subclass (AEAD modes with session keys)
                raise Error("Copying key material to an AES-CTR based mode is insecure and unsupported.")
            if not uses_same_id_hash(other_key, key):
                raise Error("You must keep the same ID hash (HMAC-SHA256 or BLAKE2b) or deduplication will break.")
            if other_key.copy_crypt_key:
                # give the user the option to use the same authenticated encryption (AE) key
                crypt_key = other_key.crypt_key
            else:
                # borg transfer re-encrypts all data anyway, thus we can default to a new, random AE key
                crypt_key = os.urandom(64)
            key.init_from_given_data(crypt_key=crypt_key, id_key=other_key.id_key, chunk_seed=other_key.chunk_seed)
        else:
            key.init_from_random_data()
        passphrase = Passphrase.new(allow_empty=True)
        key.init_ciphers()
        target = key.get_new_target(args)
        key.save(target, passphrase, create=True, algorithm=KEY_ALGORITHMS["argon2"])
        logger.info('Key in "%s" created.' % target)
        logger.info("Keep this key safe. Your data will be inaccessible without it.")
        return key

    def sanity_check(self, filename, id):
        file_id = self.FILE_ID.encode() + b" "
        repo_id = bin_to_hex(id).encode("ascii")
        with open(filename, "rb") as fd:
            # we do the magic / id check in binary mode to avoid stumbling over
            # decoding errors if somebody has binary files in the keys dir for some reason.
            if fd.read(len(file_id)) != file_id:
                raise KeyfileInvalidError(self.repository._location.canonical_path(), filename)
            if fd.read(len(repo_id)) != repo_id:
                raise KeyfileMismatchError(self.repository._location.canonical_path(), filename)
        # we get here if it really looks like a borg key for this repo,
        # do some more checks that are close to how borg reads/parses the key.
        with open(filename) as fd:
            lines = fd.readlines()
            if len(lines) < 2:
                logger.warning(f"borg key sanity check: expected 2+ lines total. [{filename}]")
                raise KeyfileInvalidError(self.repository._location.canonical_path(), filename)
            if len(lines[0].rstrip()) > len(file_id) + len(repo_id):
                logger.warning(f"borg key sanity check: key line 1 seems too long. [{filename}]")
                raise KeyfileInvalidError(self.repository._location.canonical_path(), filename)
            key_b64 = "".join(lines[1:])
            try:
                key = binascii.a2b_base64(key_b64)
            except (ValueError, binascii.Error):
                logger.warning(f"borg key sanity check: key line 2+ does not look like base64. [{filename}]")
                raise KeyfileInvalidError(self.repository._location.canonical_path(), filename) from None
            if len(key) < 20:
                # this is in no way a precise check, usually we have about 400b key data.
                logger.warning(
                    f"borg key sanity check: binary encrypted key data from key line 2+ suspiciously short."
                    f" [{filename}]"
                )
                raise KeyfileInvalidError(self.repository._location.canonical_path(), filename)
        # looks good!
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
            key = self.repository.load_key()
            if not key:
                # if we got an empty key, it means there is no key.
                raise RepoKeyNotFoundError(loc) from None
            return loc
        else:
            raise TypeError("Unsupported borg key storage type")

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
        keys_path = Path(get_keys_dir())
        for entry in keys_path.iterdir():
            filename = keys_path / entry.name
            try:
                return self.sanity_check(str(filename), id)
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
            raise TypeError("Unsupported borg key storage type")

    def _find_key_file_from_environment(self):
        keyfile = os.environ.get("BORG_KEY_FILE")
        if keyfile:
            return os.path.abspath(keyfile)

    def _get_new_target_in_keys_dir(self, args):
        filename = args.location.to_key_filename()
        path = Path(filename)
        i = 1
        while path.exists():
            i += 1
            path = Path(filename + ".%d" % i)
        return str(path)

    def load(self, target, passphrase):
        if self.STORAGE == KeyBlobStorage.KEYFILE:
            with open(target) as fd:
                key_data = "".join(fd.readlines()[1:])
        elif self.STORAGE == KeyBlobStorage.REPO:
            # While the repository is encrypted, we consider a repokey repository with a blank
            # passphrase an unencrypted repository.
            self.logically_encrypted = passphrase != ""  # nosec B105

            # what we get in target is just a repo location, but we already have the repo obj:
            target = self.repository
            key_data = target.load_key()
            if not key_data:
                # if we got an empty key, it means there is no key.
                loc = target._location.canonical_path()
                raise RepoKeyNotFoundError(loc) from None
            key_data = key_data.decode("utf-8")  # remote repo: msgpack issue #99, getting bytes
        else:
            raise TypeError("Unsupported borg key storage type")
        success = self._load(key_data, passphrase)
        if success:
            self.target = target
        return success

    def save(self, target, passphrase, algorithm, create=False):
        key_data = self._save(passphrase, algorithm)
        if self.STORAGE == KeyBlobStorage.KEYFILE:
            if create and os.path.isfile(target):
                # if a new keyfile key repository is created, ensure that an existing keyfile of another
                # keyfile key repo is not accidentally overwritten by careless use of the BORG_KEY_FILE env var.
                # see issue #6036
                raise Error('Aborting because key in "%s" already exists.' % target)
            with SaveFile(target) as fd:
                fd.write(f"{self.FILE_ID} {bin_to_hex(self.repository_id)}\n")
                fd.write(key_data)
                fd.write("\n")
        elif self.STORAGE == KeyBlobStorage.REPO:
            self.logically_encrypted = passphrase != ""  # nosec B105
            key_data = key_data.encode("utf-8")  # remote repo: msgpack issue #99, giving bytes
            target.save_key(key_data)
        else:
            raise TypeError("Unsupported borg key storage type")
        self.target = target

    def remove(self, target):
        if self.STORAGE == KeyBlobStorage.KEYFILE:
            os.remove(target)
        elif self.STORAGE == KeyBlobStorage.REPO:
            target.save_key(b"")  # save empty key (no new api at remote repo necessary)
        else:
            raise TypeError("Unsupported borg key storage type")


class KeyfileKey(ID_HMAC_SHA_256, AESKeyBase, FlexiKey):
    TYPES_ACCEPTABLE = {KeyType.KEYFILE, KeyType.REPO, KeyType.PASSPHRASE}
    TYPE = KeyType.KEYFILE
    NAME = "key file"
    ARG_NAME = "keyfile"
    STORAGE = KeyBlobStorage.KEYFILE
    CIPHERSUITE = AES256_CTR_HMAC_SHA256


class RepoKey(ID_HMAC_SHA_256, AESKeyBase, FlexiKey):
    TYPES_ACCEPTABLE = {KeyType.KEYFILE, KeyType.REPO, KeyType.PASSPHRASE}
    TYPE = KeyType.REPO
    NAME = "repokey"
    ARG_NAME = "repokey"
    STORAGE = KeyBlobStorage.REPO
    CIPHERSUITE = AES256_CTR_HMAC_SHA256


class Blake2KeyfileKey(ID_BLAKE2b_256, AESKeyBase, FlexiKey):
    TYPES_ACCEPTABLE = {KeyType.BLAKE2KEYFILE, KeyType.BLAKE2REPO}
    TYPE = KeyType.BLAKE2KEYFILE
    NAME = "key file BLAKE2b"
    ARG_NAME = "keyfile-blake2"
    STORAGE = KeyBlobStorage.KEYFILE
    CIPHERSUITE = AES256_CTR_BLAKE2b


class Blake2RepoKey(ID_BLAKE2b_256, AESKeyBase, FlexiKey):
    TYPES_ACCEPTABLE = {KeyType.BLAKE2KEYFILE, KeyType.BLAKE2REPO}
    TYPE = KeyType.BLAKE2REPO
    NAME = "repokey BLAKE2b"
    ARG_NAME = "repokey-blake2"
    STORAGE = KeyBlobStorage.REPO
    CIPHERSUITE = AES256_CTR_BLAKE2b


class AuthenticatedKeyBase(AESKeyBase, FlexiKey):
    STORAGE = KeyBlobStorage.REPO

    # It's only authenticated, not encrypted.
    logically_encrypted = False

    def _load(self, key_data, passphrase):
        if AUTHENTICATED_NO_KEY:
            # fake _load if we have no key or passphrase
            NOPE = bytes(32)  # 256 bit all-zero
            self.repository_id = NOPE
            self.enc_key = NOPE
            self.enc_hmac_key = NOPE
            self.id_key = NOPE
            self.chunk_seed = 0
            return True
        return super()._load(key_data, passphrase)

    def load(self, target, passphrase):
        success = super().load(target, passphrase)
        self.logically_encrypted = False
        return success

    def save(self, target, passphrase, algorithm, create=False):
        super().save(target, passphrase, algorithm, create=create)
        self.logically_encrypted = False

    def init_ciphers(self, manifest_data=None):
        if manifest_data is not None:
            self.assert_type(manifest_data[0])

    def encrypt(self, id, data):
        return b"".join([self.TYPE_STR, data])

    def decrypt(self, id, data):
        self.assert_type(data[0], id)
        return memoryview(data)[1:]


class AuthenticatedKey(ID_HMAC_SHA_256, AuthenticatedKeyBase):
    TYPE = KeyType.AUTHENTICATED
    TYPES_ACCEPTABLE = {TYPE}
    NAME = "authenticated"
    ARG_NAME = "authenticated"


class Blake2AuthenticatedKey(ID_BLAKE2b_256, AuthenticatedKeyBase):
    TYPE = KeyType.BLAKE2AUTHENTICATED
    TYPES_ACCEPTABLE = {TYPE}
    NAME = "authenticated BLAKE2b"
    ARG_NAME = "authenticated-blake2"


# ------------ new crypto ------------


class AEADKeyBase(KeyBase):
    """
    Chunks are encrypted and authenticated using some AEAD ciphersuite

    Layout: suite:4 keytype:4 reserved:8 messageIV:48 sessionID:192 auth_tag:128 payload:... [bits]
            ^-------------------- AAD ----------------------------^
    Offsets:0                 1          2            8             32           48 [bytes]

    suite: 1010b for new AEAD crypto, 0000b is old crypto
    keytype: see constants.KeyType (suite+keytype)
    reserved: all-zero, for future use
    messageIV: a counter starting from 0 for all new encrypted messages of one session
    sessionID: 192bit random, computed once per session (the session key is derived from this)
    auth_tag: authentication tag output of the AEAD cipher (computed over payload and AAD)
    payload: encrypted chunk data
    """

    PAYLOAD_OVERHEAD = 1 + 1 + 6 + 24 + 16  # [bytes], see Layout

    CIPHERSUITE: Callable = None  # override in subclass

    logically_encrypted = True

    MAX_IV = 2**48 - 1

    def assert_id(self, id, data):
        # Comparing the id hash here would not be needed any more for the new AEAD crypto **IF** we
        # could be sure that chunks were created by normal (not tampered, not evil) borg code:
        # We put the id into AAD when storing the chunk, so it gets into the authentication tag computation.
        # when decrypting, we provide the id we **want** as AAD for the auth tag verification, so
        # decrypting only succeeds if we got the ciphertext we wrote **for that chunk id**.
        # So, basically the **repository** can not cheat on us by giving us a different chunk.
        #
        # **BUT**, if chunks are created by tampered, evil borg code, the borg client code could put
        # a wrong chunkid into AAD and then AEAD-encrypt-and-auth this and store it into the
        # repository using this bad chunkid as key (violating the usual chunkid == id_hash(data)).
        # Later, when reading such a bad chunk, AEAD-auth-and-decrypt would not notice any
        # issue and decrypt successfully.
        # Thus, to notice such evil borg activity, we must check for such violations here:
        if id and id != Manifest.MANIFEST_ID:
            id_computed = self.id_hash(data)
            if not hmac.compare_digest(id_computed, id):
                raise IntegrityError("Chunk %s: id verification failed" % bin_to_hex(id))

    def encrypt(self, id, data):
        # to encrypt new data in this session we use always self.cipher and self.sessionid
        reserved = b"\0"
        iv = self.cipher.next_iv()
        if iv > self.MAX_IV:  # see the data-structures docs about why the IV range is enough
            raise IntegrityError("IV overflow, should never happen.")
        iv_48bit = iv.to_bytes(6, "big")
        header = self.TYPE_STR + reserved + iv_48bit + self.sessionid
        return self.cipher.encrypt(data, header=header, iv=iv, aad=id)

    def decrypt(self, id, data):
        # to decrypt existing data, we need to get a cipher configured for the sessionid and iv from header
        self.assert_type(data[0], id)
        iv_48bit = data[2:8]
        sessionid = bytes(data[8:32])
        iv = int.from_bytes(iv_48bit, "big")
        cipher = self._get_cipher(sessionid, iv)
        try:
            return cipher.decrypt(data, aad=id)
        except IntegrityError as e:
            raise IntegrityError(f"Chunk {bin_to_hex(id)}: Could not decrypt [{str(e)}]")

    def init_from_given_data(self, *, crypt_key, id_key, chunk_seed):
        assert len(crypt_key) in (32 + 32, 32 + 128)
        assert len(id_key) in (32, 128)
        assert isinstance(chunk_seed, int)
        self.crypt_key = crypt_key
        self.id_key = id_key
        self.chunk_seed = chunk_seed

    def init_from_random_data(self):
        data = os.urandom(100)
        chunk_seed = bytes_to_int(data[96:100])
        # Convert to signed int32
        if chunk_seed & 0x80000000:
            chunk_seed = chunk_seed - 0xFFFFFFFF - 1
        self.init_from_given_data(crypt_key=data[0:64], id_key=data[64:96], chunk_seed=chunk_seed)

    def _get_session_key(self, sessionid, domain=None):
        """
        Derive a session key from the secret long-term static crypt_key (which is a fully random PRK)
        and the session id (which is fully random also).
        Optionally, a domain can be given for domain separation (defaults to a different binary string
        per cipher suite).
        """
        # Performance note:
        # While this is only invoked once per session to generate a new key for encrypting new data, it is invoked
        # frequently (per encrypted repo object) to compute the corresponding key for decrypting existing data.
        assert len(sessionid) == 24  # 192bit
        if domain is None:
            domain = b"borg-session-key-" + self.CIPHERSUITE.__name__.encode()
        return self.derive_key(salt=sessionid, domain=domain, size=32)  # 256bit

    def _get_cipher(self, sessionid, iv):
        assert isinstance(iv, int)
        key = self._get_session_key(sessionid)
        cipher = self.CIPHERSUITE(key=key, iv=iv, header_len=1 + 1 + 6 + 24, aad_offset=0)
        return cipher

    def init_ciphers(self, manifest_data=None, iv=0):
        # in every new session we start with a fresh sessionid and at iv == 0, manifest_data and iv params are ignored
        self.sessionid = os.urandom(24)
        self.cipher = self._get_cipher(self.sessionid, iv=0)


class AESOCBKeyfileKey(ID_HMAC_SHA_256, AEADKeyBase, FlexiKey):
    TYPES_ACCEPTABLE = {KeyType.AESOCBKEYFILE, KeyType.AESOCBREPO}
    TYPE = KeyType.AESOCBKEYFILE
    NAME = "key file AES-OCB"
    ARG_NAME = "keyfile-aes-ocb"
    STORAGE = KeyBlobStorage.KEYFILE
    CIPHERSUITE = AES256_OCB


class AESOCBRepoKey(ID_HMAC_SHA_256, AEADKeyBase, FlexiKey):
    TYPES_ACCEPTABLE = {KeyType.AESOCBKEYFILE, KeyType.AESOCBREPO}
    TYPE = KeyType.AESOCBREPO
    NAME = "repokey AES-OCB"
    ARG_NAME = "repokey-aes-ocb"
    STORAGE = KeyBlobStorage.REPO
    CIPHERSUITE = AES256_OCB


class CHPOKeyfileKey(ID_HMAC_SHA_256, AEADKeyBase, FlexiKey):
    TYPES_ACCEPTABLE = {KeyType.CHPOKEYFILE, KeyType.CHPOREPO}
    TYPE = KeyType.CHPOKEYFILE
    NAME = "key file ChaCha20-Poly1305"
    ARG_NAME = "keyfile-chacha20-poly1305"
    STORAGE = KeyBlobStorage.KEYFILE
    CIPHERSUITE = CHACHA20_POLY1305


class CHPORepoKey(ID_HMAC_SHA_256, AEADKeyBase, FlexiKey):
    TYPES_ACCEPTABLE = {KeyType.CHPOKEYFILE, KeyType.CHPOREPO}
    TYPE = KeyType.CHPOREPO
    NAME = "repokey ChaCha20-Poly1305"
    ARG_NAME = "repokey-chacha20-poly1305"
    STORAGE = KeyBlobStorage.REPO
    CIPHERSUITE = CHACHA20_POLY1305


class Blake2AESOCBKeyfileKey(ID_BLAKE2b_256, AEADKeyBase, FlexiKey):
    TYPES_ACCEPTABLE = {KeyType.BLAKE2AESOCBKEYFILE, KeyType.BLAKE2AESOCBREPO}
    TYPE = KeyType.BLAKE2AESOCBKEYFILE
    NAME = "key file BLAKE2b AES-OCB"
    ARG_NAME = "keyfile-blake2-aes-ocb"
    STORAGE = KeyBlobStorage.KEYFILE
    CIPHERSUITE = AES256_OCB


class Blake2AESOCBRepoKey(ID_BLAKE2b_256, AEADKeyBase, FlexiKey):
    TYPES_ACCEPTABLE = {KeyType.BLAKE2AESOCBKEYFILE, KeyType.BLAKE2AESOCBREPO}
    TYPE = KeyType.BLAKE2AESOCBREPO
    NAME = "repokey BLAKE2b AES-OCB"
    ARG_NAME = "repokey-blake2-aes-ocb"
    STORAGE = KeyBlobStorage.REPO
    CIPHERSUITE = AES256_OCB


class Blake2CHPOKeyfileKey(ID_BLAKE2b_256, AEADKeyBase, FlexiKey):
    TYPES_ACCEPTABLE = {KeyType.BLAKE2CHPOKEYFILE, KeyType.BLAKE2CHPOREPO}
    TYPE = KeyType.BLAKE2CHPOKEYFILE
    NAME = "key file BLAKE2b ChaCha20-Poly1305"
    ARG_NAME = "keyfile-blake2-chacha20-poly1305"
    STORAGE = KeyBlobStorage.KEYFILE
    CIPHERSUITE = CHACHA20_POLY1305


class Blake2CHPORepoKey(ID_BLAKE2b_256, AEADKeyBase, FlexiKey):
    TYPES_ACCEPTABLE = {KeyType.BLAKE2CHPOKEYFILE, KeyType.BLAKE2CHPOREPO}
    TYPE = KeyType.BLAKE2CHPOREPO
    NAME = "repokey BLAKE2b ChaCha20-Poly1305"
    ARG_NAME = "repokey-blake2-chacha20-poly1305"
    STORAGE = KeyBlobStorage.REPO
    CIPHERSUITE = CHACHA20_POLY1305


LEGACY_KEY_TYPES = (
    # legacy (AES-CTR based) crypto
    KeyfileKey,
    RepoKey,
    Blake2KeyfileKey,
    Blake2RepoKey,
)

AVAILABLE_KEY_TYPES = (
    # these are available encryption modes for new repositories
    # not encrypted modes
    PlaintextKey,
    AuthenticatedKey,
    Blake2AuthenticatedKey,
    # new crypto
    AESOCBKeyfileKey,
    AESOCBRepoKey,
    CHPOKeyfileKey,
    CHPORepoKey,
    Blake2AESOCBKeyfileKey,
    Blake2AESOCBRepoKey,
    Blake2CHPOKeyfileKey,
    Blake2CHPORepoKey,
)

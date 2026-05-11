import binascii
import hmac
import os
import textwrap
from hashlib import sha256
from pathlib import Path
from typing import Literal, ClassVar
from collections.abc import Callable

from ..logger import create_logger

logger = create_logger()

from blake3 import blake3

from ..constants import *  # NOQA
from ..helpers import StableDict
from ..helpers import Error, IntegrityError
from ..helpers import get_keys_dir, secure_erase
from ..helpers import get_limited_unpacker
from ..helpers import bin_to_hex
from ..helpers.passphrase import Passphrase, PasswordRetriesExceeded, PassphraseWrong
from ..helpers import msgpack
from ..helpers import workarounds
from ..item import Key, EncryptedKey
from ..manifest import Manifest
from ..platform import SaveFile
from ..repoobj import RepoObj


from .low_level import bytes_to_int, num_cipher_blocks, hmac_sha256
from .low_level import AES256_OCB, CHACHA20_POLY1305
from . import low_level


def keyfile_name_for(content: bytes) -> str:
    return sha256(content).hexdigest()


KEYFILE_ID = "BORG_KEY"

# label of the first borg key, created at repo-create time. it is protected from deletion
# and its label is reserved (cannot be assigned to additionally added borg keys).
ADMIN_LABEL = "admin"


def is_keyfile(data: str | bytes, repoid: str | None = None) -> bool:
    # repoid is a hex str, if given. if given, we only accept keyfiles for that repo.
    header = f"{KEYFILE_ID} {repoid or ''}"
    if isinstance(data, str):
        return data.startswith(header)
    elif isinstance(data, bytes):
        # data can be given as bytes to avoid decoding issues for invalid files.
        return data.startswith(header.encode())
    else:
        raise TypeError(f"Expected str or bytes, got {type(data)}")


def keyfile_format(repoid: str, b64data: str) -> str:
    return f"{KEYFILE_ID} {repoid}\n{b64data}\n"


def keyfile_parse(data: str | bytes, repoid: str | None = None) -> tuple[str, str]:
    if repoid is None:
        if not is_keyfile(data):
            raise ValueError("Not a keyfile")
    else:
        if not is_keyfile(data, repoid):
            raise ValueError("Not a keyfile for repo %s" % repoid)
    if isinstance(data, bytes):
        data = data.decode()
    header, b64data = data.split("\n", 1)
    repoid = header[len(KEYFILE_ID) + 1 :]
    return repoid, b64data


# workaround for lost passphrase or key in "authenticated*" modes
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
    """Your Borg key is stored in an unsupported format. Try using a newer version of Borg."""

    exit_mcode = 49


# map the user-facing key location names ("borg repo-create --key-location", "borg key change-location")
# to the internal KeyBlobStorage values. Note "repokey" != KeyBlobStorage.REPO's string value.
KEY_LOCATIONS = {"keyfile": KeyBlobStorage.KEYFILE, "repokey": KeyBlobStorage.REPO}


def key_creator(repository, args, *, other_key=None):
    # the crypto suite is selected by two orthogonal dimensions: the cipher / AE algorithm
    # (--encryption) and the id hash function (--id-hash). id-hash is always significant, so e.g.
    # "--encryption none --id-hash blake3" finds no match and is rejected (none only supports sha256).
    enc = args.encryption
    id_hash = getattr(args, "id_hash", "sha256")
    for key in AVAILABLE_KEY_TYPES:
        if key.ENC_NAME == enc and key.IDHASH_NAME == id_hash:
            return key.create(repository, args, other_key=other_key)
    raise Error(
        f'Unsupported --encryption "{enc}" / --id-hash "{id_hash}" combination '
        f'(the "none" encryption only supports the "sha256" id-hash).'
    )


def encryption_argument_names():
    # distinct cipher / AE algorithm names offered by "borg repo-create --encryption", in the
    # order the key types are listed in AVAILABLE_KEY_TYPES (deduplicated, sha256/blake3 variants merge).
    names = []
    for key in AVAILABLE_KEY_TYPES:
        if key.ENC_NAME and key.ENC_NAME not in names:
            names.append(key.ENC_NAME)
    return names


def id_hash_argument_names():
    # distinct id hash function names offered by "borg repo-create --id-hash".
    names = []
    for key in AVAILABLE_KEY_TYPES:
        if key.IDHASH_NAME and key.IDHASH_NAME not in names:
            names.append(key.IDHASH_NAME)
    return names


def identify_key(manifest_data):
    # the key-type byte only identifies the crypto suite (id hash, MAC, cipher), NOT where the key is
    # stored: keyfile and repokey share one class now and accept both historic type bytes. The legacy
    # PASSPHRASE byte (0x01) is part of AESCTRKey.TYPES_ACCEPTABLE. All TYPES_ACCEPTABLE sets are disjoint.
    key_type = manifest_data[0]
    for key in LEGACY_KEY_TYPES + AVAILABLE_KEY_TYPES:
        if key_type in key.TYPES_ACCEPTABLE:
            return key
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
    old_hmac_sha256_ids = (AESCTRKey, AuthenticatedKey)
    new_hmac_sha256_ids = (AESOCBKey, CHPOKey, AuthenticatedKey)
    # note: we do not support blake2b for new repos, see #8867
    new_blake3_ids = (Blake3AESOCBKey, Blake3CHPOKey, Blake3AuthenticatedKey)
    same_ids = (
        isinstance(other_key, old_hmac_sha256_ids + new_hmac_sha256_ids)
        and isinstance(key, new_hmac_sha256_ids)
        or isinstance(other_key, new_blake3_ids)
        and isinstance(key, new_blake3_ids)
        or isinstance(other_key, old_sha256_ids + new_sha256_ids)
        and isinstance(key, new_sha256_ids)
    )
    return same_ids


class KeyBase:
    # Numeric key type ID, must fit in one byte.
    TYPE: int = None  # override in subclasses
    # set of key type IDs the class can handle as input
    TYPES_ACCEPTABLE: set[int] = None  # override in subclasses

    # The two orthogonal dimensions a creatable crypto suite is selected by on the command line:
    # ENC_NAME -> "borg repo-create --encryption" (cipher / AE algorithm)
    # IDHASH_NAME -> "borg repo-create --id-hash" (id hash function)
    # (key location is the third dimension, handled separately via --key-location).
    # None means "not creatable this way" (e.g. legacy read-only classes).
    ENC_NAME: ClassVar[str] = None  # override in creatable subclasses
    IDHASH_NAME: ClassVar[str] = None  # override in creatable subclasses (or via id-hash mix-in)

    # Storage type (no key blob storage / keyfile / repo). This is only a default seed for the
    # per-instance self.storage; keyfile vs repokey is a property of an individual key, not the class.
    STORAGE: ClassVar[str] = KeyBlobStorage.NO_STORAGE

    # Whether a key of this class may be stored as a keyfile or as a repokey (configurable at
    # repo creation via --key-location and changeable later via "borg key change-location").
    LOCATION_CONFIGURABLE = False

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
        # where this particular key is/will be stored (keyfile or repo); seeded from the class default,
        # overwritten when a key is loaded (see FlexiKey._try_key) or created (see --key-location).
        self.storage = self.STORAGE
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
    ENC_NAME = "none"
    IDHASH_NAME = "sha256"  # plain sha256(data), no key; blake3 is not supported for "none"

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


class ID_HMAC_SHA_256:
    """
    Key mix-in class for using HMAC-SHA-256 for the id key.

    The id_key length must be 32 bytes.
    """

    IDHASH_NAME = "sha256"

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
    FILE_ID = KEYFILE_ID
    STORAGE: ClassVar[str] = KeyBlobStorage.NO_STORAGE  # override in subclass

    # multiple-borg-keys state (a repository may have multiple borg keys, one per passphrase):
    _encrypted_key_label = None  # label read from the EncryptedKey envelope on decrypt
    _loaded_key_id = None  # key id (content digest / store name) of the borg key we unlocked
    _loaded_label = None  # label of the borg key we unlocked

    @classmethod
    def detect(cls, repository, manifest_data, *, other=False):
        key = cls(repository)
        target = key.find_key()
        prompt = "Enter passphrase for key %s: " % target
        passphrase = Passphrase.env_passphrase(other=other)
        # a repository may have multiple borg keys, one per passphrase; try the
        # passphrase against all of them.
        if passphrase is None:
            passphrase = Passphrase()
            if not key.load_any(passphrase):
                for retry in range(0, 3):
                    passphrase = Passphrase.getpass(prompt)
                    if key.load_any(passphrase):
                        break
                    Passphrase.display_debug_info(passphrase)
                else:
                    raise PasswordRetriesExceeded
        else:
            if not key.load_any(passphrase):
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
            self._encrypted_key_label = encrypted_key.get("label")
            if encrypted_key.algorithm == "argon2 chacha20-poly1305":
                return self.decrypt_key_file_argon2(encrypted_key, passphrase)
            else:
                raise UnsupportedKeyFormatError()

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
        return low_level.argon2_hash(
            passphrase.encode("utf-8"), salt, time_cost, memory_cost, parallelism, output_len_in_bytes, type
        )

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

    def encrypt_key_file(self, data, passphrase, algorithm, label=None):
        if algorithm == "argon2 chacha20-poly1305":
            return self.encrypt_key_file_argon2(data, passphrase, label=label)
        else:
            raise ValueError(f"Unexpected algorithm: {algorithm}")

    def encrypt_key_file_argon2(self, data, passphrase, label=None):
        salt = os.urandom(ARGON2_SALT_BYTES)
        key = self.argon2(passphrase, output_len_in_bytes=32, salt=salt, **ARGON2_ARGS)
        ae_cipher = CHACHA20_POLY1305(key=key, iv=0, header_len=0, aad_offset=0)
        kw = dict(
            version=1,
            algorithm="argon2 chacha20-poly1305",
            salt=salt,
            data=ae_cipher.encrypt(data),
            **{"argon2_" + k: v for k, v in ARGON2_ARGS.items()},
        )
        if label is not None:
            kw["label"] = label
        encrypted_key = EncryptedKey(**kw)
        return msgpack.packb(encrypted_key.as_dict())

    def _save(self, passphrase, algorithm, label=None):
        key = Key(
            version=2,
            repository_id=self.repository_id,
            crypt_key=self.crypt_key,
            id_key=self.id_key,
            chunk_seed=self.chunk_seed,
        )
        data = self.encrypt_key_file(msgpack.packb(key.as_dict()), passphrase, algorithm, label=label)
        key_data = "\n".join(textwrap.wrap(binascii.b2a_base64(data).decode("ascii")))
        return key_data

    def change_passphrase(self, passphrase=None):
        if passphrase is None:
            passphrase = Passphrase.new(allow_empty=True)
        # replace the borg key we unlocked with: keep its label, write the new borg key, then
        # (for repokey) delete the previously-loaded borg key (keyfile mode auto-erases it in save()).
        old_id = self._loaded_key_id
        self.save(self.target, passphrase, algorithm=self._encrypted_key_algorithm, label=self._loaded_label)
        if self.storage == KeyBlobStorage.REPO and old_id and hasattr(self.repository, "delete_key"):
            if self._loaded_key_id != old_id:
                self.repository.delete_key(old_id)

    @classmethod
    def create(cls, repository, args, *, other_key=None):
        key = cls(repository)
        key.repository_id = repository.id
        if cls.LOCATION_CONFIGURABLE:
            # choose initial storage (keyfile or repokey) from --key-location (default: repokey).
            key.storage = KEY_LOCATIONS.get(getattr(args, "key_location", None), cls.STORAGE)
        if other_key is not None:
            if isinstance(other_key, PlaintextKey):
                raise Error("Copying key material from an unencrypted repository is not possible.")
            if isinstance(key, AESKeyBase):
                # user must use an AEADKeyBase subclass (AEAD modes with session keys)
                raise Error("Copying key material to an AES-CTR based mode is insecure and unsupported.")
            if other_key.copy_crypt_key:
                # give the user the option to use the same authenticated encryption (AE) key
                crypt_key = other_key.crypt_key
            else:
                # borg transfer re-encrypts all data anyway, thus we can default to a new, random AE key
                crypt_key = os.urandom(64)
            if len(other_key.id_key) == 128:  # blake2b id key from borg 1.x is not supported anymore
                id_key = os.urandom(32)  # hmac-sha256 and blake3 use 32 bytes
            else:
                id_key = other_key.id_key
            chunk_seed = other_key.chunk_seed
            key.init_from_given_data(crypt_key=crypt_key, id_key=id_key, chunk_seed=chunk_seed)
        else:
            key.init_from_random_data()
        passphrase = Passphrase.new(allow_empty=True)
        key.init_ciphers()
        target = key.get_new_target(args)
        # the first borg key of a repository is the protected "admin" key.
        key.save(target, passphrase, create=True, algorithm=KEY_ALGORITHMS["argon2"], label=ADMIN_LABEL)
        logger.info('Key in "%s" created.' % key.target)
        logger.info("Keep this key safe. Your data will be inaccessible without it.")
        return key

    def sanity_check(self, filename, id):
        repo_id_hex = bin_to_hex(id)
        with open(filename, "rb") as fd:
            # we do the magic / id check in binary mode to avoid stumbling over
            # decoding errors if somebody has binary files in the keys dir for some reason.
            data = fd.read(10000)
        if not is_keyfile(data):
            raise KeyfileInvalidError(self.repository._location.canonical_path(), filename)
        if not is_keyfile(data, repo_id_hex):
            raise KeyfileMismatchError(self.repository._location.canonical_path(), filename)
        # we get here if it really looks like a borg key for this repo,
        # do some more checks that are close to how borg reads/parses the key.
        _, key_b64 = keyfile_parse(data, repo_id_hex)
        try:
            binascii.a2b_base64(key_b64)
        except (ValueError, binascii.Error):
            logger.warning(f"borg key sanity check: key line 2+ does not look like base64. [{filename}]")
            raise KeyfileInvalidError(self.repository._location.canonical_path(), filename) from None
        # looks good!
        return filename

    def find_key(self):
        # storage-agnostic: report the location of any existing borg key for this repo, preferring a
        # keyfile (checked first) over a repokey. Used for the passphrase prompt and for logging.
        env_keyfile = self._find_key_file_from_environment()
        if env_keyfile is not None:
            return self.sanity_check(env_keyfile, self.repository.id)
        keyfile = self._find_key_in_keys_dir()
        if keyfile is not None:
            return keyfile
        loc = self.repository._location.canonical_path()
        if self.repository.load_key():
            return loc
        raise RepoKeyNotFoundError(loc) from None

    def get_existing_or_new_target(self, args):
        keyfile = self._find_key_file_from_environment()
        if keyfile is not None:
            return keyfile
        keyfile = self._find_key_in_keys_dir()
        if keyfile is not None:
            return keyfile
        return get_keys_dir()

    def _keys_dir(self):
        # v1 repos use the borg 1.x keys dir, which differs from the borg2 one on macOS
        # (~/.config/borg/keys vs ~/Library/Application Support/borg/keys).
        if self.repository.version == 1:
            from ..legacy.fs import get_keys_dir as get_keys_dir_legacy

            return get_keys_dir_legacy()
        return get_keys_dir()

    def _find_key_in_keys_dir(self):
        id = self.repository.id
        keys_path = Path(self._keys_dir())
        for entry in keys_path.iterdir():
            filename = keys_path / entry.name
            try:
                return self.sanity_check(str(filename), id)
            except (KeyfileInvalidError, KeyfileMismatchError):
                pass

    def _find_all_keys_in_keys_dir(self):
        # return all keyfiles in the keys dir that belong to this repository (multiple passphrases).
        id = self.repository.id
        keys_path = Path(self._keys_dir())
        found = []
        if not keys_path.exists():
            return found
        for entry in sorted(keys_path.iterdir()):
            filename = keys_path / entry.name
            try:
                self.sanity_check(str(filename), id)
            except (KeyfileInvalidError, KeyfileMismatchError):
                continue
            found.append(str(filename))
        return found

    def get_new_target(self, args):
        if self.storage == KeyBlobStorage.KEYFILE:
            keyfile = self._find_key_file_from_environment()
            if keyfile is not None:
                return keyfile
            return get_keys_dir()
        elif self.storage == KeyBlobStorage.REPO:
            return self.repository
        else:
            raise TypeError("Unsupported borg key storage type")

    def _find_key_file_from_environment(self):
        keyfile = os.environ.get("BORG_KEY_FILE")
        if keyfile:
            return os.path.abspath(keyfile)

    def _repo_candidates(self):
        # legacy-safe enumeration: modern Repository has load_keys() (multiple borg keys),
        # legacy LegacyRepository only has load_key() (a single borg key).
        repo = self.repository
        result = []
        if hasattr(repo, "load_keys"):
            for name, keydata in repo.load_keys():
                result.append((name, keydata.decode("utf-8"), None))
        else:
            keydata = repo.load_key()
            if keydata:
                result.append((sha256(keydata).hexdigest(), keydata.decode("utf-8"), None))
        return result

    def _keyfile_candidates(self):
        env_keyfile = self._find_key_file_from_environment()
        paths = [env_keyfile] if env_keyfile is not None else self._find_all_keys_in_keys_dir()
        result = []
        for path in paths:
            try:
                with open(path, "rb") as fd:
                    blob = fd.read()
            except OSError:
                continue
            result.append((sha256(blob).hexdigest(), blob.decode("utf-8"), str(path)))
        return result

    def _iter_keys(self):
        # return [(key_id, blob_text, keyfile_path_or_None)] for all borg keys of this repo.
        # storage-agnostic: we look at keyfiles first and repokeys afterwards, regardless of the
        # manifest key-type byte. The first key a passphrase unlocks wins (see load_any).
        return self._keyfile_candidates() + self._repo_candidates()

    def _key_envelope(self, blob_text):
        # decode the (unencrypted) EncryptedKey envelope of a borg key without decrypting it.
        if is_keyfile(blob_text):
            _, b64 = keyfile_parse(blob_text, bin_to_hex(self.repository.id))
        else:
            b64 = blob_text  # borg 1.x repokey: raw base64, no BORG_KEY header
        raw = binascii.a2b_base64(b64)
        unpacker = get_limited_unpacker("key")
        unpacker.feed(raw)
        return EncryptedKey(internal_dict=unpacker.unpack())

    def _try_key(self, key_id, blob_text, keyfile_path, passphrase):
        # try to unlock a single borg key with the given passphrase; on success, remember it.
        if is_keyfile(blob_text):
            # keyfile / modern repokey: data is wrapped in keyfile_format (BORG_KEY header).
            try:
                _, key_data = keyfile_parse(blob_text, bin_to_hex(self.repository.id))
            except ValueError:
                return False
        else:
            # borg 1.x repokey: stored as raw base64 without the BORG_KEY header.
            key_data = blob_text
        try:
            loaded = self._load(key_data, passphrase)
        except Exception as exc:  # noqa: BLE001 - a corrupted borg key must not break unlocking via the others
            logger.debug("Borg key %s could not be loaded (corrupted?), skipping it: %s", key_id[:12], exc)
            return False
        if loaded:
            # remember where this particular key actually lives (keyfile vs repokey), independent of
            # the manifest key-type byte, so save/remove/list operate on the right storage afterwards.
            self.storage = KeyBlobStorage.KEYFILE if keyfile_path is not None else KeyBlobStorage.REPO
            self.target = keyfile_path if self.storage == KeyBlobStorage.KEYFILE else self.repository
            if self.storage == KeyBlobStorage.REPO:
                # While the repository is encrypted, we consider a repokey repository with a blank
                # passphrase an unencrypted repository.
                self.logically_encrypted = passphrase != ""  # nosec B105
            self._loaded_key_id = key_id
            self._loaded_label = self._encrypted_key_label
            return True
        return False

    def load_any(self, passphrase):
        """Try the passphrase against every borg key of this repository."""
        for key_id, blob_text, keyfile_path in self._iter_keys():
            if self._try_key(key_id, blob_text, keyfile_path, passphrase):
                return True
        return False

    def load(self, target, passphrase):
        # load a specific borg key: for keyfiles, the explicit file given as target; for repokey,
        # any of the repository's borg keys (which are addressed by passphrase, not by target).
        if self.storage == KeyBlobStorage.KEYFILE:
            try:
                with open(target, "rb") as fd:
                    blob = fd.read()
            except OSError:
                return False
            return self._try_key(sha256(blob).hexdigest(), blob.decode("utf-8"), str(target), passphrase)
        else:
            return self.load_any(passphrase)

    def save(self, target, passphrase, algorithm, create=False, label=None, replace=True):
        # replace=True replaces the previously-loaded borg key (change-passphrase semantics);
        # replace=False adds an additional borg key, keeping the existing ones (key add).
        key_data = self._save(passphrase, algorithm, label=label)
        if self.storage == KeyBlobStorage.KEYFILE:
            old_target = getattr(self, "target", None)
            keys_dir = get_keys_dir()
            keyfile_data = keyfile_format(bin_to_hex(self.repository_id), key_data)
            target_dir = target if os.path.isdir(target) else os.path.dirname(target)
            auto_named = not os.environ.get("BORG_KEY_FILE") and os.path.samefile(target_dir, keys_dir)
            if auto_named:
                target = os.path.join(keys_dir, keyfile_name_for(keyfile_data.encode()))
            if create and os.path.isfile(target):
                # if a new keyfile key repository is created, ensure that an existing keyfile of another
                # keyfile key repo is not accidentally overwritten by careless use of the BORG_KEY_FILE env var.
                # see issue #6036
                raise Error('Aborting because key in "%s" already exists.' % target)
            # use binary mode so line endings are NOT translated to CRLF on Windows
            with SaveFile(target, binary=True) as fd:
                fd.write(keyfile_data.encode())
            if replace and auto_named and isinstance(old_target, str) and old_target != target:
                try:
                    in_keys_dir = os.path.samefile(os.path.dirname(old_target), keys_dir)
                except OSError:
                    in_keys_dir = False
                if in_keys_dir:
                    try:
                        secure_erase(old_target, avoid_collateral_damage=True)
                    except OSError as exc:
                        logger.debug('Could not remove previous keyfile "%s": %s', old_target, exc)
            self._loaded_key_id = sha256(keyfile_data.encode()).hexdigest()
        elif self.storage == KeyBlobStorage.REPO:
            self.logically_encrypted = passphrase != ""  # nosec B105
            key_data = keyfile_format(bin_to_hex(self.repository_id), key_data)
            key_data = key_data.encode("utf-8")  # remote repo: msgpack issue #99, giving bytes
            # additive store: keeps the other borg keys of this repository.
            store_key = getattr(target, "store_key", None)
            if store_key is not None:
                self._loaded_key_id = store_key(key_data)
            else:
                target.save_key(key_data)  # legacy repository: single borg key
                self._loaded_key_id = sha256(key_data).hexdigest()
        else:
            raise TypeError("Unsupported borg key storage type")
        self.target = target if self.storage != KeyBlobStorage.REPO else self.repository
        self._loaded_label = label

    def remove(self, target):
        if self.storage == KeyBlobStorage.KEYFILE:
            # the keyfile of the borg key we unlocked; other borg keys are separate files.
            # overwrite it with random data before unlinking (same as save() does for old keyfiles).
            secure_erase(target, avoid_collateral_damage=True)
        elif self.storage == KeyBlobStorage.REPO:
            # remove only the borg key we unlocked, leaving the repository's other borg keys alone.
            if hasattr(target, "delete_key") and self._loaded_key_id:
                target.delete_key(self._loaded_key_id)
            else:
                target.save_key(b"")  # legacy repository (single borg key)
        else:
            raise TypeError("Unsupported borg key storage type")

    def list_keys(self):
        """Return metadata for all borg keys of this repository (no decryption)."""
        result = []
        for key_id, blob_text, keyfile_path in self._iter_keys():
            # storage is a per-key property now, so report each key's actual mode (a repository may
            # hold a mix of keyfile- and repo-stored borg keys).
            mode = "keyfile" if keyfile_path is not None else "repokey"
            try:
                env = self._key_envelope(blob_text)
                label, algorithm = env.get("label"), env.get("algorithm")
            except Exception as exc:  # noqa: BLE001 - a corrupted borg key must stay visible and removable
                logger.warning("Borg key %s is corrupted (could not be parsed): %s", key_id[:12], exc)
                label, algorithm = None, "(corrupted)"
            result.append(
                {
                    "id": key_id,
                    "mode": mode,
                    "label": label,
                    "algorithm": algorithm,
                    "path": keyfile_path,
                    "current": key_id == self._loaded_key_id,
                }
            )
        return result

    def add_key(self, passphrase=None, label=None):
        """Add an additional borg key protecting the same key material with a new passphrase."""
        if self.storage == KeyBlobStorage.REPO and not hasattr(self.repository, "store_key"):
            raise Error("This repository type does not support multiple borg keys.")
        if self.storage == KeyBlobStorage.KEYFILE and os.environ.get("BORG_KEY_FILE"):
            raise Error(
                "Cannot add a borg key while BORG_KEY_FILE points to a single keyfile; "
                "unset it so the new keyfile can be stored in the keys directory."
            )
        if not label:
            raise Error("A label is required when adding a borg key (--label).")
        if label == ADMIN_LABEL:
            raise Error('The "%s" label is reserved for the borg key created at repository creation.' % ADMIN_LABEL)
        if label in {bk["label"] for bk in self.list_keys()}:
            raise Error("A borg key with label %r already exists." % label)
        if passphrase is None:
            passphrase = Passphrase.new(allow_empty=True)
        self.save(self.target, passphrase, algorithm=self._encrypted_key_algorithm, label=label, replace=False)

    def remove_key(self, *, label=None, key_id=None, current=False):
        """Remove a borg key. Selects by label, by key id prefix, or the current one."""
        keys = self.list_keys()
        if len(keys) <= 1:
            raise Error("Cannot remove the last remaining borg key of a repository.")
        if current:
            matches = [k for k in keys if k["id"] == self._loaded_key_id]
        elif key_id is not None:
            matches = [k for k in keys if k["id"].startswith(key_id)]
        elif label is not None:
            matches = [k for k in keys if k["label"] == label]
        else:
            raise Error("No borg key selector given (use --label, --key or --passphrase).")
        if len(matches) != 1:
            raise Error("The selector needs to match precisely 1 key, but it matched %d keys." % len(matches))
        victim = matches[0]
        if victim["label"] == ADMIN_LABEL:
            raise Error('The "%s" borg key is protected and cannot be removed.' % ADMIN_LABEL)
        # remove from the victim's own storage (which may differ from the unlocked key's storage)
        if victim["mode"] == "repokey":
            self.repository.delete_key(victim["id"])
        else:
            secure_erase(victim["path"], avoid_collateral_damage=True)  # overwrite the keyfile before unlinking
        return victim


class AuthenticatedKeyBase(AESKeyBase, FlexiKey):
    # default storage; an individual key's actual storage is tracked per-instance in self.storage.
    STORAGE = KeyBlobStorage.REPO
    # an authenticated-mode key has real key material (id/auth key) and a key blob, just no data
    # encryption. The blob may live as a keyfile or inside the repository, like the encrypted modes
    # (configurable via --key-location, changeable later via "borg key change-location").
    LOCATION_CONFIGURABLE = True

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

    def load_any(self, passphrase):
        success = super().load_any(passphrase)
        self.logically_encrypted = False
        return success

    def save(self, target, passphrase, algorithm, create=False, label=None, replace=True):
        super().save(target, passphrase, algorithm, create=create, label=label, replace=replace)
        self.logically_encrypted = False

    def init_ciphers(self, manifest_data=None):
        if manifest_data is not None:
            self.assert_type(manifest_data[0])

    def encrypt(self, id, data):
        return b"".join([self.TYPE_STR, data])

    def decrypt(self, id, data):
        self.assert_type(data[0], id)
        return memoryview(data)[1:]


# legacy imports placed after FlexiKey/AESKeyBase/KeyBase/AuthenticatedKeyBase so those names are already
# in the partial module when legacy/crypto/key.py imports them back during circular load
from ..legacy.crypto.key import AESCTRKey, Blake2AESCTRKey  # noqa: F401
from ..legacy.crypto.key import Blake2AuthenticatedKey  # noqa: F401
from ..legacy.crypto.key import LEGACY_KEY_TYPES  # noqa: E402
from ..legacy.crypto.key import ID_BLAKE2b_256  # noqa: F401


class AuthenticatedKey(ID_HMAC_SHA_256, AuthenticatedKeyBase):
    TYPE = KeyType.AUTHENTICATED
    TYPES_ACCEPTABLE = {TYPE}
    ENC_NAME = "authenticated"  # IDHASH_NAME = "sha256" via ID_HMAC_SHA_256 mix-in


# ------------ new crypto ------------


class ID_BLAKE3_256:
    """
    Key mix-in class for using BLAKE3 for the id key.

    The id_key length must be 32 bytes.
    """

    IDHASH_NAME = "blake3"

    def id_hash(self, data):
        return blake3(data, key=self.id_key).digest(length=32)


class Blake3AuthenticatedKey(ID_BLAKE3_256, AuthenticatedKeyBase):
    TYPE = KeyType.BLAKE3AUTHENTICATED
    TYPES_ACCEPTABLE = {TYPE}
    ENC_NAME = "authenticated"  # IDHASH_NAME = "blake3" via ID_BLAKE3_256 mix-in


class AEADKeyBase(KeyBase):
    """
    Chunks are encrypted and authenticated using some AEAD ciphersuite

    Layout: suite:4 keytype:4 reserved:8 messageIV:48 sessionID:192 auth_tag:128 payload:... [bits]
            ^-------------------- AAD ----------------------------^
    Offsets:0                 1          2            8             32           48 [bytes]

    suite: 1010b for new AEAD crypto, 0000b is old crypto
    keytype: always 0 for new crypto (the key storage location is no longer encoded in the type byte)
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

    # default storage; an individual key's actual storage is tracked per-instance in self.storage.
    STORAGE = KeyBlobStorage.REPO
    # an AEAD key may be stored as a keyfile or inside the repository (see borg key change-location).
    LOCATION_CONFIGURABLE = True

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


# Each of these is one unified key class per crypto suite. A key of this class may be stored either as
# a keyfile or inside the repository (repokey) - that is a per-key storage property (self.storage), not
# a class distinction. The class is selected from the manifest's key-type byte (see identify_key), which
# only encodes the crypto suite (there is exactly one type byte per suite now).


class AESOCBKey(ID_HMAC_SHA_256, AEADKeyBase, FlexiKey):
    TYPE = KeyType.AESOCB
    TYPES_ACCEPTABLE = {TYPE}
    ENC_NAME = "aes256-ocb"  # IDHASH_NAME = "sha256" via ID_HMAC_SHA_256 mix-in
    CIPHERSUITE = AES256_OCB


class CHPOKey(ID_HMAC_SHA_256, AEADKeyBase, FlexiKey):
    TYPE = KeyType.CHPO
    TYPES_ACCEPTABLE = {TYPE}
    ENC_NAME = "chacha20-poly1305"  # IDHASH_NAME = "sha256" via ID_HMAC_SHA_256 mix-in
    CIPHERSUITE = CHACHA20_POLY1305


class Blake3AESOCBKey(ID_BLAKE3_256, AEADKeyBase, FlexiKey):
    TYPE = KeyType.BLAKE3AESOCB
    TYPES_ACCEPTABLE = {TYPE}
    ENC_NAME = "aes256-ocb"  # IDHASH_NAME = "blake3" via ID_BLAKE3_256 mix-in
    CIPHERSUITE = AES256_OCB


class Blake3CHPOKey(ID_BLAKE3_256, AEADKeyBase, FlexiKey):
    TYPE = KeyType.BLAKE3CHPO
    TYPES_ACCEPTABLE = {TYPE}
    ENC_NAME = "chacha20-poly1305"  # IDHASH_NAME = "blake3" via ID_BLAKE3_256 mix-in
    CIPHERSUITE = CHACHA20_POLY1305


AVAILABLE_KEY_TYPES = (
    # these are available encryption modes for new repositories
    # not encrypted modes
    PlaintextKey,
    AuthenticatedKey,
    # new crypto
    Blake3AuthenticatedKey,
    AESOCBKey,
    CHPOKey,
    Blake3AESOCBKey,
    Blake3CHPOKey,
)

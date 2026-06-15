import hmac
import os
from hashlib import pbkdf2_hmac

from ...constants import *  # NOQA
from ...crypto.low_level import AES256_CTR_HMAC_SHA256, AES256_CTR_BLAKE2b, hmac_sha256, blake2b_256
from ...crypto.key import ID_HMAC_SHA_256, AESKeyBase, FlexiKey, AuthenticatedKeyBase, UnsupportedKeyFormatError
from ...helpers import get_limited_unpacker, msgpack
from ...item import EncryptedKey
from .low_level import AES


class Pbkdf2FileMixin:
    """Mixin for borg 1.x key files encrypted with PBKDF2 + AES-CTR."""

    @staticmethod
    def pbkdf2(passphrase, salt, iterations, output_len_in_bytes):
        if os.environ.get("BORG_TESTONLY_WEAKEN_KDF") == "1":
            iterations = 1
        return pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations, output_len_in_bytes)

    def decrypt_key_file(self, data, passphrase):
        unpacker = get_limited_unpacker("key")
        unpacker.feed(data)
        unpacked = unpacker.unpack()
        encrypted_key = EncryptedKey(internal_dict=unpacked)
        if encrypted_key.version != 1:
            raise UnsupportedKeyFormatError()
        self._encrypted_key_algorithm = encrypted_key.algorithm
        if encrypted_key.algorithm == "sha256":
            return self.decrypt_key_file_pbkdf2(encrypted_key, passphrase)
        return super().decrypt_key_file(data, passphrase)

    def encrypt_key_file(self, data, passphrase, algorithm, label=None):
        if algorithm == "sha256":
            return self.encrypt_key_file_pbkdf2(data, passphrase)
        return super().encrypt_key_file(data, passphrase, algorithm, label=label)

    def decrypt_key_file_pbkdf2(self, encrypted_key, passphrase):
        key = self.pbkdf2(passphrase, encrypted_key.salt, encrypted_key.iterations, 32)
        data = AES(key, b"\0" * 16).decrypt(encrypted_key.data)
        if hmac.compare_digest(hmac_sha256(key, data), encrypted_key.hash):
            return data
        return None

    def encrypt_key_file_pbkdf2(self, data, passphrase):
        salt = os.urandom(32)
        iterations = PBKDF2_ITERATIONS
        key = self.pbkdf2(passphrase, salt, iterations, 32)
        hash = hmac_sha256(key, data)
        cdata = AES(key, b"\0" * 16).encrypt(data)
        enc_key = EncryptedKey(version=1, salt=salt, iterations=iterations, algorithm="sha256", hash=hash, data=cdata)
        return msgpack.packb(enc_key.as_dict())


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

    IDHASH_NAME = "blake2"

    def id_hash(self, data):
        return blake2b_256(self.id_key, data)

    def init_from_random_data(self):
        super().init_from_random_data()
        enc_key = os.urandom(32)
        enc_hmac_key = random_blake2b_256_key()
        self.crypt_key = enc_key + enc_hmac_key
        self.id_key = random_blake2b_256_key()


class Blake2AuthenticatedKey(ID_BLAKE2b_256, AuthenticatedKeyBase):  # type: ignore[misc]
    TYPE = KeyType.BLAKE2AUTHENTICATED
    TYPES_ACCEPTABLE = {TYPE}
    NAME = "authenticated BLAKE2b"
    ENC_NAME = "authenticated"  # IDHASH_NAME = "blake2" via ID_BLAKE2b_256 mix-in; read-only (borg 1.x)


# borg 1.x AES-CTR keys. keyfile and repokey are no longer separate classes - storage is a per-key
# property (self.storage), tracked when the key is loaded. These classes are read-only (borg 2 only
# reads borg 1.x repos, e.g. via borg transfer; it never creates them), so the canonical TYPE byte is
# never written - only TYPES_ACCEPTABLE matters, and it keeps the historic keyfile/repokey/passphrase bytes.


class AESCTRKey(Pbkdf2FileMixin, ID_HMAC_SHA_256, AESKeyBase, FlexiKey):  # type: ignore[misc]
    TYPES_ACCEPTABLE = {KeyType.KEYFILE, KeyType.REPO, KeyType.PASSPHRASE}
    TYPE = KeyType.KEYFILE
    NAME = "AES-CTR HMAC-SHA256"
    ENC_NAME = "aes256-ctr"  # IDHASH_NAME = "sha256" via ID_HMAC_SHA_256 mix-in; read-only (borg 1.x)
    STORAGE = KeyBlobStorage.REPO  # seed default; actual per-key storage is tracked in self.storage on load
    LOCATION_CONFIGURABLE = True  # borg 1.x had keyfile and repokey variants
    CIPHERSUITE = AES256_CTR_HMAC_SHA256


class Blake2AESCTRKey(Pbkdf2FileMixin, ID_BLAKE2b_256, AESKeyBase, FlexiKey):  # type: ignore[misc]
    TYPES_ACCEPTABLE = {KeyType.BLAKE2KEYFILE, KeyType.BLAKE2REPO}
    TYPE = KeyType.BLAKE2KEYFILE
    NAME = "AES-CTR BLAKE2b"
    ENC_NAME = "aes256-ctr"  # IDHASH_NAME = "blake2" via ID_BLAKE2b_256 mix-in; read-only (borg 1.x)
    STORAGE = KeyBlobStorage.REPO  # seed default; actual per-key storage is tracked in self.storage on load
    LOCATION_CONFIGURABLE = True  # borg 1.x had keyfile and repokey variants
    CIPHERSUITE = AES256_CTR_BLAKE2b


LEGACY_KEY_TYPES = (AESCTRKey, Blake2AESCTRKey, Blake2AuthenticatedKey)

import hmac
import os

from ...constants import *  # NOQA
from ...crypto.low_level import AES256_CTR_HMAC_SHA256, AES256_CTR_BLAKE2b, hmac_sha256
from ...crypto.key import ID_HMAC_SHA_256, ID_BLAKE2b_256, AESKeyBase, FlexiKey, UnsupportedKeyFormatError
from ...helpers import get_limited_unpacker, msgpack
from ...item import EncryptedKey
from .low_level import AES


class Pbkdf2FileMixin:
    """Mixin for borg 1.x key files encrypted with PBKDF2 + AES-CTR."""

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

    def encrypt_key_file(self, data, passphrase, algorithm):
        if algorithm == "sha256":
            return self.encrypt_key_file_pbkdf2(data, passphrase)
        return super().encrypt_key_file(data, passphrase, algorithm)

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


class KeyfileKey(Pbkdf2FileMixin, ID_HMAC_SHA_256, AESKeyBase, FlexiKey):  # type: ignore[misc]
    TYPES_ACCEPTABLE = {KeyType.KEYFILE, KeyType.REPO, KeyType.PASSPHRASE}
    TYPE = KeyType.KEYFILE
    NAME = "key file"
    ARG_NAME = "keyfile"
    STORAGE = KeyBlobStorage.KEYFILE
    CIPHERSUITE = AES256_CTR_HMAC_SHA256


class RepoKey(Pbkdf2FileMixin, ID_HMAC_SHA_256, AESKeyBase, FlexiKey):  # type: ignore[misc]
    TYPES_ACCEPTABLE = {KeyType.KEYFILE, KeyType.REPO, KeyType.PASSPHRASE}
    TYPE = KeyType.REPO
    NAME = "repokey"
    ARG_NAME = "repokey"
    STORAGE = KeyBlobStorage.REPO
    CIPHERSUITE = AES256_CTR_HMAC_SHA256


class Blake2KeyfileKey(Pbkdf2FileMixin, ID_BLAKE2b_256, AESKeyBase, FlexiKey):  # type: ignore[misc]
    TYPES_ACCEPTABLE = {KeyType.BLAKE2KEYFILE, KeyType.BLAKE2REPO}
    TYPE = KeyType.BLAKE2KEYFILE
    NAME = "key file BLAKE2b"
    ARG_NAME = "keyfile-blake2"
    STORAGE = KeyBlobStorage.KEYFILE
    CIPHERSUITE = AES256_CTR_BLAKE2b


class Blake2RepoKey(Pbkdf2FileMixin, ID_BLAKE2b_256, AESKeyBase, FlexiKey):  # type: ignore[misc]
    TYPES_ACCEPTABLE = {KeyType.BLAKE2KEYFILE, KeyType.BLAKE2REPO}
    TYPE = KeyType.BLAKE2REPO
    NAME = "repokey BLAKE2b"
    ARG_NAME = "repokey-blake2"
    STORAGE = KeyBlobStorage.REPO
    CIPHERSUITE = AES256_CTR_BLAKE2b


LEGACY_KEY_TYPES = (KeyfileKey, RepoKey, Blake2KeyfileKey, Blake2RepoKey)

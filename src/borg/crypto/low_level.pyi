# Type stubs for borg.crypto.low_level
# This file provides type hints for the Cython extension module

from typing import Optional, Union

API_VERSION: str

# Module-level functions
def num_cipher_blocks(length: int, blocksize: int = 16) -> int:
    """Return the number of cipher blocks required to encrypt/decrypt <length> bytes of data."""
    ...

def bytes_to_int(x: bytes, offset: int = 0) -> int: ...
def bytes_to_long(x: bytes, offset: int = 0) -> int: ...
def long_to_bytes(x: int) -> bytes: ...
def hmac_sha256(key: bytes, data: bytes) -> bytes: ...
def blake2b_256(key: bytes, data: bytes) -> bytes: ...
def blake2b_128(data: bytes) -> bytes: ...

# Exception classes
class CryptoError(Exception):
    """Malfunction in the crypto module."""

    ...

class IntegrityError(CryptoError):
    """Integrity checks failed. Corrupted or tampered data."""

    ...

# Cipher classes
class UNENCRYPTED:
    """Unencrypted cipher suite (no encryption, no MAC)."""

    header_len: int
    iv: Optional[Union[int, bytes]]

    def __init__(
        self,
        mac_key: None,
        enc_key: None,
        iv: Optional[Union[int, bytes]] = None,
        header_len: int = 1,
        aad_offset: int = 1,
    ) -> None: ...
    def encrypt(
        self, data: bytes, header: bytes = b"", iv: Optional[Union[int, bytes]] = None, aad: Optional[bytes] = None
    ) -> bytes: ...
    def decrypt(self, envelope: bytes, aad: Optional[bytes] = None) -> memoryview: ...
    def block_count(self, length: int) -> int: ...
    def set_iv(self, iv: Union[int, bytes]) -> None: ...
    def next_iv(self) -> Union[int, bytes]: ...
    def extract_iv(self, envelope: bytes) -> int: ...

class AES256_CTR_BASE:
    """Base class for AES-256-CTR based cipher suites."""

    @classmethod
    def requirements_check(cls) -> None: ...
    def __init__(
        self,
        mac_key: bytes,
        enc_key: bytes,
        iv: Optional[Union[int, bytes]] = None,
        header_len: int = 1,
        aad_offset: int = 1,
    ) -> None: ...
    def encrypt(
        self, data: bytes, header: bytes = b"", iv: Optional[Union[int, bytes]] = None, aad: Optional[bytes] = None
    ) -> bytes: ...
    def decrypt(self, envelope: bytes, aad: Optional[bytes] = None) -> bytes: ...
    def block_count(self, length: int) -> int: ...
    def set_iv(self, iv: Union[int, bytes]) -> None: ...
    def next_iv(self) -> int: ...
    def extract_iv(self, envelope: bytes) -> int: ...

class AES256_CTR_HMAC_SHA256(AES256_CTR_BASE):
    """AES-256-CTR with HMAC-SHA256 authentication."""

    def __init__(
        self,
        mac_key: bytes,
        enc_key: bytes,
        iv: Optional[Union[int, bytes]] = None,
        header_len: int = 1,
        aad_offset: int = 1,
    ) -> None: ...

class AES256_CTR_BLAKE2b(AES256_CTR_BASE):
    """AES-256-CTR with BLAKE2b authentication."""

    def __init__(
        self,
        mac_key: bytes,
        enc_key: bytes,
        iv: Optional[Union[int, bytes]] = None,
        header_len: int = 1,
        aad_offset: int = 1,
    ) -> None: ...

class _AEAD_BASE:
    """Base class for AEAD cipher suites."""

    @classmethod
    def requirements_check(cls) -> None:
        """Check whether library requirements for this ciphersuite are satisfied."""
        ...

    def __init__(
        self, key: bytes, iv: Optional[Union[int, bytes]] = None, header_len: int = 0, aad_offset: int = 0
    ) -> None: ...
    def encrypt(
        self, data: bytes, header: bytes = b"", iv: Optional[Union[int, bytes]] = None, aad: bytes = b""
    ) -> bytes: ...
    def decrypt(self, envelope: bytes, aad: bytes = b"") -> bytes: ...
    def block_count(self, length: int) -> int: ...
    def set_iv(self, iv: Union[int, bytes]) -> None: ...
    def next_iv(self) -> int: ...

class AES256_OCB(_AEAD_BASE):
    """AES-256-OCB AEAD cipher suite."""

    @classmethod
    def requirements_check(cls) -> None: ...
    def __init__(
        self, key: bytes, iv: Optional[Union[int, bytes]] = None, header_len: int = 0, aad_offset: int = 0
    ) -> None: ...

class CHACHA20_POLY1305(_AEAD_BASE):
    """ChaCha20-Poly1305 AEAD cipher suite."""

    @classmethod
    def requirements_check(cls) -> None: ...
    def __init__(
        self, key: bytes, iv: Optional[Union[int, bytes]] = None, header_len: int = 0, aad_offset: int = 0
    ) -> None: ...

class AES:
    """A thin wrapper around the OpenSSL EVP cipher API - for legacy code, like key file encryption."""

    def __init__(self, enc_key: bytes, iv: Optional[Union[int, bytes]] = None) -> None: ...
    def encrypt(self, data: bytes, iv: Optional[Union[int, bytes]] = None) -> bytes: ...
    def decrypt(self, data: bytes) -> bytes: ...
    def block_count(self, length: int) -> int: ...
    def set_iv(self, iv: Union[int, bytes]) -> None: ...
    def next_iv(self) -> int: ...

class CSPRNG:
    """
    Cryptographically Secure Pseudo-Random Number Generator based on AES-CTR mode.

    This class provides methods for generating random bytes and shuffling lists
    using a deterministic algorithm seeded with a 256-bit key.
    """

    def __init__(self, seed_key: bytes) -> None:
        """
        Initialize the CSPRNG with a 256-bit key.

        :param seed_key: A 32-byte key used as the seed for the CSPRNG
        """
        ...

    def random_bytes(self, n: int) -> bytes:
        """
        Generate n random bytes.

        :param n: Number of bytes to generate
        :return: a bytes object containing the random bytes
        """
        ...

    def random_int(self, n: int) -> int:
        """
        Generate a random integer in the range [0, n).

        :param n: Upper bound (exclusive)
        :return: Random integer
        """
        ...

    def shuffle(self, items: list) -> None:
        """
        Shuffle a list in-place using the Fisher-Yates algorithm.

        :param items: List to shuffle
        """
        ...

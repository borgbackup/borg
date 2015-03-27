from binascii import hexlify, a2b_base64, b2a_base64
from getpass import getpass
import os
import msgpack
import textwrap
from collections import namedtuple
import hmac
from hashlib import sha256, sha512
import zlib

try:
    import lzma  # python >= 3.3
except ImportError:
    try:
        from backports import lzma  # backports.lzma from pypi
    except ImportError:
        lzma = None

try:
    import blosc
except ImportError:
    blosc = None

from attic.crypto import pbkdf2_sha256, get_random_bytes, AES, AES_CTR_MODE, AES_GCM_MODE, \
    bytes_to_int, increment_iv
from attic.helpers import IntegrityError, get_keys_dir, Error

# we do not store the full IV on disk, as the upper 8 bytes are expected to be
# zero anyway as the full IV is a 128bit counter. PREFIX are the upper 8 bytes,
# stored_iv are the lower 8 Bytes.
PREFIX = b'\0' * 8
Meta = namedtuple('Meta', 'compr_type, key_type, mac_type, cipher_type, iv, legacy')


class UnsupportedPayloadError(Error):
    """Unsupported payload type {}. A newer version is required to access this repository.
    """

class sha512_256(object):  # note: can't subclass sha512
    """sha512, but digest truncated to 256bit - faster than sha256 on 64bit platforms"""
    digestsize = digest_size = 32
    block_size = 64

    def __init__(self, data=None):
        self.name = 'sha512-256'
        self._h = sha512()
        if data:
            self.update(data)

    def update(self, data):
        self._h.update(data)

    def digest(self):
        return self._h.digest()[:self.digest_size]

    def hexdigest(self):
        return self._h.hexdigest()[:self.digest_size * 2]

    def copy(self):
        new = sha512_256.__new__(sha512_256)
        new._h = self._h.copy()
        return new


class HMAC(hmac.HMAC):
    """Workaround a bug in Python < 3.4 Where HMAC does not accept memoryviews
    """
    def update(self, msg):
        self.inner.update(msg)


# HASH / MAC stuff below all has a mac-like interface, so it can be used in the same way.
# special case: hashes do not use keys (and thus, do not sign/authenticate)

class SHA256(object):  # note: can't subclass sha256
    TYPE = 0
    digest_size = 32

    def __init__(self, key, data=b''):
        # signature is like for a MAC, we ignore the key as this is a simple hash
        if key is not None:
            raise Exception("use a HMAC if you have a key")
        self.h = sha256(data)

    def update(self, data):
        self.h.update(data)

    def digest(self):
        return self.h.digest()

    def hexdigest(self):
        return self.h.hexdigest()


class SHA512_256(sha512_256):
    """sha512, but digest truncated to 256bit - faster than sha256 on 64bit platforms"""
    TYPE = 1
    digest_size = 32

    def __init__(self, key, data):
        # signature is like for a MAC, we ignore the key as this is a simple hash
        if key is not None:
            raise Exception("use a HMAC if you have a key")
        super().__init__(data)


class GHASH:
    TYPE = 2
    digest_size = 16

    def __init__(self, key, data):
        # signature is like for a MAC, we ignore the key as this is a simple hash
        if key is not None:
            raise Exception("use a MAC if you have a key")
        self.key = b'\0' * 32
        self.data = data

    def digest(self):
        mac_cipher = AES(mode=AES_GCM_MODE, is_encrypt=True, key=self.key, iv=b'\0' * 16)
        # GMAC = aes-gcm with all data as AAD, no data as to-be-encrypted data
        mac_cipher.add(bytes(self.data))
        hash, _ = mac_cipher.compute_mac_and_encrypt(b'')
        return hash


class HMAC_SHA256(HMAC):
    TYPE = 10
    digest_size = 32

    def __init__(self, key, data):
        if key is None:
            raise Exception("do not use HMAC if you don't have a key")
        super().__init__(key, data, sha256)


class HMAC_SHA512_256(HMAC):
    TYPE = 11
    digest_size = 32

    def __init__(self, key, data):
        if key is None:
            raise Exception("do not use HMAC if you don't have a key")
        super().__init__(key, data, sha512_256)


class GMAC(GHASH):
    TYPE = 20
    digest_size = 16

    def __init__(self, key, data):
        super().__init__(None, data)
        if key is None:
            raise Exception("do not use GMAC if you don't have a key")
        self.key = key


# defaults are optimized for speed on modern CPUs with AES hw support
HASH_DEFAULT = GHASH.TYPE
MAC_DEFAULT = GMAC.TYPE


# compressor classes, all same interface
# special case: zlib level 0 is "no compression"

class NullCompressor(object):  # uses 0 in the mapping
    TYPE = 0

    def compress(self, data):
        return bytes(data)

    def decompress(self, data):
        return bytes(data)


class ZlibCompressor(object):  # uses 1..9 in the mapping
    TYPE = 0
    LEVELS = range(10)

    def compress(self, data):
        level = self.TYPE - ZlibCompressor.TYPE
        return zlib.compress(data, level)

    def decompress(self, data):
        return zlib.decompress(data)


class LzmaCompressor(object):  # uses 10..19 in the mapping
    TYPE = 10
    PRESETS = range(10)

    def __init__(self):
        if lzma is None:
            raise NotImplemented("lzma compression needs Python >= 3.3 or backports.lzma from PyPi")

    def compress(self, data):
        preset = self.TYPE - LzmaCompressor.TYPE
        return lzma.compress(data, preset=preset)

    def decompress(self, data):
        return lzma.decompress(data)


class BLOSCCompressor(object):
    TYPE = 0  # override in subclass
    LEVELS = range(10)
    CNAME = ''  # override in subclass

    def __init__(self):
        if blosc is None:
            raise NotImplemented("%s compression needs blosc from PyPi" % self.CNAME)
        if self.CNAME not in blosc.compressor_list():
            raise NotImplemented("%s compression is not supported by blosc" % self.CNAME)
        blosc.set_blocksize(16384)  # 16kiB is the minimum, so 64kiB are enough for 4 threads

    def _get_level(self):
        raise NotImplemented

    def compress(self, data):
        return blosc.compress(bytes(data), 1, cname=self.CNAME, clevel=self._get_level())

    def decompress(self, data):
        return blosc.decompress(data)


class LZ4Compressor(BLOSCCompressor):
    TYPE = 20
    CNAME = 'lz4'

    def _get_level(self):
        return self.TYPE - LZ4Compressor.TYPE


class LZ4HCCompressor(BLOSCCompressor):
    TYPE = 30
    CNAME = 'lz4hc'

    def _get_level(self):
        return self.TYPE - LZ4HCCompressor.TYPE


class BLOSCLZCompressor(BLOSCCompressor):
    TYPE = 40
    CNAME = 'blosclz'

    def _get_level(self):
        return self.TYPE - BLOSCLZCompressor.TYPE


class SnappyCompressor(BLOSCCompressor):
    TYPE = 50
    CNAME = 'snappy'

    def _get_level(self):
        return self.TYPE - SnappyCompressor.TYPE


class BLOSCZlibCompressor(BLOSCCompressor):
    TYPE = 60
    CNAME = 'zlib'

    def _get_level(self):
        return self.TYPE - BLOSCZlibCompressor.TYPE


# default is optimized for speed
COMPR_DEFAULT = NullCompressor.TYPE # no compression


# ciphers - AEAD (authenticated encryption with assoc. data) style interface
# special case: PLAIN dummy does not encrypt / authenticate

class PLAIN:
    TYPE = 0
    enc_iv = None  # dummy

    def __init__(self, **kw):
        pass

    def compute_mac_and_encrypt(self, meta, data):
        return None, data

    def check_mac_and_decrypt(self, mac, meta, data):
        return data


def get_aad(meta):
    """get additional authenticated data for AEAD ciphers"""
    if meta.legacy:
        # legacy format computed the mac over (iv_last8 +  data)
        return meta.iv[8:]
    else:
        return msgpack.packb(meta)


class AES_CTR_HMAC:
    TYPE = 1

    def __init__(self, enc_key=b'\0' * 32, enc_iv=b'\0' * 16, enc_hmac_key=b'\0' * 32, **kw):
        self.hmac_key = enc_hmac_key
        self.enc_iv = enc_iv
        self.enc_cipher = AES(mode=AES_CTR_MODE, is_encrypt=True, key=enc_key, iv=enc_iv)
        self.dec_cipher = AES(mode=AES_CTR_MODE, is_encrypt=False, key=enc_key)

    def compute_mac_and_encrypt(self, meta, data):
        self.enc_cipher.reset(iv=meta.iv)
        _, data = self.enc_cipher.compute_mac_and_encrypt(data)
        self.enc_iv = increment_iv(meta.iv, len(data))
        aad = get_aad(meta)
        mac = HMAC(self.hmac_key, aad + data, sha256).digest()  # XXX mac / hash flexibility
        return mac, data

    def check_mac_and_decrypt(self, mac, meta, data):
        aad = get_aad(meta)
        if HMAC(self.hmac_key, aad + data, sha256).digest() != mac:
            raise IntegrityError('Encryption envelope checksum mismatch')
        self.dec_cipher.reset(iv=meta.iv)
        data = self.dec_cipher.check_mac_and_decrypt(None, data)
        return data


class AES_GCM:
    TYPE = 2

    def __init__(self, enc_key=b'\0' * 32, enc_iv=b'\0' * 16, **kw):
        # note: hmac_key is not used for aes-gcm, it does aes+gmac in 1 pass
        self.enc_iv = enc_iv
        self.enc_cipher = AES(mode=AES_GCM_MODE, is_encrypt=True, key=enc_key, iv=enc_iv)
        self.dec_cipher = AES(mode=AES_GCM_MODE, is_encrypt=False, key=enc_key)

    def compute_mac_and_encrypt(self, meta, data):
        self.enc_cipher.reset(iv=meta.iv)
        aad = get_aad(meta)
        self.enc_cipher.add(aad)
        mac, data = self.enc_cipher.compute_mac_and_encrypt(data)
        self.enc_iv = increment_iv(meta.iv, len(data))
        return mac, data

    def check_mac_and_decrypt(self, mac, meta, data):
        self.dec_cipher.reset(iv=meta.iv)
        aad = get_aad(meta)
        self.dec_cipher.add(aad)
        try:
            data = self.dec_cipher.check_mac_and_decrypt(mac, data)
        except Exception:
            raise IntegrityError('Encryption envelope checksum mismatch')
        return data


# cipher default is optimized for speed on modern CPUs with AES hw support
PLAIN_DEFAULT = PLAIN.TYPE
CIPHER_DEFAULT = AES_GCM.TYPE


# misc. types of keys
# special case: no keys (thus: no encryption, no signing/authentication)

class KeyBase(object):
    TYPE = 0x00  # override in derived classes

    def __init__(self, compressor_cls, maccer_cls, cipher_cls):
        self.compressor = compressor_cls()
        self.maccer_cls = maccer_cls  # hasher/maccer used by id_hash
        self.cipher_cls = cipher_cls  # plaintext dummy or AEAD cipher
        self.cipher = cipher_cls()
        self.id_key = None

    def id_hash(self, data):
        """Return a HASH (no id_key) or a MAC (using the "id_key" key)

        XXX do we need a cryptographic hash function here or is a keyed hash
        function like GMAC / GHASH good enough? See NIST SP 800-38D.

        IMPORTANT: in 1 repo, there should be only 1 kind of id_hash, otherwise
        data hashed/maced with one id_hash might result in same ID as already
        exists in the repo for other data created with another id_hash method.
        somehow unlikely considering 128 or 256bits, but still.
        """
        return self.maccer_cls(self.id_key, data).digest()

    def encrypt(self, data):
        data = self.compressor.compress(data)
        meta = Meta(compr_type=self.compressor.TYPE, key_type=self.TYPE,
                    mac_type=self.maccer_cls.TYPE, cipher_type=self.cipher.TYPE,
                    iv=self.cipher.enc_iv, legacy=False)
        mac, data = self.cipher.compute_mac_and_encrypt(meta, data)
        return generate(mac, meta, data)

    def decrypt(self, id, data):
        mac, meta, data = parser(data)
        compressor, keyer, maccer, cipher = get_implementations(meta)
        assert isinstance(self, keyer)
        assert self.maccer_cls is maccer
        assert self.cipher_cls is cipher
        data = self.cipher.check_mac_and_decrypt(mac, meta, data)
        data = self.compressor.decompress(data)
        if id and self.id_hash(data) != id:
            raise IntegrityError('Chunk id verification failed')
        return data


class PlaintextKey(KeyBase):
    TYPE = 0x02

    chunk_seed = 0

    @classmethod
    def create(cls, repository, args):
        print('Encryption NOT enabled.\nUse the "--encryption=passphrase|keyfile" to enable encryption.')
        compressor = compressor_creator(args)
        maccer = maccer_creator(args, cls)
        cipher = cipher_creator(args, cls)
        return cls(compressor, maccer, cipher)

    @classmethod
    def detect(cls, repository, manifest_data):
        mac, meta, data = parser(manifest_data)
        compressor, keyer, maccer, cipher = get_implementations(meta)
        return cls(compressor, maccer, cipher)


class AESKeyBase(KeyBase):
    """Common base class shared by KeyfileKey and PassphraseKey

    Chunks are encrypted using 256bit AES in CTR or GCM mode.
    Chunks are authenticated by a GCM GMAC or a HMAC.

    Payload layout: TYPE(1) + MAC(32) + NONCE(8) + CIPHERTEXT

    To reduce payload size only 8 bytes of the 16 bytes nonce is saved
    in the payload, the first 8 bytes are always zeros. This does not
    affect security but limits the maximum repository capacity to
    only 295 exabytes!
    """
    def extract_iv(self, payload):
        _, meta, _ = parser(payload)
        return meta.iv

    def init_from_random_data(self, data):
        self.enc_key = data[0:32]
        self.enc_hmac_key = data[32:64]
        self.id_key = data[64:96]
        self.chunk_seed = bytes_to_int(data[96:100])
        # Convert to signed int32
        if self.chunk_seed & 0x80000000:
            self.chunk_seed = self.chunk_seed - 0xffffffff - 1

    def init_ciphers(self, enc_iv=b'\0' * 16):
        self.cipher = self.cipher_cls(enc_key=self.enc_key, enc_iv=enc_iv,
                                      enc_hmac_key=self.enc_hmac_key)

    @property
    def enc_iv(self):
        return self.cipher.enc_iv


class PassphraseKey(AESKeyBase):
    TYPE = 0x01
    iterations = 100000

    @classmethod
    def create(cls, repository, args):
        compressor = compressor_creator(args)
        maccer = maccer_creator(args, cls)
        cipher = cipher_creator(args, cls)
        key = cls(compressor, maccer, cipher)
        passphrase = os.environ.get('ATTIC_PASSPHRASE')
        if passphrase is not None:
            passphrase2 = passphrase
        else:
            passphrase, passphrase2 = 1, 2
        while passphrase != passphrase2:
            passphrase = getpass('Enter passphrase: ')
            if not passphrase:
                print('Passphrase must not be blank')
                continue
            passphrase2 = getpass('Enter same passphrase again: ')
            if passphrase != passphrase2:
                print('Passphrases do not match')
        key.init(repository, passphrase)
        if passphrase:
            print('Remember your passphrase. Your data will be inaccessible without it.')
        return key

    @classmethod
    def detect(cls, repository, manifest_data):
        prompt = 'Enter passphrase for %s: ' % repository._location.orig
        mac, meta, data = parser(manifest_data)
        compressor, keyer, maccer, cipher = get_implementations(meta)
        key = cls(compressor, maccer, cipher)
        passphrase = os.environ.get('ATTIC_PASSPHRASE')
        if passphrase is None:
            passphrase = getpass(prompt)
        while True:
            key.init(repository, passphrase)
            try:
                key.decrypt(None, manifest_data)
                key.init_ciphers(increment_iv(key.extract_iv(manifest_data), len(data)))
                return key
            except IntegrityError:
                passphrase = getpass(prompt)

    def change_passphrase(self):
        class ImmutablePassphraseError(Error):
            """The passphrase for this encryption key type can't be changed."""

        raise ImmutablePassphraseError

    def init(self, repository, passphrase):
        self.init_from_random_data(pbkdf2_sha256(passphrase.encode('utf-8'), repository.id, self.iterations, 100))
        self.init_ciphers()


class KeyfileKey(AESKeyBase):
    FILE_ID = 'ATTIC KEY'
    TYPE = 0x00

    @classmethod
    def detect(cls, repository, manifest_data):
        mac, meta, data = parser(manifest_data)
        compressor, keyer, maccer, cipher = get_implementations(meta)
        key = cls(compressor, maccer, cipher)
        path = cls.find_key_file(repository)
        prompt = 'Enter passphrase for key file %s: ' % path
        passphrase = os.environ.get('ATTIC_PASSPHRASE', '')
        while not key.load(path, passphrase):
            passphrase = getpass(prompt)
        key.init_ciphers(increment_iv(key.extract_iv(manifest_data), len(data)))
        return key

    @classmethod
    def find_key_file(cls, repository):
        id = hexlify(repository.id).decode('ascii')
        keys_dir = get_keys_dir()
        for name in os.listdir(keys_dir):
            filename = os.path.join(keys_dir, name)
            with open(filename, 'r') as fd:
                line = fd.readline().strip()
                if line and line.startswith(cls.FILE_ID) and line[10:] == id:
                    return filename
        raise Exception('Key file for repository with ID %s not found' % id)

    def load(self, filename, passphrase):
        with open(filename, 'r') as fd:
            cdata = a2b_base64(''.join(fd.readlines()[1:]).encode('ascii'))  # .encode needed for Python 3.[0-2]
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
            self.path = filename
            return True

    def decrypt_key_file(self, data, passphrase):
        d = msgpack.unpackb(data)
        assert d[b'version'] == 1
        assert d[b'algorithm'] == b'gmac'
        key = pbkdf2_sha256(passphrase.encode('utf-8'), d[b'salt'], d[b'iterations'], 32)
        try:
            cipher = AES(mode=AES_GCM_MODE, is_encrypt=False, key=key, iv=b'\0'*16)
            data = cipher.check_mac_and_decrypt(d[b'hash'], d[b'data'])
            return data
        except Exception:
            return None

    def encrypt_key_file(self, data, passphrase):
        salt = get_random_bytes(32)
        iterations = 100000
        key = pbkdf2_sha256(passphrase.encode('utf-8'), salt, iterations, 32)
        cipher = AES(mode=AES_GCM_MODE, is_encrypt=True, key=key, iv=b'\0'*16)
        mac, cdata = cipher.compute_mac_and_encrypt(data)
        d = {
            'version': 1,
            'salt': salt,
            'iterations': iterations,
            'algorithm': 'gmac',
            'hash': mac,
            'data': cdata,
        }
        return msgpack.packb(d)

    def save(self, path, passphrase):
        key = {
            'version': 1,
            'repository_id': self.repository_id,
            'enc_key': self.enc_key,
            'enc_hmac_key': self.enc_hmac_key,
            'id_key': self.id_key,
            'chunk_seed': self.chunk_seed,
        }
        data = self.encrypt_key_file(msgpack.packb(key), passphrase)
        with open(path, 'w') as fd:
            fd.write('%s %s\n' % (self.FILE_ID, hexlify(self.repository_id).decode('ascii')))
            fd.write('\n'.join(textwrap.wrap(b2a_base64(data).decode('ascii'))))
            fd.write('\n')
        self.path = path

    def change_passphrase(self):
        passphrase, passphrase2 = 1, 2
        while passphrase != passphrase2:
            passphrase = getpass('New passphrase: ')
            passphrase2 = getpass('Enter same passphrase again: ')
            if passphrase != passphrase2:
                print('Passphrases do not match')
        self.save(self.path, passphrase)
        print('Key file "%s" updated' % self.path)

    @classmethod
    def create(cls, repository, args):
        filename = args.repository.to_key_filename()
        path = filename
        i = 1
        while os.path.exists(path):
            i += 1
            path = filename + '.%d' % i
        passphrase = os.environ.get('ATTIC_PASSPHRASE')
        if passphrase is not None:
            passphrase2 = passphrase
        else:
            passphrase, passphrase2 = 1, 2
        while passphrase != passphrase2:
            passphrase = getpass('Enter passphrase (empty for no passphrase):')
            passphrase2 = getpass('Enter same passphrase again: ')
            if passphrase != passphrase2:
                print('Passphrases do not match')
        compressor = compressor_creator(args)
        maccer = maccer_creator(args, cls)
        cipher = cipher_creator(args, cls)
        key = cls(compressor, maccer, cipher)
        key.repository_id = repository.id
        key.init_from_random_data(get_random_bytes(100))
        key.init_ciphers()
        key.save(path, passphrase)
        print('Key file "%s" created.' % key.path)
        print('Keep this file safe. Your data will be inaccessible without it.')
        return key


# note: key 0 nicely maps to a zlib compressor with level 0 which means "no compression"
compressor_mapping = {}
for level in ZlibCompressor.LEVELS:
    compressor_mapping[ZlibCompressor.TYPE + level] = \
        type('ZlibCompressorLevel%d' % level, (ZlibCompressor, ), dict(TYPE=ZlibCompressor.TYPE + level))
for preset in LzmaCompressor.PRESETS:
    compressor_mapping[LzmaCompressor.TYPE + preset] = \
        type('LzmaCompressorPreset%d' % preset, (LzmaCompressor, ), dict(TYPE=LzmaCompressor.TYPE + preset))
for level in LZ4Compressor.LEVELS:
    compressor_mapping[LZ4Compressor.TYPE + level] = \
        type('LZ4CompressorLevel%d' % level, (LZ4Compressor, ), dict(TYPE=LZ4Compressor.TYPE + level))
for level in LZ4HCCompressor.LEVELS:
    compressor_mapping[LZ4HCCompressor.TYPE + level] = \
        type('LZ4HCCompressorLevel%d' % level, (LZ4HCCompressor, ), dict(TYPE=LZ4HCCompressor.TYPE + level))
for level in BLOSCLZCompressor.LEVELS:
    compressor_mapping[BLOSCLZCompressor.TYPE + level] = \
        type('BLOSCLZCompressorLevel%d' % level, (BLOSCLZCompressor, ), dict(TYPE=BLOSCLZCompressor.TYPE + level))
for level in SnappyCompressor.LEVELS:
    compressor_mapping[SnappyCompressor.TYPE + level] = \
        type('SnappyCompressorLevel%d' % level, (SnappyCompressor, ), dict(TYPE=SnappyCompressor.TYPE + level))
for level in BLOSCZlibCompressor.LEVELS:
    compressor_mapping[BLOSCZlibCompressor.TYPE + level] = \
        type('BLOSCZlibCompressorLevel%d' % level, (BLOSCZlibCompressor, ), dict(TYPE=BLOSCZlibCompressor.TYPE + level))
# overwrite 0 with NullCompressor
compressor_mapping[NullCompressor.TYPE] = NullCompressor


keyer_mapping = {
    KeyfileKey.TYPE: KeyfileKey,
    PassphraseKey.TYPE: PassphraseKey,
    PlaintextKey.TYPE: PlaintextKey,
}


maccer_mapping = {
    # simple hashes, not MACs (but MAC-like class __init__ method signature):
    SHA256.TYPE: SHA256,
    SHA512_256.TYPE: SHA512_256,
    GHASH.TYPE: GHASH,
    # MACs:
    HMAC_SHA256.TYPE: HMAC_SHA256,
    HMAC_SHA512_256.TYPE: HMAC_SHA512_256,
    GMAC.TYPE: GMAC,
}


cipher_mapping = {
    # no cipher (but cipher-like class __init__ method signature):
    PLAIN.TYPE: PLAIN,
    # AEAD cipher implementations
    AES_CTR_HMAC.TYPE: AES_CTR_HMAC,
    AES_GCM.TYPE: AES_GCM,
}


def get_implementations(meta):
    try:
        compressor = compressor_mapping[meta.compr_type]
        keyer = keyer_mapping[meta.key_type]
        maccer = maccer_mapping[meta.mac_type]
        cipher = cipher_mapping[meta.cipher_type]
    except KeyError:
        raise UnsupportedPayloadError("compr_type %x key_type %x mac_type %x cipher_type %x" % (
            meta.compr_type, meta.key_type, meta.mac_type, meta.cipher_type))
    return compressor, keyer, maccer, cipher


def legacy_parser(all_data, key_type):  # all rather hardcoded
    """
    Payload layout:
    no encryption:   TYPE(1) + data
    with encryption: TYPE(1) + HMAC(32) + NONCE(8) + data
    data is compressed with zlib level 6 and (in the 2nd case) encrypted.

    To reduce payload size only 8 bytes of the 16 bytes nonce is saved
    in the payload, the first 8 bytes are always zeros. This does not
    affect security but limits the maximum repository capacity to
    only 295 exabytes!
    """
    offset = 1
    if key_type == PlaintextKey.TYPE:
        mac_type = SHA256.TYPE
        mac = None
        cipher_type = PLAIN.TYPE
        iv = None
        data = all_data[offset:]
    else:
        mac_type = HMAC_SHA256.TYPE
        mac = all_data[offset:offset+32]
        cipher_type = AES_CTR_HMAC.TYPE
        iv = PREFIX + all_data[offset+32:offset+40]
        data = all_data[offset+40:]
    meta = Meta(compr_type=6, key_type=key_type, mac_type=mac_type,
                cipher_type=cipher_type, iv=iv, legacy=True)
    return mac, meta, data

def parser00(all_data):
    return legacy_parser(all_data, KeyfileKey.TYPE)

def parser01(all_data):
    return legacy_parser(all_data, PassphraseKey.TYPE)

def parser02(all_data):
    return legacy_parser(all_data, PlaintextKey.TYPE)


def parser03(all_data):  # new & flexible
    """
    Payload layout:
    always: TYPE(1) + MSGPACK((mac, meta, data))

    meta is a Meta namedtuple and contains all required information about data.
    data is maybe compressed (see meta) and maybe encrypted (see meta).
    """
    max_len = 10000000  # XXX formula?
    unpacker = msgpack.Unpacker(
        use_list=False,
        # avoid memory allocation issues causes by tampered input data.
        max_buffer_size=max_len,  # does not work in 0.4.6 unpackb C implementation
        max_array_len=10,  # meta_tuple
        max_bin_len=max_len,  # data
        max_str_len=0,  # not used yet
        max_map_len=0,  # not used yet
        max_ext_len=0,  # not used yet
        )
    unpacker.feed(all_data[1:])
    mac, meta_tuple, data = unpacker.unpack()
    meta = Meta(*meta_tuple)
    return mac, meta, data


def parser(data):
    parser_mapping = {
        0x00: parser00,
        0x01: parser01,
        0x02: parser02,
        0x03: parser03,
    }
    header_type = data[0]
    parser_func = parser_mapping[header_type]
    return parser_func(data)


def key_factory(repository, manifest_data):
    mac, meta, data = parser(manifest_data)
    compressor, keyer, maccer, cipher = get_implementations(meta)
    return keyer.detect(repository, manifest_data)


def generate(mac, meta, data):
    # always create new-style 0x03 format
    return b'\x03' + msgpack.packb((mac, meta, data), use_bin_type=True)


def compressor_creator(args):
    # args == None is used by unit tests
    compression = COMPR_DEFAULT if args is None else args.compression
    compressor = compressor_mapping.get(compression)
    if compressor is None:
        raise NotImplementedError("no compression %d" % args.compression)
    return compressor


def key_creator(args):
    if args.encryption == 'keyfile':
        return KeyfileKey
    if args.encryption == 'passphrase':
        return PassphraseKey
    if args.encryption == 'none':
        return PlaintextKey
    raise NotImplemented("no encryption %s" % args.encryption)


def maccer_creator(args, key_cls):
    # args == None is used by unit tests
    mac = None if args is None else args.mac
    if mac is None:
        if key_cls is PlaintextKey:
            mac = HASH_DEFAULT
        elif key_cls in (KeyfileKey, PassphraseKey):
            mac = MAC_DEFAULT
        else:
            raise NotImplementedError("unknown key class")
    maccer = maccer_mapping.get(mac)
    if maccer is None:
        raise NotImplementedError("no mac %d" % args.mac)
    return maccer


def cipher_creator(args, key_cls):
    # args == None is used by unit tests
    cipher = None if args is None else args.cipher
    if cipher is None:
        if key_cls is PlaintextKey:
            cipher = PLAIN_DEFAULT
        elif key_cls in (KeyfileKey, PassphraseKey):
            cipher = CIPHER_DEFAULT
        else:
            raise NotImplementedError("unknown key class")
    cipher = cipher_mapping.get(cipher)
    if cipher is None:
        raise NotImplementedError("no cipher %d" % args.cipher)
    return cipher

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

from attic.crypto import pbkdf2_sha256, get_random_bytes, AES, bytes_to_long, long_to_bytes, bytes_to_int, num_aes_blocks
from attic.helpers import IntegrityError, get_keys_dir, Error

PREFIX = b'\0' * 8


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


class SHA256(object):  # note: can't subclass sha256
    TYPE = 0x00

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
    TYPE = 0x01

    def __init__(self, key, data):
        # signature is like for a MAC, we ignore the key as this is a simple hash
        if key is not None:
            raise Exception("use a HMAC if you have a key")
        super().__init__(data)


HASH_DEFAULT = SHA256.TYPE


class HMAC_SHA256(HMAC):
    TYPE = 0x02

    def __init__(self, key, data):
        if key is None:
            raise Exception("do not use HMAC if you don't have a key")
        super().__init__(key, data, sha256)


class HMAC_SHA512_256(HMAC):
    TYPE = 0x03

    def __init__(self, key, data):
        if key is None:
            raise Exception("do not use HMAC if you don't have a key")
        super().__init__(key, data, sha512_256)


MAC_DEFAULT = HMAC_SHA256.TYPE


class ZlibCompressor(object):  # uses 0..9 in the mapping
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


COMPR_DEFAULT = ZlibCompressor.TYPE + 6  # zlib level 6


Meta = namedtuple('Meta', 'compr_type, crypt_type, mac_type, hmac, iv, stored_iv')


class KeyBase(object):
    TYPE = 0x00  # override in derived classes

    def __init__(self, compressor, maccer):
        self.compressor = compressor()
        self.maccer = maccer

    def id_hash(self, data):
        """Return HMAC hash using the "id" HMAC key
        """

    def encrypt(self, data):
        pass

    def decrypt(self, id, data):
        pass


class PlaintextKey(KeyBase):
    TYPE = 0x02

    chunk_seed = 0

    @classmethod
    def create(cls, repository, args):
        print('Encryption NOT enabled.\nUse the "--encryption=passphrase|keyfile" to enable encryption.')
        compressor = compressor_creator(args)
        maccer = maccer_creator(args, cls)
        return cls(compressor, maccer)

    @classmethod
    def detect(cls, repository, manifest_data):
        meta, data, compressor, crypter, maccer = parser(manifest_data)
        return cls(compressor, maccer)

    def id_hash(self, data):
        return self.maccer(None, data).digest()

    def encrypt(self, data):
        meta = Meta(compr_type=self.compressor.TYPE, crypt_type=self.TYPE, mac_type=self.maccer.TYPE,
                    hmac=None, iv=None, stored_iv=None)
        data = self.compressor.compress(data)
        return generate(meta, data)

    def decrypt(self, id, data):
        meta, data, compressor, crypter, maccer = parser(data)
        assert isinstance(self, crypter)
        assert self.maccer is maccer
        data = self.compressor.decompress(data)
        if id and self.id_hash(data) != id:
            raise IntegrityError('Chunk id verification failed')
        return data


class AESKeyBase(KeyBase):
    """Common base class shared by KeyfileKey and PassphraseKey

    Chunks are encrypted using 256bit AES in Counter Mode (CTR)

    Payload layout: HEADER(4) + HMAC(32) + NONCE(8) + CIPHERTEXT

    To reduce payload size only 8 bytes of the 16 bytes nonce is saved
    in the payload, the first 8 bytes are always zeros. This does not
    affect security but limits the maximum repository capacity to
    only 295 exabytes!
    """
    PAYLOAD_OVERHEAD = 4 + 32 + 8  # HEADER + HMAC + NONCE, TODO: get rid of this

    def id_hash(self, data):
        """Return HMAC hash using the "id" HMAC key
        """
        return self.maccer(self.id_key, data).digest()

    def encrypt(self, data):
        data = self.compressor.compress(data)
        self.enc_cipher.reset()
        stored_iv = self.enc_cipher.iv[8:]
        iv = PREFIX + stored_iv
        data = self.enc_cipher.encrypt(data)
        hmac = self.maccer(self.enc_hmac_key, stored_iv + data).digest()
        meta = Meta(compr_type=self.compressor.TYPE, crypt_type=self.TYPE, mac_type=self.maccer.TYPE,
                    hmac=hmac, iv=iv, stored_iv=stored_iv)
        return generate(meta, data)

    def decrypt(self, id, data):
        meta, data, compressor, crypter, maccer = parser(data)
        assert isinstance(self, crypter)
        assert self.maccer is maccer
        computed_hmac = self.maccer(self.enc_hmac_key, meta.stored_iv + data).digest()
        if computed_hmac != meta.hmac:
            raise IntegrityError('Encryption envelope checksum mismatch')
        self.dec_cipher.reset(iv=meta.iv)
        data = self.compressor.decompress(self.dec_cipher.decrypt(data))
        if id and self.id_hash(data) != id:
            raise IntegrityError('Chunk id verification failed')
        return data

    def extract_nonce(self, payload):
        meta, data, compressor, crypter, maccer = parser(payload)
        assert isinstance(self, crypter)
        nonce = bytes_to_long(meta.stored_iv)
        return nonce

    def init_from_random_data(self, data):
        self.enc_key = data[0:32]
        self.enc_hmac_key = data[32:64]
        self.id_key = data[64:96]
        self.chunk_seed = bytes_to_int(data[96:100])
        # Convert to signed int32
        if self.chunk_seed & 0x80000000:
            self.chunk_seed = self.chunk_seed - 0xffffffff - 1

    def init_ciphers(self, enc_iv=b''):
        self.enc_cipher = AES(self.enc_key, enc_iv)
        self.dec_cipher = AES(self.enc_key)


class PassphraseKey(AESKeyBase):
    TYPE = 0x01
    iterations = 100000

    @classmethod
    def create(cls, repository, args):
        compressor = compressor_creator(args)
        maccer = maccer_creator(args, cls)
        key = cls(compressor, maccer)
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
        meta, data, compressor, crypter, maccer = parser(manifest_data)
        key = cls(compressor, maccer)
        passphrase = os.environ.get('ATTIC_PASSPHRASE')
        if passphrase is None:
            passphrase = getpass(prompt)
        while True:
            key.init(repository, passphrase)
            try:
                key.decrypt(None, manifest_data)
                num_blocks = num_aes_blocks(len(data))
                key.init_ciphers(PREFIX + long_to_bytes(key.extract_nonce(manifest_data) + num_blocks))
                return key
            except IntegrityError:
                passphrase = getpass(prompt)

    def init(self, repository, passphrase):
        self.init_from_random_data(pbkdf2_sha256(passphrase.encode('utf-8'), repository.id, self.iterations, 100))
        self.init_ciphers()


class KeyfileKey(AESKeyBase):
    FILE_ID = 'ATTIC KEY'
    TYPE = 0x00

    @classmethod
    def detect(cls, repository, manifest_data):
        meta, data, compressor, crypter, maccer = parser(manifest_data)
        key = cls(compressor, maccer)
        path = cls.find_key_file(repository)
        prompt = 'Enter passphrase for key file %s: ' % path
        passphrase = os.environ.get('ATTIC_PASSPHRASE', '')
        while not key.load(path, passphrase):
            passphrase = getpass(prompt)
        num_blocks = num_aes_blocks(len(data))
        key.init_ciphers(PREFIX + long_to_bytes(key.extract_nonce(manifest_data) + num_blocks))
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
        assert d[b'algorithm'] == b'sha256'
        key = pbkdf2_sha256(passphrase.encode('utf-8'), d[b'salt'], d[b'iterations'], 32)
        data = AES(key).decrypt(d[b'data'])
        if HMAC(key, data, sha256).digest() != d[b'hash']:
            return None
        return data

    def encrypt_key_file(self, data, passphrase):
        salt = get_random_bytes(32)
        iterations = 100000
        key = pbkdf2_sha256(passphrase.encode('utf-8'), salt, iterations, 32)
        hash = HMAC(key, data, sha256).digest()
        cdata = AES(key).encrypt(data)
        d = {
            'version': 1,
            'salt': salt,
            'iterations': iterations,
            'algorithm': 'sha256',
            'hash': hash,
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
        key = cls(compressor, maccer)
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


crypter_mapping = {
    KeyfileKey.TYPE: KeyfileKey,
    PassphraseKey.TYPE: PassphraseKey,
    PlaintextKey.TYPE: PlaintextKey,
}


maccer_mapping = {
    # simple hashes, not MACs (but MAC-like class __init__ method signature):
    SHA256.TYPE: SHA256,
    SHA512_256.TYPE: SHA512_256,
    # MACs:
    HMAC_SHA256.TYPE: HMAC_SHA256,
    HMAC_SHA512_256.TYPE: HMAC_SHA512_256,
}


def get_implementations(meta):
    try:
        compressor = compressor_mapping[meta.compr_type]
        crypter = crypter_mapping[meta.crypt_type]
        maccer = maccer_mapping[meta.mac_type]
    except KeyError:
        raise UnsupportedPayloadError("compr_type %x crypt_type %x mac_type %x" % (
            meta.compr_type, meta.crypt_type, meta.mac_type))
    return compressor, crypter, maccer


def parser00(all_data):  # legacy, hardcoded
    offset = 1
    hmac = all_data[offset:offset+32]
    stored_iv = all_data[offset+32:offset+40]
    iv = PREFIX + stored_iv
    data = all_data[offset+40:]
    meta = Meta(compr_type=6, crypt_type=KeyfileKey.TYPE, mac_type=HMAC_SHA256.TYPE,
                hmac=hmac, iv=iv, stored_iv=stored_iv)
    compressor, crypter, maccer = get_implementations(meta)
    return meta, data, compressor, crypter, maccer

def parser01(all_data):  # legacy, hardcoded
    offset = 1
    hmac = all_data[offset:offset+32]
    stored_iv = all_data[offset+32:offset+40]
    iv = PREFIX + stored_iv
    data = all_data[offset+40:]
    meta = Meta(compr_type=6, crypt_type=PassphraseKey.TYPE, mac_type=HMAC_SHA256.TYPE,
                hmac=hmac, iv=iv, stored_iv=stored_iv)
    compressor, crypter, maccer = get_implementations(meta)
    return meta, data, compressor, crypter, maccer

def parser02(all_data):  # legacy, hardcoded
    offset = 1
    hmac = None
    iv = stored_iv = None
    data = all_data[offset:]
    meta = Meta(compr_type=6, crypt_type=PlaintextKey.TYPE, mac_type=SHA256.TYPE,
                hmac=hmac, iv=iv, stored_iv=stored_iv)
    compressor, crypter, maccer = get_implementations(meta)
    return meta, data, compressor, crypter, maccer


def parser03(all_data):  # new & flexible
    offset = 4
    compr_type, crypt_type, mac_type = all_data[1:offset]
    if crypt_type == PlaintextKey.TYPE:
        hmac = None
        iv = stored_iv = None
        data = all_data[offset:]
    else:
        hmac = all_data[offset:offset+32]
        stored_iv = all_data[offset+32:offset+40]
        iv = PREFIX + stored_iv
        data = all_data[offset+40:]
    meta = Meta(compr_type=compr_type, crypt_type=crypt_type, mac_type=mac_type,
                hmac=hmac, iv=iv, stored_iv=stored_iv)
    compressor, crypter, maccer = get_implementations(meta)
    return meta, data, compressor, crypter, maccer


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
    meta, data, compressor, crypter, maccer = parser(manifest_data)
    return crypter.detect(repository, manifest_data)


def generate(meta, data):
    # always create new-style 0x03 format
    start = bytes([0x03, meta.compr_type, meta.crypt_type, meta.mac_type])
    if meta.crypt_type == PlaintextKey.TYPE:
        result = start + data
    else:
        assert len(meta.hmac) == 32
        assert len(meta.stored_iv) == 8
        result = start + meta.hmac + meta.stored_iv + data
    return result

def compressor_creator(args):
    # args == None is used by unit tests
    compression = COMPR_DEFAULT if args is None else args.compression
    compressor = compressor_mapping.get(compression)
    if compressor is None:
        raise NotImplementedError("no compression %d" % args.compression)
    return compressor


def key_creator(repository, args):
    if args.encryption == 'keyfile':
        return KeyfileKey.create(repository, args)
    if args.encryption == 'passphrase':
        return PassphraseKey.create(repository, args)
    if args.encryption == 'none':
        return PlaintextKey.create(repository, args)
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

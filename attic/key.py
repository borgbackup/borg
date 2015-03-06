from binascii import hexlify, a2b_base64, b2a_base64
from getpass import getpass
import os
import msgpack
import textwrap
import hmac
from hashlib import sha256
import zlib

from attic.crypto import pbkdf2_sha256, get_random_bytes, AES, bytes_to_long, long_to_bytes, bytes_to_int, num_aes_blocks
from attic.helpers import IntegrityError, get_keys_dir, Error

PREFIX = b'\0' * 8


class UnsupportedPayloadError(Error):
    """Unsupported payload type {}. A newer version is required to access this repository.
    """

class HMAC(hmac.HMAC):
    """Workaround a bug in Python < 3.4 Where HMAC does not accept memoryviews
    """
    def update(self, msg):
        self.inner.update(msg)


def key_creator(repository, args):
    if args.encryption == 'keyfile':
        return KeyfileKey.create(repository, args)
    elif args.encryption == 'passphrase':
        return PassphraseKey.create(repository, args)
    else:
        return PlaintextKey.create(repository, args)


def key_factory(repository, manifest_data):
    if manifest_data[0] == KeyfileKey.TYPE:
        return KeyfileKey.detect(repository, manifest_data)
    elif manifest_data[0] == PassphraseKey.TYPE:
        return PassphraseKey.detect(repository, manifest_data)
    elif manifest_data[0] == PlaintextKey.TYPE:
        return PlaintextKey.detect(repository, manifest_data)
    else:
        raise UnsupportedPayloadError(manifest_data[0])


class KeyBase(object):

    def __init__(self):
        self.TYPE_STR = bytes([self.TYPE])

    def id_hash(self, data):
        """Return a HASH (no id_key) or a MAC (using the "id_key" key)
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
        return cls()

    @classmethod
    def detect(cls, repository, manifest_data):
        return cls()

    def id_hash(self, data):
        return sha256(data).digest()

    def encrypt(self, data):
        return b''.join([self.TYPE_STR, zlib.compress(data)])

    def decrypt(self, id, data):
        if data[0] != self.TYPE:
            raise IntegrityError('Invalid encryption envelope')
        data = zlib.decompress(memoryview(data)[1:])
        if id and sha256(data).digest() != id:
            raise IntegrityError('Chunk id verification failed')
        return data


class AESKeyBase(KeyBase):
    """Common base class shared by KeyfileKey and PassphraseKey

    Chunks are encrypted using 256bit AES in Galois Counter Mode (GCM)

    Payload layout: TYPE(1) + TAG(32) + NONCE(8) + CIPHERTEXT

    To reduce payload size only 8 bytes of the 16 bytes nonce is saved
    in the payload, the first 8 bytes are always zeros. This does not
    affect security but limits the maximum repository capacity to
    only 295 exabytes!
    """

    PAYLOAD_OVERHEAD = 1 + 32 + 8  # TYPE + HMAC + NONCE

    def id_hash(self, data):
        """
        Return GMAC using the "id_key" GMAC key

        XXX do we need a cryptographic hash function here or is a keyed hash
        function like GMAC / GHASH good enough? See NIST SP 800-38D.

        IMPORTANT: in 1 repo, there should be only 1 kind of id_hash, otherwise
        data hashed/maced with one id_hash might result in same ID as already
        exists in the repo for other data created with another id_hash method.
        somehow unlikely considering 128 or 256bits, but still.
        """
        mac_cipher = AES(is_encrypt=True, key=self.id_key, iv=b'\0'*16)  # XXX do we need an IV here?
        # GMAC = aes-gcm with all data as AAD, no data as to-be-encrypted data
        mac_cipher.add(bytes(data))
        tag, _ = mac_cipher.compute_tag_and_encrypt(b'')
        return tag

    def encrypt(self, data):
        data = zlib.compress(data)
        self.enc_cipher.reset(iv=self.enc_iv)
        iv_last8 = self.enc_iv[8:]
        self.enc_cipher.add(iv_last8)
        tag, data = self.enc_cipher.compute_tag_and_encrypt(data)
        # increase the IV (counter) value so same value is never used twice
        current_iv = bytes_to_long(iv_last8)
        self.enc_iv = PREFIX + long_to_bytes(current_iv + num_aes_blocks(len(data)))
        return b''.join((self.TYPE_STR, tag, iv_last8, data))

    def decrypt(self, id, data):
        if data[0] != self.TYPE:
            raise IntegrityError('Invalid encryption envelope')
        iv_last8 = data[1+32:1+40]
        iv = PREFIX + iv_last8
        self.dec_cipher.reset(iv=iv)
        self.dec_cipher.add(iv_last8)
        tag, data = data[1:1+32], data[1+40:]
        try:
            data = self.dec_cipher.check_tag_and_decrypt(tag, data)
        except Exception:
            raise IntegrityError('Encryption envelope checksum mismatch')
        data = zlib.decompress(data)
        if id and self.id_hash(data) != id:
            raise IntegrityError('Chunk id verification failed')
        return data

    def extract_nonce(self, payload):
        if payload[0] != self.TYPE:
             raise IntegrityError('Invalid encryption envelope')
        nonce = bytes_to_long(payload[33:41])
        return nonce

    def init_from_random_data(self, data):
        self.enc_key = data[0:32]
        self.enc_hmac_key = data[32:64]  # XXX enc_hmac_key not used for AES-GCM
        self.id_key = data[64:96]
        self.chunk_seed = bytes_to_int(data[96:100])
        # Convert to signed int32
        if self.chunk_seed & 0x80000000:
            self.chunk_seed = self.chunk_seed - 0xffffffff - 1

    def init_ciphers(self, enc_iv=PREFIX * 2):  # default IV = 16B zero
        self.enc_iv = enc_iv
        self.enc_cipher = AES(is_encrypt=True, key=self.enc_key, iv=enc_iv)
        self.dec_cipher = AES(is_encrypt=False, key=self.enc_key)


class PassphraseKey(AESKeyBase):
    TYPE = 0x01
    iterations = 100000

    @classmethod
    def create(cls, repository, args):
        key = cls()
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
        key = cls()
        passphrase = os.environ.get('ATTIC_PASSPHRASE')
        if passphrase is None:
            passphrase = getpass(prompt)
        while True:
            key.init(repository, passphrase)
            try:
                key.decrypt(None, manifest_data)
                num_blocks = num_aes_blocks(len(manifest_data) - 41)
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
        key = cls()
        path = cls.find_key_file(repository)
        prompt = 'Enter passphrase for key file %s: ' % path
        passphrase = os.environ.get('ATTIC_PASSPHRASE', '')
        while not key.load(path, passphrase):
            passphrase = getpass(prompt)
        num_blocks = num_aes_blocks(len(manifest_data) - 41)
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
        assert d[b'algorithm'] == b'gmac'
        key = pbkdf2_sha256(passphrase.encode('utf-8'), d[b'salt'], d[b'iterations'], 32)
        try:
            data = AES(is_encrypt=False, key=key, iv=b'\0'*16).check_tag_and_decrypt(d[b'hash'], d[b'data'])
            return data
        except Exception:
            return None

    def encrypt_key_file(self, data, passphrase):
        salt = get_random_bytes(32)
        iterations = 100000
        key = pbkdf2_sha256(passphrase.encode('utf-8'), salt, iterations, 32)
        tag, cdata = AES(is_encrypt=True, key=key, iv=b'\0'*16).compute_tag_and_encrypt(data)
        d = {
            'version': 1,
            'salt': salt,
            'iterations': iterations,
            'algorithm': 'gmac',
            'hash': tag,
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
        key = cls()
        key.repository_id = repository.id
        key.init_from_random_data(get_random_bytes(100))
        key.init_ciphers()
        key.save(path, passphrase)
        print('Key file "%s" created.' % key.path)
        print('Keep this file safe. Your data will be inaccessible without it.')
        return key

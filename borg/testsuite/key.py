import os
import re
import shutil
import tempfile
from binascii import hexlify, unhexlify

from ..crypto import bytes_to_long, num_aes_blocks
from ..key import PlaintextKey, PassphraseKey, KeyfileKey
from ..helpers import Location, IntegrityError, Chunk, bin_to_hex
from . import environment_variable


class KeyTestCase(BaseTestCase):

    class MockArgs:
        location = Location(tempfile.mkstemp()[1])

    keyfile2_key_file = """
        BORG_KEY 0000000000000000000000000000000000000000000000000000000000000000
        hqppdGVyYXRpb25zzgABhqCkaGFzaNoAIMyonNI+7Cjv0qHi0AOBM6bLGxACJhfgzVD2oq
        bIS9SFqWFsZ29yaXRobaZzaGEyNTakc2FsdNoAINNK5qqJc1JWSUjACwFEWGTdM7Nd0a5l
        1uBGPEb+9XM9p3ZlcnNpb24BpGRhdGHaANAYDT5yfPpU099oBJwMomsxouKyx/OG4QIXK2
        hQCG2L2L/9PUu4WIuKvGrsXoP7syemujNfcZws5jLp2UPva4PkQhQsrF1RYDEMLh2eF9Ol
        rwtkThq1tnh7KjWMG9Ijt7/aoQtq0zDYP/xaFF8XXSJxiyP5zjH5+spB6RL0oQHvbsliSh
        /cXJq7jrqmrJ1phd6dg4SHAM/i+hubadZoS6m25OQzYAW09wZD/phG8OVa698Z5ed3HTaT
        SmrtgJL3EoOKgUI9d6BLE4dJdBqntifo""".strip()

    keyfile2_cdata = unhexlify(re.sub('\W', '', """
        0055f161493fcfc16276e8c31493c4641e1eb19a79d0326fad0291e5a9c98e5933
        00000000000003e8d21eaf9b86c297a8cd56432e1915bb
        """))
    keyfile2_id = unhexlify('c3fbf14bc001ebcc3cd86e696c13482ed071740927cd7cbe1b01b4bfcee49314')

    def setUp(self):
        self.tmppath = tempfile.mkdtemp()
        os.environ['BORG_KEYS_DIR'] = self.tmppath
        self.tmppath2 = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmppath)
        shutil.rmtree(self.tmppath2)

    class MockRepository:
        class _Location:
            orig = '/some/place'

        _location = _Location()
        id = bytes(32)
        id_str = bin_to_hex(id)

    def test_plaintext(self):
        key = PlaintextKey.create(None, None)
        chunk = Chunk(b'foo')
        self.assert_equal(hexlify(key.id_hash(chunk.data)), b'2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae')
        self.assert_equal(chunk, key.decrypt(key.id_hash(chunk.data), key.encrypt(chunk)))

    def test_keyfile(self):
        os.environ['BORG_PASSPHRASE'] = 'test'
        key = KeyfileKey.create(self.MockRepository(), self.MockArgs())
        self.assert_equal(bytes_to_long(key.enc_cipher.iv, 8), 0)
        manifest = key.encrypt(Chunk(b'XXX'))
        self.assert_equal(key.extract_nonce(manifest), 0)
        manifest2 = key.encrypt(Chunk(b'XXX'))
        self.assert_not_equal(manifest, manifest2)
        self.assert_equal(key.decrypt(None, manifest), key.decrypt(None, manifest2))
        self.assert_equal(key.extract_nonce(manifest2), 1)
        iv = key.extract_nonce(manifest)
        key2 = KeyfileKey.detect(self.MockRepository(), manifest)
        self.assert_equal(bytes_to_long(key2.enc_cipher.iv, 8), iv + num_aes_blocks(len(manifest) - KeyfileKey.PAYLOAD_OVERHEAD))
        # Key data sanity check
        self.assert_equal(len(set([key2.id_key, key2.enc_key, key2.enc_hmac_key])), 3)
        self.assert_equal(key2.chunk_seed == 0, False)
        chunk = Chunk(b'foo')
        self.assert_equal(chunk, key2.decrypt(key.id_hash(chunk.data), key.encrypt(chunk)))

    def test_keyfile_kfenv(self):
        keyfile = os.path.join(self.tmppath2, 'keyfile')
        with environment_variable(BORG_KEY_FILE=keyfile, BORG_PASSPHRASE='testkf'):
            assert not os.path.exists(keyfile)
            key = KeyfileKey.create(self.MockRepository(), self.MockArgs())
            assert os.path.exists(keyfile)
            chunk = Chunk(b'XXX')
            chunk_id = key.id_hash(chunk.data)
            chunk_cdata = key.encrypt(chunk)
            key = KeyfileKey.detect(self.MockRepository(), chunk_cdata)
            self.assert_equal(chunk, key.decrypt(chunk_id, chunk_cdata))
            os.unlink(keyfile)
            self.assert_raises(FileNotFoundError, KeyfileKey.detect, self.MockRepository(), chunk_cdata)

    def test_keyfile2(self):
        with open(os.path.join(os.environ['BORG_KEYS_DIR'], 'keyfile'), 'w') as fd:
            fd.write(self.keyfile2_key_file)
        os.environ['BORG_PASSPHRASE'] = 'passphrase'
        key = KeyfileKey.detect(self.MockRepository(), self.keyfile2_cdata)
        self.assert_equal(key.decrypt(self.keyfile2_id, self.keyfile2_cdata).data, b'payload')

    def test_keyfile2_kfenv(self):
        keyfile = os.path.join(self.tmppath2, 'keyfile')
        with open(keyfile, 'w') as fd:
            fd.write(self.keyfile2_key_file)
        with environment_variable(BORG_KEY_FILE=keyfile, BORG_PASSPHRASE='passphrase'):
            key = KeyfileKey.detect(self.MockRepository(), self.keyfile2_cdata)
            self.assert_equal(key.decrypt(self.keyfile2_id, self.keyfile2_cdata).data, b'payload')

    def test_passphrase(self):
        os.environ['BORG_PASSPHRASE'] = 'test'
        key = PassphraseKey.create(self.MockRepository(), None)
        self.assert_equal(bytes_to_long(key.enc_cipher.iv, 8), 0)
        self.assert_equal(hexlify(key.id_key), b'793b0717f9d8fb01c751a487e9b827897ceea62409870600013fbc6b4d8d7ca6')
        self.assert_equal(hexlify(key.enc_hmac_key), b'b885a05d329a086627412a6142aaeb9f6c54ab7950f996dd65587251f6bc0901')
        self.assert_equal(hexlify(key.enc_key), b'2ff3654c6daf7381dbbe718d2b20b4f1ea1e34caa6cc65f6bb3ac376b93fed2a')
        self.assert_equal(key.chunk_seed, -775740477)
        manifest = key.encrypt(Chunk(b'XXX'))
        self.assert_equal(key.extract_nonce(manifest), 0)
        manifest2 = key.encrypt(Chunk(b'XXX'))
        self.assert_not_equal(manifest, manifest2)
        self.assert_equal(key.decrypt(None, manifest), key.decrypt(None, manifest2))
        self.assert_equal(key.extract_nonce(manifest2), 1)
        iv = key.extract_nonce(manifest)
        key2 = PassphraseKey.detect(self.MockRepository(), manifest)
        self.assert_equal(bytes_to_long(key2.enc_cipher.iv, 8), iv + num_aes_blocks(len(manifest) - PassphraseKey.PAYLOAD_OVERHEAD))
        self.assert_equal(key.id_key, key2.id_key)
        self.assert_equal(key.enc_hmac_key, key2.enc_hmac_key)
        self.assert_equal(key.enc_key, key2.enc_key)
        self.assert_equal(key.chunk_seed, key2.chunk_seed)
        chunk = Chunk(b'foo')
        self.assert_equal(hexlify(key.id_hash(chunk.data)), b'818217cf07d37efad3860766dcdf1d21e401650fed2d76ed1d797d3aae925990')
        self.assert_equal(chunk, key2.decrypt(key2.id_hash(chunk.data), key.encrypt(chunk)))

    def test_decrypt_integrity(self):
        with open(os.path.join(os.environ['BORG_KEYS_DIR'], 'keyfile'), 'w') as fd:
            fd.write(self.keyfile2_key_file)
        os.environ['BORG_PASSPHRASE'] = 'passphrase'
        key = KeyfileKey.detect(self.MockRepository(), self.keyfile2_cdata)
        with self.assert_raises_regex(IntegrityError, 'Invalid encryption envelope'):
            data = bytearray(self.keyfile2_cdata)
            data[0] += 5  # wrong TYPE
            key.decrypt("", data)
        with self.assert_raises_regex(IntegrityError, 'Encryption envelope checksum mismatch'):
            data = bytearray(self.keyfile2_cdata)
            data[5] += 5  # corrupt HMAC
            key.decrypt("", data)
        with self.assert_raises_regex(IntegrityError, 'Encryption envelope checksum mismatch'):
            data = bytearray(self.keyfile2_cdata)
            id = key.id_hash(data)
            data[36] += 123  # this in the IV/CTR
            key.decrypt(id, data)
        with self.assert_raises_regex(IntegrityError, 'Encryption envelope checksum mismatch'):
            data = bytearray(self.keyfile2_cdata)
            id = key.id_hash(data)
            data[50] += 1  # corrupt data
            key.decrypt(id, data)
        with self.assert_raises_regex(IntegrityError, 'Chunk id verification failed'):
            data = bytearray(self.keyfile2_cdata)
            id = bytearray(key.id_hash(data))  # corrupt chunk id
            id[12] = 0
            key.decrypt(id, data)

import os
import re
import shutil
import tempfile
from binascii import hexlify
from attic.crypto import bytes_to_long, num_aes_blocks
from attic.testsuite import AtticTestCase
from attic.key import PlaintextKey, PassphraseKey, KeyfileKey
from attic.helpers import Location, unhexlify


class KeyTestCase(AtticTestCase):

    class MockArgs(object):
        repository = Location(tempfile.mkstemp()[1])

    keyfile2_key_file = """
ATTIC KEY 0000000000000000000000000000000000000000000000000000000000000000
hqppdGVyYXRpb25zzgABhqCkc2FsdNoAICiRWfijWqIuvr+70VzOsUS4Y6NM45FWm6LgCu
2GyalGqWFsZ29yaXRobaRnbWFjpGhhc2jaACDgCK7u30Pi+Du1qHRyWBupAAAAAAAAAAAA
AAAAAAAAAKd2ZXJzaW9uAaRkYXRh2gDQrlCtq2mzdmkuhwIoko5+amxYqnlfNHHZxRFiX9
F8AliP7H6S0j9uHyrBKRDWtj7VGYWVW8COy/FncLRgRhspB59rH3y/GS6pfeEw7RWUPd32
eOcB6v8q+IHUvGttyFRcN6PxSFHBhOKN0jqStP0UqXLv+d9rGWi6X/HNZGu9WPkqs/g0G9
xnf48i9pOy19aQo3HV//ubf+VYWmc1J8zjCS2Og0JkMtxbqM6j4mShPjkURZZBXSJGtORV
5IzNAzixJWmr8LR12TmFGVb0U9P79A==""".strip()

    keyfile2_cdata = unhexlify(re.sub('\W', '', """
        004078370be366ac3ad9d147992be8ebee000000000000000000000000000000000000000000000000
        b94bfb5d0a63b0c47cf74e2d0585aa
        """))
    keyfile2_id = unhexlify('45f309b4ef353c467d16a19039b87e5400000000000000000000000000000000')

    def setUp(self):
        self.tmppath = tempfile.mkdtemp()
        os.environ['ATTIC_KEYS_DIR'] = self.tmppath

    def tearDown(self):
        shutil.rmtree(self.tmppath)

    class MockRepository(object):
        class _Location(object):
            orig = '/some/place'

        _location = _Location()
        id = bytes(32)

    def _test_make_testdata(self):
        # modify tearDown to not kill the key file first, before using this
        os.environ['ATTIC_PASSPHRASE'] = 'passphrase'
        key = KeyfileKey.create(self.MockRepository(), self.MockArgs())
        print("keyfile2_key_file: find the it in the filesystem, see location in test log output")
        print("keyfile2_cdata:", hexlify(key.encrypt(b'payload')))
        print("keyfile2_id:", hexlify(key.id_hash(b'payload')))
        assert False

    def test_plaintext(self):
        key = PlaintextKey.create(None, None)
        data = b'foo'
        self.assert_equal(hexlify(key.id_hash(data)), b'2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae')
        self.assert_equal(data, key.decrypt(key.id_hash(data), key.encrypt(data)))

    def test_keyfile(self):
        os.environ['ATTIC_PASSPHRASE'] = 'test'
        key = KeyfileKey.create(self.MockRepository(), self.MockArgs())
        self.assert_equal(bytes_to_long(key.enc_iv, 8), 0)
        manifest = key.encrypt(b'XXX')
        self.assert_equal(key.extract_nonce(manifest), 0)
        manifest2 = key.encrypt(b'XXX')
        self.assert_not_equal(manifest, manifest2)
        self.assert_equal(key.decrypt(None, manifest), key.decrypt(None, manifest2))
        self.assert_equal(key.extract_nonce(manifest2), 1)
        iv = key.extract_nonce(manifest)
        key2 = KeyfileKey.detect(self.MockRepository(), manifest)
        self.assert_equal(bytes_to_long(key2.enc_iv, 8), iv + num_aes_blocks(len(manifest) - KeyfileKey.PAYLOAD_OVERHEAD))
        # Key data sanity check
        self.assert_equal(len(set([key2.id_key, key2.enc_key, key2.enc_hmac_key])), 3)
        self.assert_equal(key2.chunk_seed == 0, False)
        data = b'foo'
        self.assert_equal(data, key2.decrypt(key.id_hash(data), key.encrypt(data)))

    def test_keyfile2(self):
        with open(os.path.join(os.environ['ATTIC_KEYS_DIR'], 'keyfile'), 'w') as fd:
            fd.write(self.keyfile2_key_file)
        os.environ['ATTIC_PASSPHRASE'] = 'passphrase'
        key = KeyfileKey.detect(self.MockRepository(), self.keyfile2_cdata)
        self.assert_equal(key.decrypt(self.keyfile2_id, self.keyfile2_cdata), b'payload')

    def test_passphrase(self):
        os.environ['ATTIC_PASSPHRASE'] = 'test'
        key = PassphraseKey.create(self.MockRepository(), None)
        self.assert_equal(bytes_to_long(key.enc_iv, 8), 0)
        self.assert_equal(hexlify(key.id_key), b'793b0717f9d8fb01c751a487e9b827897ceea62409870600013fbc6b4d8d7ca6')
        self.assert_equal(hexlify(key.enc_hmac_key), b'b885a05d329a086627412a6142aaeb9f6c54ab7950f996dd65587251f6bc0901')
        self.assert_equal(hexlify(key.enc_key), b'2ff3654c6daf7381dbbe718d2b20b4f1ea1e34caa6cc65f6bb3ac376b93fed2a')
        self.assert_equal(key.chunk_seed, -775740477)
        manifest = key.encrypt(b'XXX')
        self.assert_equal(key.extract_nonce(manifest), 0)
        manifest2 = key.encrypt(b'XXX')
        self.assert_not_equal(manifest, manifest2)
        self.assert_equal(key.decrypt(None, manifest), key.decrypt(None, manifest2))
        self.assert_equal(key.extract_nonce(manifest2), 1)
        iv = key.extract_nonce(manifest)
        key2 = PassphraseKey.detect(self.MockRepository(), manifest)
        self.assert_equal(bytes_to_long(key2.enc_iv, 8), iv + num_aes_blocks(len(manifest) - PassphraseKey.PAYLOAD_OVERHEAD))
        self.assert_equal(key.id_key, key2.id_key)
        self.assert_equal(key.enc_hmac_key, key2.enc_hmac_key)
        self.assert_equal(key.enc_key, key2.enc_key)
        self.assert_equal(key.chunk_seed, key2.chunk_seed)
        data = b'foo'
        self.assert_equal(hexlify(key.id_hash(data)), b'a409d69859b8a07625f066e42cde050100000000000000000000000000000000')
        self.assert_equal(data, key2.decrypt(key2.id_hash(data), key.encrypt(data)))

import os
import re
import shutil
import tempfile
from binascii import hexlify
from attic.crypto import bytes_to_long, num_aes_blocks
from attic.testsuite import AtticTestCase
from attic.key import PlaintextKey, PassphraseKey, KeyfileKey, COMPR_DEFAULT
from attic.helpers import Location, unhexlify


class KeyTestCase(AtticTestCase):

    class MockArgs(object):
        repository = Location(tempfile.mkstemp()[1])
        compression = COMPR_DEFAULT
        mac = None
        cipher = None

    keyfile2_key_file = """
ATTIC KEY 0000000000000000000000000000000000000000000000000000000000000000
hqppdGVyYXRpb25zzgABhqCpYWxnb3JpdGhtpGdtYWOkaGFzaNoAII1CqUnJzgKISX3lwR
+wWqMAAAAAAAAAAAAAAAAAAAAApGRhdGHaANBGe/oYLxHbAq72vjwEpgNMV73dTMkZkYh4
0WtFC65DwZmqvwbwBBaq1g+fiym+khRtrn9hZvF6rpjk0RrAURSxCXIt/XUNQzQlcQjYbb
kTT0aFk3DkKbwA/pgx10s/nWBmz9xv4yT5uoewOdPV009nJnrLdIz1zJTPvy2ylejHF3Na
Sy/B/tWA9PIeRZzrDe/lVY6YBs8lKz1jtT/3vCJFCa+LOSSJHV+tExnpgO0NBTxDmTckRe
vk3IRPVUml5VXHoUYEUEj6QpBA2F4NKdSzpHNhbHTaACDh3gxO3vgi+K/KMmBebec6RhBy
QQWJNlInT3+yKnQpdqd2ZXJzaW9uAQ==""".strip()

    keyfile2_cdata = unhexlify(re.sub('\W', '', """
        03929606001402da002046c635e7ce41b65c5c075fa6afb97f5100000000000000000000000000000000
        a80000000000000000affb14944408753093ba2860edb49220
        """))
    keyfile2_id = unhexlify('94899966ce3eaad825f37500c8c87ef100000000000000000000000000000000')

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
        key = PlaintextKey.create(None, self.MockArgs())
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
        # we just assume that the payload fits into 1 AES block (which is given for b'XXX').
        self.assert_equal(bytes_to_long(key2.enc_iv, 8), iv + 1)
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
        key = PassphraseKey.create(self.MockRepository(), self.MockArgs())
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
        # we just assume that the payload fits into 1 AES block (which is given for b'XXX').
        self.assert_equal(bytes_to_long(key2.enc_iv, 8), iv + 1)
        self.assert_equal(key.id_key, key2.id_key)
        self.assert_equal(key.enc_hmac_key, key2.enc_hmac_key)
        self.assert_equal(key.enc_key, key2.enc_key)
        self.assert_equal(key.chunk_seed, key2.chunk_seed)
        data = b'foo'
        self.assert_equal(hexlify(key.id_hash(data)), b'a409d69859b8a07625f066e42cde050100000000000000000000000000000000')
        self.assert_equal(data, key2.decrypt(key2.id_hash(data), key.encrypt(data)))

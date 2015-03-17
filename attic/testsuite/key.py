import os
import re
import shutil
import tempfile
from binascii import hexlify
from attic.crypto import bytes_to_long
from attic.testsuite import AtticTestCase
from attic.key import PlaintextKey, PassphraseKey, KeyfileKey, COMPR_DEFAULT
from attic.helpers import Location, unhexlify


class KeyTestCase(AtticTestCase):

    class MockArgs:
        repository = Location(tempfile.mkstemp()[1])
        compression = COMPR_DEFAULT
        mac = None
        cipher = None

    keyfile2_key_file = """
ATTIC KEY 0000000000000000000000000000000000000000000000000000000000000000
hqlhbGdvcml0aG2kZ21hY6d2ZXJzaW9uAaRoYXNo2gAgeXkW700i+1t5mroRI9YQuAAAAA
AAAAAAAAAAAAAAAACkZGF0YdoA0FVh2YsC4Nd5Pd+9wm6m/HbXnfy7ahBQNUp/grFY/LN7
CPZYHM9tblJ40Kklnn6pktJhgEizgOzK435wbRWeuYiLO4+W0AEX74i0GcFafOhN7DyLYA
jE1qQMTm7tK2LlapnKVOOiH3KV67pdSMtRYDrHbx0Gud3jBtfMGU39nuwEFfWwIzQ8b4Tm
SWlG6orGwmvRJn8a5H+JtOY90e+tM7s2M4VF6p8grtUyighYxJrO4Y78/fsDpSHbYAh+en
6GrpcESLKYoDtgqiyjle0LpQ6kc2FsdNoAIKhlgtF1As4InTAsR3bCQif78vGjYYMKerJQ
ge5ZaKvpqml0ZXJhdGlvbnPOAAGGoA==""".strip()

    keyfile2_cdata = unhexlify(re.sub('\W', '', """
        03929600001402c4207f9b12b337e123e322ca2af795788ee100000000000000000000000000000000
        c4080000000000000000c407624711de25ab38
        """))
    keyfile2_id = unhexlify('4d532cec0eb8ec34d65c5491b5158b1400000000000000000000000000000000')

    def setUp(self):
        self.tmppath = tempfile.mkdtemp()
        os.environ['ATTIC_KEYS_DIR'] = self.tmppath

    def tearDown(self):
        shutil.rmtree(self.tmppath)

    class MockRepository:
        class _Location:
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
        self.assert_equal(hexlify(key.id_hash(data)), b'4c9137bc0dd3ddb31de4e138a49d7eb300000000000000000000000000000000')
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

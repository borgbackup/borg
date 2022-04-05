import getpass
import os.path
import re
import tempfile
from binascii import hexlify, unhexlify

import pytest

from ..crypto.key import bin_to_hex
from ..crypto.key import PlaintextKey, AuthenticatedKey, RepoKey, KeyfileKey, \
    Blake2KeyfileKey, Blake2RepoKey, Blake2AuthenticatedKey, \
    AESOCBKeyfileKey, AESOCBRepoKey, CHPOKeyfileKey, CHPORepoKey
from ..crypto.key import ID_HMAC_SHA_256, ID_BLAKE2b_256
from ..crypto.key import TAMRequiredError, TAMInvalid, TAMUnsupportedSuiteError, UnsupportedManifestError
from ..crypto.key import identify_key
from ..crypto.low_level import bytes_to_long
from ..crypto.low_level import IntegrityError as IntegrityErrorBase
from ..helpers import IntegrityError
from ..helpers import Location
from ..helpers import StableDict
from ..helpers import get_security_dir
from ..helpers import msgpack


class TestKey:
    class MockArgs:
        location = Location(tempfile.mkstemp()[1])
        key_algorithm = "argon2"

    keyfile2_key_file = """
        BORG_KEY 0000000000000000000000000000000000000000000000000000000000000000
        hqlhbGdvcml0aG2mc2hhMjU2pGRhdGHaAN4u2SiN7hqISe3OA8raBWNuvHn1R50ZU7HVCn
        11vTJNEaj9soxUaIGcW+pAB2N5yYoKMg/sGCMuZa286iJ008DvN99rf/ORfcKrK2GmzslO
        N3uv9Tk9HtqV/Sq5zgM9xuY9rEeQGDQVQ+AOsFamJqSUrAemGJbJqw9IerXC/jN4XPnX6J
        pi1cXCFxHfDaEhmWrkdPNoZdirCv/eP/dOVOLmwU58YsS+MvkZNfEa16el/fSb/ENdrwJ/
        2aYMQrDdk1d5MYzkjotv/KpofNwPXZchu2EwH7OIHWQjEVL1DZWkaGFzaNoAIO/7qn1hr3
        F84MsMMiqpbz4KVICeBZhfAaTPs4W7BC63qml0ZXJhdGlvbnPOAAGGoKRzYWx02gAgLENQ
        2uVCoR7EnAoiRzn8J+orbojKtJlNCnQ31SSC8rendmVyc2lvbgE=""".strip()

    keyfile2_cdata = unhexlify(re.sub(r'\W', '', """
        0055f161493fcfc16276e8c31493c4641e1eb19a79d0326fad0291e5a9c98e5933
        00000000000003e8d21eaf9b86c297a8cd56432e1915bb
        """))
    keyfile2_id = unhexlify('c3fbf14bc001ebcc3cd86e696c13482ed071740927cd7cbe1b01b4bfcee49314')

    keyfile_blake2_key_file = """
        BORG_KEY 0000000000000000000000000000000000000000000000000000000000000000
        hqlhbGdvcml0aG2mc2hhMjU2pGRhdGHaAZ7VCsTjbLhC1ipXOyhcGn7YnROEhP24UQvOCi
        Oar1G+JpwgO9BIYaiCODUpzPuDQEm6WxyTwEneJ3wsuyeqyh7ru2xo9FAUKRf6jcqqZnan
        ycTfktkUC+CPhKR7W6MTu5fPvy99chyL09/RGdD15aswR5PjNoFu4626sfMrBReyPdlxqt
        F80m+fbNE/vln2Trqoz9EMHQ3IxjIK4q0m4Aj7TwCu7ZankFtwt898+tYsWE7lb2Ps/gXB
        F8PM/5wHpYps2AKhDCpwKp5HyqIqlF5IzR2ydL9QP20QBjp/rSi6b+xwrfxNJZfw78f8ef
        A2Yj7xIsxNQ0kmVmTL/UF6d7+Mw1JfurWrySiDU7QQ+RiZpWUZ0DdReB+e4zn6/KNKC884
        34SGywADuLIQe2FKU+5jBCbutEyEGILQbAR/cgeLy5+V2XwXMJh4ytwXVIeT6Lk+qhYAdz
        Klx4ub7XijKcOxJyBE+4k33DAhcfIT2r4/sxgMhXrIOEQPKsMAixzdcqVYkpou+6c4PZeL
        nr+UjfJwOqK1BlWk1NgwE4GXYIKkaGFzaNoAIAzjUtpBPPh6kItZtHQZvnQG6FpucZNfBC
        UTHFJg343jqml0ZXJhdGlvbnPOAAGGoKRzYWx02gAgz3YaUZZ/s+UWywj97EY5b4KhtJYi
        qkPqtDDxs2j/T7+ndmVyc2lvbgE=""".strip()

    keyfile_blake2_cdata = bytes.fromhex('04fdf9475cf2323c0ba7a99ddc011064f2e7d039f539f2e448'
                                         '0e6f5fc6ff9993d604040404040404098c8cee1c6db8c28947')
    # Verified against b2sum. Entire string passed to BLAKE2, including the padded 64 byte key contained in
    # keyfile_blake2_key_file above is
    # 19280471de95185ec27ecb6fc9edbb4f4db26974c315ede1cd505fab4250ce7cd0d081ea66946c
    # 95f0db934d5f616921efbd869257e8ded2bd9bd93d7f07b1a30000000000000000000000000000
    # 000000000000000000000000000000000000000000000000000000000000000000000000000000
    # 00000000000000000000007061796c6f6164
    #                       p a y l o a d
    keyfile_blake2_id = bytes.fromhex('d8bc68e961c79f99be39061589e5179b2113cd9226e07b08ddd4a1fef7ce93fb')

    @pytest.fixture
    def keys_dir(self, request, monkeypatch, tmpdir):
        monkeypatch.setenv('BORG_KEYS_DIR', str(tmpdir))
        return tmpdir

    @pytest.fixture(params=(
        PlaintextKey,
        AuthenticatedKey,
        KeyfileKey,
        RepoKey,
        AuthenticatedKey,
        Blake2KeyfileKey,
        Blake2RepoKey,
        Blake2AuthenticatedKey,
        AESOCBKeyfileKey, AESOCBRepoKey,
        CHPOKeyfileKey, CHPORepoKey,
    ))
    def key(self, request, monkeypatch):
        monkeypatch.setenv('BORG_PASSPHRASE', 'test')
        return request.param.create(self.MockRepository(), self.MockArgs())

    class MockRepository:
        class _Location:
            raw = processed = '/some/place'

            def canonical_path(self):
                return self.processed

        _location = _Location()
        id = bytes(32)
        id_str = bin_to_hex(id)

        def get_free_nonce(self):
            return None

        def commit_nonce_reservation(self, next_unreserved, start_nonce):
            pass

        def save_key(self, data):
            self.key_data = data

        def load_key(self):
            return self.key_data

    def test_plaintext(self):
        key = PlaintextKey.create(None, None)
        chunk = b'foo'
        id = key.id_hash(chunk)
        assert hexlify(id) == b'2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae'
        assert chunk == key.decrypt(id, key.encrypt(id, chunk))

    def test_keyfile(self, monkeypatch, keys_dir):
        monkeypatch.setenv('BORG_PASSPHRASE', 'test')
        key = KeyfileKey.create(self.MockRepository(), self.MockArgs())
        assert key.cipher.next_iv() == 0
        chunk = b'ABC'
        id = key.id_hash(chunk)
        manifest = key.encrypt(id, chunk)
        assert key.cipher.extract_iv(manifest) == 0
        manifest2 = key.encrypt(id, chunk)
        assert manifest != manifest2
        assert key.decrypt(id, manifest) == key.decrypt(id, manifest2)
        assert key.cipher.extract_iv(manifest2) == 1
        iv = key.cipher.extract_iv(manifest)
        key2 = KeyfileKey.detect(self.MockRepository(), manifest)
        assert key2.cipher.next_iv() >= iv + key2.cipher.block_count(len(manifest) - KeyfileKey.PAYLOAD_OVERHEAD)
        # Key data sanity check
        assert len({key2.id_key, key2.enc_key, key2.enc_hmac_key}) == 3
        assert key2.chunk_seed != 0
        chunk = b'foo'
        id = key.id_hash(chunk)
        assert chunk == key2.decrypt(id, key.encrypt(id, chunk))

    def test_keyfile_nonce_rollback_protection(self, monkeypatch, keys_dir):
        monkeypatch.setenv('BORG_PASSPHRASE', 'test')
        repository = self.MockRepository()
        with open(os.path.join(get_security_dir(repository.id_str), 'nonce'), "w") as fd:
            fd.write("0000000000002000")
        key = KeyfileKey.create(repository, self.MockArgs())
        chunk = b'ABC'
        id = key.id_hash(chunk)
        data = key.encrypt(id, chunk)
        assert key.cipher.extract_iv(data) == 0x2000
        assert key.decrypt(id, data) == chunk

    def test_keyfile_kfenv(self, tmpdir, monkeypatch):
        keyfile = tmpdir.join('keyfile')
        monkeypatch.setenv('BORG_KEY_FILE', str(keyfile))
        monkeypatch.setenv('BORG_PASSPHRASE', 'testkf')
        assert not keyfile.exists()
        key = KeyfileKey.create(self.MockRepository(), self.MockArgs())
        assert keyfile.exists()
        chunk = b'ABC'
        chunk_id = key.id_hash(chunk)
        chunk_cdata = key.encrypt(chunk_id, chunk)
        key = KeyfileKey.detect(self.MockRepository(), chunk_cdata)
        assert chunk == key.decrypt(chunk_id, chunk_cdata)
        keyfile.remove()
        with pytest.raises(FileNotFoundError):
            KeyfileKey.detect(self.MockRepository(), chunk_cdata)

    def test_keyfile2(self, monkeypatch, keys_dir):
        with keys_dir.join('keyfile').open('w') as fd:
            fd.write(self.keyfile2_key_file)
        monkeypatch.setenv('BORG_PASSPHRASE', 'passphrase')
        key = KeyfileKey.detect(self.MockRepository(), self.keyfile2_cdata)
        assert key.decrypt(self.keyfile2_id, self.keyfile2_cdata) == b'payload'

    def test_keyfile2_kfenv(self, tmpdir, monkeypatch):
        keyfile = tmpdir.join('keyfile')
        with keyfile.open('w') as fd:
            fd.write(self.keyfile2_key_file)
        monkeypatch.setenv('BORG_KEY_FILE', str(keyfile))
        monkeypatch.setenv('BORG_PASSPHRASE', 'passphrase')
        key = KeyfileKey.detect(self.MockRepository(), self.keyfile2_cdata)
        assert key.decrypt(self.keyfile2_id, self.keyfile2_cdata) == b'payload'

    def test_keyfile_blake2(self, monkeypatch, keys_dir):
        with keys_dir.join('keyfile').open('w') as fd:
            fd.write(self.keyfile_blake2_key_file)
        monkeypatch.setenv('BORG_PASSPHRASE', 'passphrase')
        key = Blake2KeyfileKey.detect(self.MockRepository(), self.keyfile_blake2_cdata)
        assert key.decrypt(self.keyfile_blake2_id, self.keyfile_blake2_cdata) == b'payload'

    def _corrupt_byte(self, key, data, offset):
        data = bytearray(data)
        # note: we corrupt in a way so that even corruption of the unauthenticated encryption type byte
        # will trigger an IntegrityError (does not happen while we stay within TYPES_ACCEPTABLE).
        data[offset] ^= 64
        with pytest.raises(IntegrityErrorBase):
            key.decrypt(b'', data)

    def test_decrypt_integrity(self, monkeypatch, keys_dir):
        with keys_dir.join('keyfile').open('w') as fd:
            fd.write(self.keyfile2_key_file)
        monkeypatch.setenv('BORG_PASSPHRASE', 'passphrase')
        key = KeyfileKey.detect(self.MockRepository(), self.keyfile2_cdata)

        data = self.keyfile2_cdata
        for i in range(len(data)):
            self._corrupt_byte(key, data, i)

        with pytest.raises(IntegrityError):
            data = bytearray(self.keyfile2_cdata)
            id = bytearray(key.id_hash(data))  # corrupt chunk id
            id[12] = 0
            key.decrypt(id, data)

    def test_roundtrip(self, key):
        repository = key.repository
        plaintext = b'foo'
        id = key.id_hash(plaintext)
        encrypted = key.encrypt(id, plaintext)
        identified_key_class = identify_key(encrypted)
        assert identified_key_class == key.__class__
        loaded_key = identified_key_class.detect(repository, encrypted)
        decrypted = loaded_key.decrypt(id, encrypted)
        assert decrypted == plaintext

    def test_decrypt_decompress(self, key):
        plaintext = b'123456789'
        id = key.id_hash(plaintext)
        encrypted = key.encrypt(id, plaintext)
        assert key.decrypt(id, encrypted, decompress=False) != plaintext
        assert key.decrypt(id, encrypted) == plaintext

    def test_assert_id(self, key):
        plaintext = b'123456789'
        id = key.id_hash(plaintext)
        key.assert_id(id, plaintext)
        id_changed = bytearray(id)
        id_changed[0] ^= 1
        with pytest.raises(IntegrityError):
            key.assert_id(id_changed, plaintext)
        plaintext_changed = plaintext + b'1'
        with pytest.raises(IntegrityError):
            key.assert_id(id, plaintext_changed)

    def test_authenticated_encrypt(self, monkeypatch):
        monkeypatch.setenv('BORG_PASSPHRASE', 'test')
        key = AuthenticatedKey.create(self.MockRepository(), self.MockArgs())
        assert AuthenticatedKey.id_hash is ID_HMAC_SHA_256.id_hash
        assert len(key.id_key) == 32
        plaintext = b'123456789'
        id = key.id_hash(plaintext)
        authenticated = key.encrypt(id, plaintext)
        # 0x07 is the key TYPE, \x0000 identifies no compression.
        assert authenticated == b'\x07\x00\x00' + plaintext

    def test_blake2_authenticated_encrypt(self, monkeypatch):
        monkeypatch.setenv('BORG_PASSPHRASE', 'test')
        key = Blake2AuthenticatedKey.create(self.MockRepository(), self.MockArgs())
        assert Blake2AuthenticatedKey.id_hash is ID_BLAKE2b_256.id_hash
        assert len(key.id_key) == 128
        plaintext = b'123456789'
        id = key.id_hash(plaintext)
        authenticated = key.encrypt(id, plaintext)
        # 0x06 is the key TYPE, 0x0000 identifies no compression.
        assert authenticated == b'\x06\x00\x00' + plaintext


class TestTAM:
    @pytest.fixture
    def key(self, monkeypatch):
        monkeypatch.setenv('BORG_PASSPHRASE', 'test')
        return KeyfileKey.create(TestKey.MockRepository(), TestKey.MockArgs())

    def test_unpack_future(self, key):
        blob = b'\xc1\xc1\xc1\xc1foobar'
        with pytest.raises(UnsupportedManifestError):
            key.unpack_and_verify_manifest(blob)

        blob = b'\xc1\xc1\xc1'
        with pytest.raises(msgpack.UnpackException):
            key.unpack_and_verify_manifest(blob)

    def test_missing_when_required(self, key):
        blob = msgpack.packb({})
        with pytest.raises(TAMRequiredError):
            key.unpack_and_verify_manifest(blob)

    def test_missing(self, key):
        blob = msgpack.packb({})
        key.tam_required = False
        unpacked, verified = key.unpack_and_verify_manifest(blob)
        assert unpacked == {}
        assert not verified

    def test_unknown_type_when_required(self, key):
        blob = msgpack.packb({
            'tam': {
                'type': 'HMAC_VOLLBIT',
            },
        })
        with pytest.raises(TAMUnsupportedSuiteError):
            key.unpack_and_verify_manifest(blob)

    def test_unknown_type(self, key):
        blob = msgpack.packb({
            'tam': {
                'type': 'HMAC_VOLLBIT',
            },
        })
        key.tam_required = False
        unpacked, verified = key.unpack_and_verify_manifest(blob)
        assert unpacked == {}
        assert not verified

    @pytest.mark.parametrize('tam, exc', (
        ({}, TAMUnsupportedSuiteError),
        ({'type': b'\xff'}, TAMUnsupportedSuiteError),
        (None, TAMInvalid),
        (1234, TAMInvalid),
    ))
    def test_invalid(self, key, tam, exc):
        blob = msgpack.packb({
            'tam': tam,
        })
        with pytest.raises(exc):
            key.unpack_and_verify_manifest(blob)

    @pytest.mark.parametrize('hmac, salt', (
        ({}, bytes(64)),
        (bytes(64), {}),
        (None, bytes(64)),
        (bytes(64), None),
    ))
    def test_wrong_types(self, key, hmac, salt):
        data = {
            'tam': {
                'type': 'HKDF_HMAC_SHA512',
                'hmac': hmac,
                'salt': salt
            },
        }
        tam = data['tam']
        if hmac is None:
            del tam['hmac']
        if salt is None:
            del tam['salt']
        blob = msgpack.packb(data)
        with pytest.raises(TAMInvalid):
            key.unpack_and_verify_manifest(blob)

    def test_round_trip(self, key):
        data = {'foo': 'bar'}
        blob = key.pack_and_authenticate_metadata(data)
        assert blob.startswith(b'\x82')

        unpacked = msgpack.unpackb(blob)
        assert unpacked[b'tam'][b'type'] == b'HKDF_HMAC_SHA512'

        unpacked, verified = key.unpack_and_verify_manifest(blob)
        assert verified
        assert unpacked[b'foo'] == b'bar'
        assert b'tam' not in unpacked

    @pytest.mark.parametrize('which', (b'hmac', b'salt'))
    def test_tampered(self, key, which):
        data = {'foo': 'bar'}
        blob = key.pack_and_authenticate_metadata(data)
        assert blob.startswith(b'\x82')

        unpacked = msgpack.unpackb(blob, object_hook=StableDict)
        assert len(unpacked[b'tam'][which]) == 64
        unpacked[b'tam'][which] = unpacked[b'tam'][which][0:32] + bytes(32)
        assert len(unpacked[b'tam'][which]) == 64
        blob = msgpack.packb(unpacked)

        with pytest.raises(TAMInvalid):
            key.unpack_and_verify_manifest(blob)

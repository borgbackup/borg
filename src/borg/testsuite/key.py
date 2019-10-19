import getpass
import os.path
import re
import tempfile
from binascii import hexlify, unhexlify

import pytest

from ..crypto.key import Passphrase, PasswordRetriesExceeded, bin_to_hex
from ..crypto.key import PlaintextKey, PassphraseKey, AuthenticatedKey, RepoKey, KeyfileKey, \
    Blake2KeyfileKey, Blake2RepoKey, Blake2AuthenticatedKey
from ..crypto.key import ID_HMAC_SHA_256, ID_BLAKE2b_256
from ..crypto.key import TAMRequiredError, TAMInvalid, TAMUnsupportedSuiteError, UnsupportedManifestError
from ..crypto.key import identify_key
from ..crypto.low_level import bytes_to_long, num_aes_blocks
from ..helpers import IntegrityError
from ..helpers import Location
from ..helpers import StableDict
from ..helpers import get_security_dir
from ..helpers import msgpack


class TestKey:
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

    keyfile2_cdata = unhexlify(re.sub(r'\W', '', """
        0055f161493fcfc16276e8c31493c4641e1eb19a79d0326fad0291e5a9c98e5933
        00000000000003e8d21eaf9b86c297a8cd56432e1915bb
        """))
    keyfile2_id = unhexlify('c3fbf14bc001ebcc3cd86e696c13482ed071740927cd7cbe1b01b4bfcee49314')

    keyfile_blake2_key_file = """
        BORG_KEY 0000000000000000000000000000000000000000000000000000000000000000
        hqlhbGdvcml0aG2mc2hhMjU2pGRhdGHaAZBu680Do3CmfWzeMCwe48KJi3Vps9mEDy7MKF
        TastsEhiAd1RQMuxfZpklkLeddMMWk+aPtFiURRFb02JLXV5cKRC1o2ZDdiNa0nao+o6+i
        gUjjsea9TAu25t3vxh8uQWs5BuKRLBRr0nUgrSd0IYMUgn+iVbLJRzCCssvxsklkwQxN3F
        Y+MvBnn8kUXSeoSoQ2l0fBHzq94Y7LMOm/owMam5URnE8/UEc6ZXBrbyX4EXxDtUqJcs+D
        i451thtlGdigDLpvf9nyK66mjiCpPCTCgtlzq0Pe1jcdhnsUYLg+qWzXZ7e2opEZoC6XxS
        3DIuBOxG3Odqj9IKB+6/kl94vz98awPWFSpYcLZVWu7sIP38ZkUK+ad5MHTo/LvTuZdFnd
        iqKzZIDUJl3Zl1WGmP/0xVOmfIlznkCZy4d3SMuujwIcqQ5kDvwDRPpdhBBk+UWQY5vFXk
        kR1NBNLSTyhAzu3fiUmFl0qZ+UWPRkGAEBy/NuoEibrWwab8BX97cATyvnmOqYkU9PT0C6
        l2l9E4bPpGhhc2jaACDnIa8KgKv84/b5sjaMgSZeIVkuKSLJy2NN8zoH8lnd36ppdGVyYX
        Rpb25zzgABhqCkc2FsdNoAIEJLlLh7q74j3q53856H5GgzA1HH+aW5bA/as544+PGkp3Zl
        cnNpb24B""".strip()

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
        Blake2KeyfileKey,
        Blake2RepoKey,
        Blake2AuthenticatedKey,
    ))
    def key(self, request, monkeypatch):
        monkeypatch.setenv('BORG_PASSPHRASE', 'test')
        return request.param.create(self.MockRepository(), self.MockArgs())

    class MockRepository:
        class _Location:
            orig = '/some/place'

            def canonical_path(self):
                return self.orig

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
        assert hexlify(key.id_hash(chunk)) == b'2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae'
        assert chunk == key.decrypt(key.id_hash(chunk), key.encrypt(chunk))

    def test_keyfile(self, monkeypatch, keys_dir):
        monkeypatch.setenv('BORG_PASSPHRASE', 'test')
        key = KeyfileKey.create(self.MockRepository(), self.MockArgs())
        assert bytes_to_long(key.enc_cipher.iv, 8) == 0
        manifest = key.encrypt(b'ABC')
        assert key.extract_nonce(manifest) == 0
        manifest2 = key.encrypt(b'ABC')
        assert manifest != manifest2
        assert key.decrypt(None, manifest) == key.decrypt(None, manifest2)
        assert key.extract_nonce(manifest2) == 1
        iv = key.extract_nonce(manifest)
        key2 = KeyfileKey.detect(self.MockRepository(), manifest)
        assert bytes_to_long(key2.enc_cipher.iv, 8) >= iv + num_aes_blocks(len(manifest) - KeyfileKey.PAYLOAD_OVERHEAD)
        # Key data sanity check
        assert len({key2.id_key, key2.enc_key, key2.enc_hmac_key}) == 3
        assert key2.chunk_seed != 0
        chunk = b'foo'
        assert chunk == key2.decrypt(key.id_hash(chunk), key.encrypt(chunk))

    def test_keyfile_nonce_rollback_protection(self, monkeypatch, keys_dir):
        monkeypatch.setenv('BORG_PASSPHRASE', 'test')
        repository = self.MockRepository()
        with open(os.path.join(get_security_dir(repository.id_str), 'nonce'), "w") as fd:
            fd.write("0000000000002000")
        key = KeyfileKey.create(repository, self.MockArgs())
        data = key.encrypt(b'ABC')
        assert key.extract_nonce(data) == 0x2000
        assert key.decrypt(None, data) == b'ABC'

    def test_keyfile_kfenv(self, tmpdir, monkeypatch):
        keyfile = tmpdir.join('keyfile')
        monkeypatch.setenv('BORG_KEY_FILE', str(keyfile))
        monkeypatch.setenv('BORG_PASSPHRASE', 'testkf')
        assert not keyfile.exists()
        key = KeyfileKey.create(self.MockRepository(), self.MockArgs())
        assert keyfile.exists()
        chunk = b'ABC'
        chunk_id = key.id_hash(chunk)
        chunk_cdata = key.encrypt(chunk)
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

    def test_passphrase(self, keys_dir, monkeypatch):
        monkeypatch.setenv('BORG_PASSPHRASE', 'test')
        key = PassphraseKey.create(self.MockRepository(), None)
        assert bytes_to_long(key.enc_cipher.iv, 8) == 0
        assert hexlify(key.id_key) == b'793b0717f9d8fb01c751a487e9b827897ceea62409870600013fbc6b4d8d7ca6'
        assert hexlify(key.enc_hmac_key) == b'b885a05d329a086627412a6142aaeb9f6c54ab7950f996dd65587251f6bc0901'
        assert hexlify(key.enc_key) == b'2ff3654c6daf7381dbbe718d2b20b4f1ea1e34caa6cc65f6bb3ac376b93fed2a'
        assert key.chunk_seed == -775740477
        manifest = key.encrypt(b'ABC')
        assert key.extract_nonce(manifest) == 0
        manifest2 = key.encrypt(b'ABC')
        assert manifest != manifest2
        assert key.decrypt(None, manifest) == key.decrypt(None, manifest2)
        assert key.extract_nonce(manifest2) == 1
        iv = key.extract_nonce(manifest)
        key2 = PassphraseKey.detect(self.MockRepository(), manifest)
        assert bytes_to_long(key2.enc_cipher.iv, 8) == iv + num_aes_blocks(len(manifest) - PassphraseKey.PAYLOAD_OVERHEAD)
        assert key.id_key == key2.id_key
        assert key.enc_hmac_key == key2.enc_hmac_key
        assert key.enc_key == key2.enc_key
        assert key.chunk_seed == key2.chunk_seed
        chunk = b'foo'
        assert hexlify(key.id_hash(chunk)) == b'818217cf07d37efad3860766dcdf1d21e401650fed2d76ed1d797d3aae925990'
        assert chunk == key2.decrypt(key2.id_hash(chunk), key.encrypt(chunk))

    def _corrupt_byte(self, key, data, offset):
        data = bytearray(data)
        data[offset] ^= 1
        with pytest.raises(IntegrityError):
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
        encrypted = key.encrypt(plaintext)
        identified_key_class = identify_key(encrypted)
        assert identified_key_class == key.__class__
        loaded_key = identified_key_class.detect(repository, encrypted)
        decrypted = loaded_key.decrypt(None, encrypted)
        assert decrypted == plaintext

    def test_decrypt_decompress(self, key):
        plaintext = b'123456789'
        encrypted = key.encrypt(plaintext)
        assert key.decrypt(None, encrypted, decompress=False) != plaintext
        assert key.decrypt(None, encrypted) == plaintext

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
        authenticated = key.encrypt(plaintext)
        # 0x07 is the key TYPE, 0x0100 identifies LZ4 compression, 0x90 is part of LZ4 and means that an uncompressed
        # block of length nine follows (the plaintext).
        assert authenticated == b'\x07\x01\x00\x90' + plaintext

    def test_blake2_authenticated_encrypt(self, monkeypatch):
        monkeypatch.setenv('BORG_PASSPHRASE', 'test')
        key = Blake2AuthenticatedKey.create(self.MockRepository(), self.MockArgs())
        assert Blake2AuthenticatedKey.id_hash is ID_BLAKE2b_256.id_hash
        assert len(key.id_key) == 128
        plaintext = b'123456789'
        authenticated = key.encrypt(plaintext)
        # 0x06 is the key TYPE, 0x0100 identifies LZ4 compression, 0x90 is part of LZ4 and means that an uncompressed
        # block of length nine follows (the plaintext).
        assert authenticated == b'\x06\x01\x00\x90' + plaintext


class TestPassphrase:
    def test_passphrase_new_verification(self, capsys, monkeypatch):
        monkeypatch.setattr(getpass, 'getpass', lambda prompt: "12aöäü")
        monkeypatch.setenv('BORG_DISPLAY_PASSPHRASE', 'no')
        Passphrase.new()
        out, err = capsys.readouterr()
        assert "12" not in out
        assert "12" not in err

        monkeypatch.setenv('BORG_DISPLAY_PASSPHRASE', 'yes')
        passphrase = Passphrase.new()
        out, err = capsys.readouterr()
        assert "313261c3b6c3a4c3bc" not in out
        assert "313261c3b6c3a4c3bc" in err
        assert passphrase == "12aöäü"

        monkeypatch.setattr(getpass, 'getpass', lambda prompt: "1234/@=")
        Passphrase.new()
        out, err = capsys.readouterr()
        assert "1234/@=" not in out
        assert "1234/@=" in err

    def test_passphrase_new_empty(self, capsys, monkeypatch):
        monkeypatch.delenv('BORG_PASSPHRASE', False)
        monkeypatch.setattr(getpass, 'getpass', lambda prompt: "")
        with pytest.raises(PasswordRetriesExceeded):
            Passphrase.new(allow_empty=False)
        out, err = capsys.readouterr()
        assert "must not be blank" in err

    def test_passphrase_new_retries(self, monkeypatch):
        monkeypatch.delenv('BORG_PASSPHRASE', False)
        ascending_numbers = iter(range(20))
        monkeypatch.setattr(getpass, 'getpass', lambda prompt: str(next(ascending_numbers)))
        with pytest.raises(PasswordRetriesExceeded):
            Passphrase.new()

    def test_passphrase_repr(self):
        assert "secret" not in repr(Passphrase("secret"))


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
        with pytest.raises((ValueError, msgpack.UnpackException)):
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

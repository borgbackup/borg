import getpass
import re
import tempfile
import os.path
from binascii import hexlify, unhexlify

import pytest

from ..crypto import bytes_to_long, num_aes_blocks
from ..helpers import Location
from ..helpers import Chunk
from ..helpers import IntegrityError
from ..helpers import get_nonces_dir
from ..key import PlaintextKey, PassphraseKey, KeyfileKey, Passphrase, PasswordRetriesExceeded, bin_to_hex


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    # Workaround for some tests (testsuite/archiver) polluting the environment
    monkeypatch.delenv('BORG_PASSPHRASE', False)


@pytest.fixture(autouse=True)
def nonce_dir(tmpdir_factory, monkeypatch):
    monkeypatch.setenv('XDG_CONFIG_HOME', tmpdir_factory.mktemp('xdg-config-home'))


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

    keyfile2_cdata = unhexlify(re.sub('\W', '', """
        0055f161493fcfc16276e8c31493c4641e1eb19a79d0326fad0291e5a9c98e5933
        00000000000003e8d21eaf9b86c297a8cd56432e1915bb
        """))
    keyfile2_id = unhexlify('c3fbf14bc001ebcc3cd86e696c13482ed071740927cd7cbe1b01b4bfcee49314')

    @pytest.fixture
    def keys_dir(self, request, monkeypatch, tmpdir):
        monkeypatch.setenv('BORG_KEYS_DIR', tmpdir)
        return tmpdir

    @pytest.fixture(params=(
        KeyfileKey,
        PlaintextKey
    ))
    def key(self, request, monkeypatch):
        monkeypatch.setenv('BORG_PASSPHRASE', 'test')
        return request.param.create(self.MockRepository(), self.MockArgs())

    class MockRepository:
        class _Location:
            orig = '/some/place'

        _location = _Location()
        id = bytes(32)
        id_str = bin_to_hex(id)

        def get_free_nonce(self):
            return None

        def commit_nonce_reservation(self, next_unreserved, start_nonce):
            pass

    def test_plaintext(self):
        key = PlaintextKey.create(None, None)
        chunk = Chunk(b'foo')
        assert hexlify(key.id_hash(chunk.data)) == b'2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae'
        assert chunk == key.decrypt(key.id_hash(chunk.data), key.encrypt(chunk))

    def test_keyfile(self, monkeypatch, keys_dir):
        monkeypatch.setenv('BORG_PASSPHRASE', 'test')
        key = KeyfileKey.create(self.MockRepository(), self.MockArgs())
        assert bytes_to_long(key.enc_cipher.iv, 8) == 0
        manifest = key.encrypt(Chunk(b'ABC'))
        assert key.extract_nonce(manifest) == 0
        manifest2 = key.encrypt(Chunk(b'ABC'))
        assert manifest != manifest2
        assert key.decrypt(None, manifest) == key.decrypt(None, manifest2)
        assert key.extract_nonce(manifest2) == 1
        iv = key.extract_nonce(manifest)
        key2 = KeyfileKey.detect(self.MockRepository(), manifest)
        assert bytes_to_long(key2.enc_cipher.iv, 8) >= iv + num_aes_blocks(len(manifest) - KeyfileKey.PAYLOAD_OVERHEAD)
        # Key data sanity check
        assert len({key2.id_key, key2.enc_key, key2.enc_hmac_key}) == 3
        assert key2.chunk_seed != 0
        chunk = Chunk(b'foo')
        assert chunk == key2.decrypt(key.id_hash(chunk.data), key.encrypt(chunk))

    def test_keyfile_nonce_rollback_protection(self, monkeypatch, keys_dir):
        monkeypatch.setenv('BORG_PASSPHRASE', 'test')
        repository = self.MockRepository()
        with open(os.path.join(get_nonces_dir(), repository.id_str), "w") as fd:
            fd.write("0000000000002000")
        key = KeyfileKey.create(repository, self.MockArgs())
        data = key.encrypt(Chunk(b'ABC'))
        assert key.extract_nonce(data) == 0x2000
        assert key.decrypt(None, data).data == b'ABC'

    def test_keyfile_kfenv(self, tmpdir, monkeypatch):
        keyfile = tmpdir.join('keyfile')
        monkeypatch.setenv('BORG_KEY_FILE', str(keyfile))
        monkeypatch.setenv('BORG_PASSPHRASE', 'testkf')
        assert not keyfile.exists()
        key = KeyfileKey.create(self.MockRepository(), self.MockArgs())
        assert keyfile.exists()
        chunk = Chunk(b'ABC')
        chunk_id = key.id_hash(chunk.data)
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
        assert key.decrypt(self.keyfile2_id, self.keyfile2_cdata).data == b'payload'

    def test_keyfile2_kfenv(self, tmpdir, monkeypatch):
        keyfile = tmpdir.join('keyfile')
        with keyfile.open('w') as fd:
            fd.write(self.keyfile2_key_file)
        monkeypatch.setenv('BORG_KEY_FILE', str(keyfile))
        monkeypatch.setenv('BORG_PASSPHRASE', 'passphrase')
        key = KeyfileKey.detect(self.MockRepository(), self.keyfile2_cdata)
        assert key.decrypt(self.keyfile2_id, self.keyfile2_cdata).data == b'payload'

    def test_passphrase(self, keys_dir, monkeypatch):
        monkeypatch.setenv('BORG_PASSPHRASE', 'test')
        key = PassphraseKey.create(self.MockRepository(), None)
        assert bytes_to_long(key.enc_cipher.iv, 8) == 0
        assert hexlify(key.id_key) == b'793b0717f9d8fb01c751a487e9b827897ceea62409870600013fbc6b4d8d7ca6'
        assert hexlify(key.enc_hmac_key) == b'b885a05d329a086627412a6142aaeb9f6c54ab7950f996dd65587251f6bc0901'
        assert hexlify(key.enc_key) == b'2ff3654c6daf7381dbbe718d2b20b4f1ea1e34caa6cc65f6bb3ac376b93fed2a'
        assert key.chunk_seed == -775740477
        manifest = key.encrypt(Chunk(b'ABC'))
        assert key.extract_nonce(manifest) == 0
        manifest2 = key.encrypt(Chunk(b'ABC'))
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
        chunk = Chunk(b'foo')
        assert hexlify(key.id_hash(chunk.data)) == b'818217cf07d37efad3860766dcdf1d21e401650fed2d76ed1d797d3aae925990'
        assert chunk == key2.decrypt(key2.id_hash(chunk.data), key.encrypt(chunk))

    def _corrupt_byte(self, key, data, offset):
        data = bytearray(data)
        data[offset] += 1
        with pytest.raises(IntegrityError):
            key.decrypt("", data)

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

    def test_decrypt_decompress(self, key):
        plaintext = Chunk(b'123456789')
        encrypted = key.encrypt(plaintext)
        assert key.decrypt(None, encrypted, decompress=False) != plaintext
        assert key.decrypt(None, encrypted) == plaintext

    def test_assert_id(self, key):
        plaintext = b'123456789'
        id = key.id_hash(plaintext)
        key.assert_id(id, plaintext)
        id_changed = bytearray(id)
        id_changed[0] += 1
        with pytest.raises(IntegrityError):
            key.assert_id(id_changed, plaintext)
        plaintext_changed = plaintext + b'1'
        with pytest.raises(IntegrityError):
            key.assert_id(id, plaintext_changed)


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

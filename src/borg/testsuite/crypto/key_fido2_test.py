"""Tests for FIDO2-protected borg keys at the key layer (borg.crypto.key).

Fido2Operations is monkeypatched at the key.py boundary (borg.crypto.fido2 module), so no
python-fido2 package and no hardware is needed: the fake token reproduces the essential
hmac-secret property (a stable secret per (credential, salt), different with/without UV).
"""

import binascii
import hashlib
import hmac
import os
import tempfile
import textwrap
from binascii import a2b_base64
from types import SimpleNamespace

import pytest

from ...constants import KEY_ALGORITHMS, KeyBlobStorage
from ...crypto.key import AESOCBKey, Fido2Error, Fido2DeviceNotFoundError, keyfile_format, keyfile_parse, store_hash
from ...helpers import Error, Location, bin_to_hex, msgpack
from ...helpers.passphrase import Passphrase, PasswordRetriesExceeded


class MockArgs:
    location = Location(tempfile.mkstemp()[1])
    key_algorithm = "argon2"
    key_location = "repokey"


class MultiKeyRepository:
    """Minimal modern repository: multiple borg keys, stored/loaded/deleted by content id."""

    class _Location:
        raw = processed = "/some/place"

        def canonical_path(self):
            return self.processed

    _location = _Location()
    version = 2

    def __init__(self, id=b"R" * 32):
        self.id = id
        self.id_str = bin_to_hex(id)
        self.keys = {}

    def store_key(self, data):
        key_id = store_hash(data).hexdigest()
        self.keys[key_id] = data
        return key_id

    def load_keys(self):
        return sorted(self.keys.items())

    def delete_key(self, key_id):
        del self.keys[key_id]

    def load_key(self):
        # storage-agnostic find_key() probes this; any stored borg key will do.
        return next(iter(self.keys.values()), b"")


@pytest.fixture
def fake_token(monkeypatch, tmp_path):
    """A fake plugged-in FIDO2 token behind a fake Fido2Operations, patched into borg.crypto.fido2."""
    token = SimpleNamespace(
        path="fake-fido2-device",
        present=True,
        credentials={},  # credential_id -> cred_random
        enroll_calls=0,
        derive_calls=[],  # list of dicts recording the derive_secret arguments
        enroll_uv=False,  # what enrollment reports as uv_required
        enroll_error=None,  # raised by enroll() when set
        wrong_secret=False,  # derive a wrong secret (e.g. "different token, same credential id")
        extra_devices=[],  # additional (path, name) entries for list_devices()
    )

    class FakeFido2Operations:
        device_name = "FakeToken"

        @classmethod
        def list_devices(cls):
            if not token.present:
                return []
            return [(token.path, "FakeToken")] + token.extra_devices

        @classmethod
        def from_path(cls, path):
            if not token.present or path != token.path:
                raise Fido2DeviceNotFoundError(f"cannot open FIDO2 device {path}")
            return cls()

        @classmethod
        def find_device(cls, credential_id):
            if token.present and credential_id in token.credentials:
                return cls()
            raise Fido2DeviceNotFoundError("no plugged-in FIDO2 device holds the credential of this borg key")

        def close(self):
            pass

        def enroll(self, user_id, *, up_required=True):
            token.enroll_calls += 1
            if token.enroll_error is not None:
                raise token.enroll_error
            credential_id, cred_random = os.urandom(16), os.urandom(32)
            token.credentials[credential_id] = cred_random
            salt = os.urandom(32)
            secret = hmac.new(cred_random + (b"UV" if token.enroll_uv else b""), salt, hashlib.sha256).digest()
            return credential_id, salt, secret, token.enroll_uv

        def derive_secret(self, credential_id, salt, *, up_required=True, uv_required=False):
            token.derive_calls.append(
                dict(credential_id=credential_id, up_required=up_required, uv_required=uv_required)
            )
            cred_random = token.credentials[credential_id]
            if token.wrong_secret:
                cred_random = b"\x00" * 32
            return hmac.new(cred_random + (b"UV" if uv_required else b""), salt, hashlib.sha256).digest()

    monkeypatch.setattr("borg.crypto.fido2.Fido2Operations", FakeFido2Operations)
    monkeypatch.setattr("borg.crypto.fido2.has_fido2", True)
    monkeypatch.setenv("BORG_KEYS_DIR", str(tmp_path))
    for var in ("BORG_PASSPHRASE", "BORG_PASSCOMMAND", "BORG_PASSPHRASE_FD", "BORG_FIDO2_DEVICE"):
        monkeypatch.delenv(var, raising=False)
    return token


def no_prompt(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("unexpected interactive passphrase prompt")

    monkeypatch.setattr(Passphrase, "getpass", classmethod(lambda cls, prompt: fail()))


def make_repo_with_fido2_key(monkeypatch, admin_passphrase="admin-secret", fido2_touch=True):
    """Create a repokey repository with the admin (passphrase) key plus one fido2 key."""
    monkeypatch.setenv("BORG_PASSPHRASE", admin_passphrase)
    repository = MultiKeyRepository()
    key = AESOCBKey.create(repository, MockArgs())
    key.add_key(label="token", fido2_device=True, fido2_touch=fido2_touch)
    monkeypatch.delenv("BORG_PASSPHRASE")
    return repository, key


def key_material(key):
    return {a: getattr(key, a) for a in ("repository_id", "crypt_key", "id_key", "chunk_seed")}


def fido2_envelope(repository):
    """Return the unpacked EncryptedKey dict of the (single) fido2 blob in the repository."""
    for data in repository.keys.values():
        _, b64 = keyfile_parse(data.decode())
        env = msgpack.unpackb(a2b_base64(b64))
        if env["algorithm"] == KEY_ALGORITHMS["fido2"]:
            return env
    raise AssertionError("no fido2 borg key found")


def test_fido2_roundtrip_repokey(fake_token, monkeypatch):
    repository, key = make_repo_with_fido2_key(monkeypatch)
    assert len(repository.keys) == 2
    no_prompt(monkeypatch)  # unlocking must not fall through to passphrase prompts
    loaded = AESOCBKey.detect(repository, manifest_data=None)
    assert key_material(loaded) == key_material(key)
    assert loaded._encrypted_key_algorithm == KEY_ALGORITHMS["fido2"]
    assert loaded._loaded_label == "token"
    # a fido2 repokey repo counts as encrypted (not "unknown unencrypted repository").
    assert loaded.logically_encrypted is True
    assert loaded.empty_passphrase is False
    # exactly one token interaction for the unlock.
    assert len(fake_token.derive_calls) == 1


def test_fido2_blob_format(fake_token, monkeypatch):
    repository, key = make_repo_with_fido2_key(monkeypatch)
    env = fido2_envelope(repository)
    assert env["version"] == 1
    assert env["algorithm"] == "fido2 hmac-secret chacha20-poly1305"
    assert env["label"] == "token"
    assert len(env["salt"]) == 32
    assert env["fido2_credential_id"] in fake_token.credentials
    assert env["fido2_up_required"] is True
    assert env["fido2_uv_required"] is False
    assert "argon2_time_cost" not in env


def test_env_passphrase_never_drives_the_token(fake_token, monkeypatch):
    repository, key = make_repo_with_fido2_key(monkeypatch)
    monkeypatch.setenv("BORG_PASSPHRASE", "admin-secret")
    loaded = AESOCBKey.detect(repository, manifest_data=None)
    assert loaded._encrypted_key_algorithm == KEY_ALGORITHMS["argon2"]
    # the passphrase unlocked the repo; the token was never touched.
    assert fake_token.derive_calls == []


def test_wrong_env_passphrase_falls_back_to_fido2(fake_token, monkeypatch):
    repository, key = make_repo_with_fido2_key(monkeypatch)
    monkeypatch.setenv("BORG_PASSPHRASE", "wrong")
    loaded = AESOCBKey.detect(repository, manifest_data=None)
    assert loaded._encrypted_key_algorithm == KEY_ALGORITHMS["fido2"]
    assert len(fake_token.derive_calls) == 1


def test_no_token_falls_back_to_passphrase_prompt(fake_token, monkeypatch):
    repository, key = make_repo_with_fido2_key(monkeypatch)
    fake_token.present = False
    monkeypatch.setattr(Passphrase, "getpass", classmethod(lambda cls, prompt: Passphrase("admin-secret")))
    loaded = AESOCBKey.detect(repository, manifest_data=None)
    assert loaded._encrypted_key_algorithm == KEY_ALGORITHMS["argon2"]
    assert fake_token.derive_calls == []


def test_only_fido2_keys_and_no_token_is_a_clear_error(fake_token, monkeypatch):
    repository, key = make_repo_with_fido2_key(monkeypatch)
    # forcibly drop the admin key: only the fido2 borg key remains.
    admin_id = next(kid for kid in repository.keys if kid != key._loaded_key_id)
    del repository.keys[admin_id]
    fake_token.present = False
    no_prompt(monkeypatch)  # a passphrase prompt could never succeed here
    with pytest.raises(Fido2Error, match="plugged in"):
        AESOCBKey.detect(repository, manifest_data=None)


def test_passphrase_retries_never_drive_the_token(fake_token, monkeypatch):
    repository, key = make_repo_with_fido2_key(monkeypatch)
    fake_token.wrong_secret = True  # fido2 unlock fails (e.g. a different token with a colliding setup)
    prompts = []

    def wrong_pass(cls, prompt):
        prompts.append(prompt)
        return Passphrase("wrong")

    monkeypatch.setattr(Passphrase, "getpass", classmethod(wrong_pass))
    with pytest.raises(PasswordRetriesExceeded):
        AESOCBKey.detect(repository, manifest_data=None)
    # the retry loop asked for passphrases, but the token was driven exactly once.
    assert len(prompts) == 3
    assert len(fake_token.derive_calls) == 1


def test_touchless_flag_is_stored_and_used(fake_token, monkeypatch):
    repository, key = make_repo_with_fido2_key(monkeypatch, fido2_touch=False)
    assert fido2_envelope(repository)["fido2_up_required"] is False
    loaded = AESOCBKey.detect(repository, manifest_data=None)
    assert loaded._encrypted_key_algorithm == KEY_ALGORITHMS["fido2"]
    assert fake_token.derive_calls[-1]["up_required"] is False


def test_uv_flag_is_stored_and_used(fake_token, monkeypatch):
    fake_token.enroll_uv = True
    repository, key = make_repo_with_fido2_key(monkeypatch)
    assert fido2_envelope(repository)["fido2_uv_required"] is True
    loaded = AESOCBKey.detect(repository, manifest_data=None)
    assert loaded._encrypted_key_algorithm == KEY_ALGORITHMS["fido2"]
    assert fake_token.derive_calls[-1]["uv_required"] is True


def test_failed_enrollment_leaves_the_key_set_unchanged(fake_token, monkeypatch):
    monkeypatch.setenv("BORG_PASSPHRASE", "admin-secret")
    repository = MultiKeyRepository()
    key = AESOCBKey.create(repository, MockArgs())
    keys_before = dict(repository.keys)
    fake_token.enroll_error = Fido2Error("simulated missed touch")
    with pytest.raises(Fido2Error):
        key.add_key(label="token", fido2_device=True)
    assert repository.keys == keys_before


def test_add_key_device_autoselection(fake_token, monkeypatch):
    monkeypatch.setenv("BORG_PASSPHRASE", "admin-secret")
    repository = MultiKeyRepository()
    key = AESOCBKey.create(repository, MockArgs())
    fake_token.present = False
    with pytest.raises(Fido2DeviceNotFoundError):
        key.add_key(label="token", fido2_device=True)
    fake_token.present = True
    fake_token.extra_devices = [("other-device", "OtherKey")]
    with pytest.raises(Fido2Error, match="multiple FIDO2 devices"):
        key.add_key(label="token", fido2_device=True)
    # with several devices plugged in, an explicit choice works.
    key.add_key(label="token", fido2_device=fake_token.path)
    assert len(repository.keys) == 2


def test_change_passphrase_refused_for_fido2_key(fake_token, monkeypatch):
    repository, key = make_repo_with_fido2_key(monkeypatch)
    loaded = AESOCBKey.detect(repository, manifest_data=None)
    assert loaded._encrypted_key_algorithm == KEY_ALGORITHMS["fido2"]
    with pytest.raises(Error, match="FIDO2"):
        loaded.change_passphrase(Passphrase("new"))


def test_add_passphrase_key_while_unlocked_via_fido2(fake_token, monkeypatch):
    repository, key = make_repo_with_fido2_key(monkeypatch)
    loaded = AESOCBKey.detect(repository, manifest_data=None)
    assert loaded._encrypted_key_algorithm == KEY_ALGORITHMS["fido2"]
    # the new passphrase-protected borg key must be argon2, not a copy of the fido2 algorithm.
    loaded.add_key(passphrase=Passphrase("user-pass"), label="user")
    monkeypatch.setenv("BORG_PASSPHRASE", "user-pass")
    reloaded = AESOCBKey.detect(repository, manifest_data=None)
    assert reloaded._encrypted_key_algorithm == KEY_ALGORITHMS["argon2"]
    assert reloaded._loaded_label == "user"


def test_remove_fido2_key(fake_token, monkeypatch):
    repository, key = make_repo_with_fido2_key(monkeypatch)
    monkeypatch.setenv("BORG_PASSPHRASE", "admin-secret")
    loaded = AESOCBKey.detect(repository, manifest_data=None)
    victim = loaded.remove_key(label="token")
    assert victim["label"] == "token"
    assert len(repository.keys) == 1
    # the admin key still unlocks.
    reloaded = AESOCBKey.detect(repository, manifest_data=None)
    assert reloaded._loaded_label == "admin"


def test_corrupt_fido2_blob_lacking_credential_id(fake_token, monkeypatch):
    repository, key = make_repo_with_fido2_key(monkeypatch)
    # strip the credential id out of the stored fido2 blob.
    for key_id, data in list(repository.keys.items()):
        text = data.decode()
        _, b64 = keyfile_parse(text)
        env = msgpack.unpackb(a2b_base64(b64))
        if env["algorithm"] == KEY_ALGORITHMS["fido2"]:
            del env["fido2_credential_id"]
            new_b64 = "\n".join(textwrap.wrap(binascii.b2a_base64(msgpack.packb(env)).decode("ascii")))
            del repository.keys[key_id]
            repository.store_key(keyfile_format(bin_to_hex(repository.id), new_b64).encode())
    monkeypatch.setenv("BORG_PASSPHRASE", "admin-secret")
    # the corrupted fido2 blob does not break unlocking via the admin key.
    loaded = AESOCBKey.detect(repository, manifest_data=None)
    assert loaded._loaded_label == "admin"


def test_change_blob_location_copies_verbatim(fake_token, monkeypatch, tmp_path):
    repository, key = make_repo_with_fido2_key(monkeypatch)
    loaded = AESOCBKey.detect(repository, manifest_data=None)
    assert loaded._encrypted_key_algorithm == KEY_ALGORITHMS["fido2"]
    blob_before = repository.keys[loaded._loaded_key_id]
    old_id = loaded._loaded_key_id
    enrolls_before = fake_token.enroll_calls
    loaded.change_blob_location(MockArgs(), KeyBlobStorage.KEYFILE)
    # the blob was moved byte-for-byte: same content, same content-derived key id, no
    # re-enrollment (which would have minted a new credential).
    assert fake_token.enroll_calls == enrolls_before
    assert old_id not in repository.keys  # removed from the repository
    with open(loaded.target, "rb") as fd:
        assert fd.read() == blob_before
    assert loaded.storage == KeyBlobStorage.KEYFILE
    # and it still unlocks from the keyfile.
    reloaded = AESOCBKey.detect(repository, manifest_data=None)
    assert reloaded._encrypted_key_algorithm == KEY_ALGORITHMS["fido2"]
    assert reloaded.storage == KeyBlobStorage.KEYFILE
    # move it back into the repository.
    reloaded.change_blob_location(MockArgs(), KeyBlobStorage.REPO)
    assert repository.keys[old_id] == blob_before
    assert not os.path.exists(loaded.target) or loaded.target == repository

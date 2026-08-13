import os
import tempfile
from binascii import a2b_base64
from unittest.mock import MagicMock

import pytest

from ...crypto.key import BLAKE3_MT_THRESHOLD_KIB, get_blake3_mt_threshold
from ...crypto.key import ChecksumKey, Blake3ChecksumKey, keyfile_parse
from ...crypto.key import AuthenticatedKey, Blake3AuthenticatedKey
from ...crypto.key import AESCTRKey, Blake2AESCTRKey, Blake2AuthenticatedKey
from ...crypto.key import LegacyPlaintextKey, LegacyAuthenticatedKey
from ...crypto.key import AEADKeyBase
from ...crypto.key import AESOCBKey, CHPOKey, Blake3AESOCBKey, Blake3CHPOKey
from ...crypto.key import AES_OCB_MAX_SESSION_BLOCKS
from ...crypto.key import ID_HMAC_SHA_256, ID_BLAKE2b_256, ID_BLAKE3_256
from ...crypto.key import UnsupportedManifestError, UnsupportedKeyFormatError, UnsupportedPayloadError
from ...crypto.key import identify_key
from ...crypto.low_level import IntegrityError as IntegrityErrorBase
from ...helpers import Error
from ...helpers import IntegrityError
from ...helpers import Location
from ...helpers import msgpack
from ...constants import KEY_ALGORITHMS, KeyBlobStorage, KeyType, ROBJ_MANIFEST
from ...helpers import hex_to_bin, bin_to_hex


class TestKey:
    class MockArgs:
        location = Location(tempfile.mkstemp()[1])
        key_algorithm = "argon2"
        key_location = "repokey"  # default storage; tests that want a keyfile use kf_args() below

    @classmethod
    def kf_args(cls):
        # like MockArgs(), but selects keyfile storage (the unified key classes default to repokey).
        args = cls.MockArgs()
        args.key_location = "keyfile"
        return args

    keyfile2_key_file = """
        BORG_KEY 0000000000000000000000000000000000000000000000000000000000000000
        hqlhbGdvcml0aG2mc2hhMjU2pGRhdGHaAN4u2SiN7hqISe3OA8raBWNuvHn1R50ZU7HVCn
        11vTJNEaj9soxUaIGcW+pAB2N5yYoKMg/sGCMuZa286iJ008DvN99rf/ORfcKrK2GmzslO
        N3uv9Tk9HtqV/Sq5zgM9xuY9rEeQGDQVQ+AOsFamJqSUrAemGJbJqw9IerXC/jN4XPnX6J
        pi1cXCFxHfDaEhmWrkdPNoZdirCv/eP/dOVOLmwU58YsS+MvkZNfEa16el/fSb/ENdrwJ/
        2aYMQrDdk1d5MYzkjotv/KpofNwPXZchu2EwH7OIHWQjEVL1DZWkaGFzaNoAIO/7qn1hr3
        F84MsMMiqpbz4KVICeBZhfAaTPs4W7BC63qml0ZXJhdGlvbnPOAAGGoKRzYWx02gAgLENQ
        2uVCoR7EnAoiRzn8J+orbojKtJlNCnQ31SSC8rendmVyc2lvbgE=""".strip()

    keyfile2_cdata = hex_to_bin(
        "003be7d57280d1a42add9f3f36ea363bbc5e9349ad01ddec0634a54dd02959e70500000000000003ec063d2cbcacba6b"
    )
    keyfile2_id = hex_to_bin("c3fbf14bc001ebcc3cd86e696c13482ed071740927cd7cbe1b01b4bfcee49314")

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

    keyfile_blake2_cdata = hex_to_bin(
        "04d6040f5ef80e0a8ac92badcbe3dee83b7a6b53d5c9a58c4eed14964cb10ef591040404040404040d1e65cc1f435027"
    )
    # Verified against b2sum. Entire string passed to BLAKE2, including the padded 64 byte key contained in
    # keyfile_blake2_key_file above is
    # 19280471de95185ec27ecb6fc9edbb4f4db26974c315ede1cd505fab4250ce7cd0d081ea66946c
    # 95f0db934d5f616921efbd869257e8ded2bd9bd93d7f07b1a30000000000000000000000000000
    # 000000000000000000000000000000000000000000000000000000000000000000000000000000
    # 00000000000000000000007061796c6f6164
    #                       p a y l o a d
    keyfile_blake2_id = hex_to_bin("d8bc68e961c79f99be39061589e5179b2113cd9226e07b08ddd4a1fef7ce93fb")

    @pytest.fixture
    def keys_dir(self, request, monkeypatch, tmpdir):
        monkeypatch.setenv("BORG_KEYS_DIR", str(tmpdir))
        return tmpdir

    @pytest.fixture(
        params=(
            # keyfile and repokey are no longer separate classes (storage is a per-key property),
            # so each crypto suite appears once here.
            # not encrypted, but tagged
            ChecksumKey,
            Blake3ChecksumKey,
            AuthenticatedKey,
            Blake3AuthenticatedKey,
            # legacy crypto (read-only, borg 1.x)
            AESCTRKey,
            Blake2AESCTRKey,
            Blake2AuthenticatedKey,
            # new crypto
            AESOCBKey,
            Blake3AESOCBKey,
            CHPOKey,
            Blake3CHPOKey,
        )
    )
    def key(self, request, monkeypatch):
        monkeypatch.setenv("BORG_PASSPHRASE", "test")
        return request.param.create(self.MockRepository(), self.MockArgs())

    class MockRepository:
        class _Location:
            raw = processed = "/some/place"

            def canonical_path(self):
                return self.processed

        def __init__(self, id=bytes(32)):
            self.id = id
            self.id_str = bin_to_hex(id)

        _location = _Location()
        version = 2

        def save_key(self, data):
            self.key_data = data

        def load_key(self):
            # mirror a real repository: no repokey stored yet -> empty bytes (not an error). Detection
            # is storage-agnostic now and always probes repo candidates, even for keyfile keys.
            return getattr(self, "key_data", b"")

    def test_none_sha256(self):
        key = ChecksumKey.create(None, None)
        chunk = b"foo"
        id = key.id_hash(chunk)
        # the chunk id of the "none-*" modes is the plain (unkeyed) hash of the chunk
        assert bin_to_hex(id) == "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
        assert chunk == key.decrypt(id, key.encrypt(id, chunk))

    def test_none_blake3(self):
        key = Blake3ChecksumKey.create(None, None)
        chunk = b"foo"
        id = key.id_hash(chunk)
        assert bin_to_hex(id) == "04e0bb39f30b1a3feb89f536c93be15055482df748674b00d26e5a75777702e9"
        assert chunk == key.decrypt(id, key.encrypt(id, chunk))

    def test_keyfile(self, monkeypatch, keys_dir):
        monkeypatch.setenv("BORG_PASSPHRASE", "test")
        key = AESCTRKey.create(self.MockRepository(), self.kf_args())
        assert key.cipher.next_iv() == 0
        chunk = b"ABC"
        id = key.id_hash(chunk)
        manifest = key.encrypt(id, chunk)
        assert key.cipher.extract_iv(manifest) == 0
        manifest2 = key.encrypt(id, chunk)
        assert manifest != manifest2
        assert key.decrypt(id, manifest) == key.decrypt(id, manifest2)
        assert key.cipher.extract_iv(manifest2) == 1
        iv = key.cipher.extract_iv(manifest)
        key2 = AESCTRKey.detect(self.MockRepository(), manifest)
        assert key2.cipher.next_iv() >= iv + key2.cipher.block_count(len(manifest) - AESCTRKey.PAYLOAD_OVERHEAD)
        # Key data sanity check
        assert len({key2.id_key, key2.crypt_key}) == 2
        assert key2.chunk_seed != 0
        chunk = b"foo"
        id = key.id_hash(chunk)
        assert chunk == key2.decrypt(id, key.encrypt(id, chunk))

    def test_keyfile_kfenv(self, tmpdir, monkeypatch):
        keyfile = tmpdir.join("keyfile")
        monkeypatch.setenv("BORG_KEY_FILE", str(keyfile))
        monkeypatch.setenv("BORG_PASSPHRASE", "testkf")
        assert not keyfile.exists()
        key = CHPOKey.create(self.MockRepository(), self.kf_args())
        assert keyfile.exists()
        chunk = b"ABC"
        chunk_id = key.id_hash(chunk)
        chunk_cdata = key.encrypt(chunk_id, chunk)
        key = CHPOKey.detect(self.MockRepository(), chunk_cdata)
        assert chunk == key.decrypt(chunk_id, chunk_cdata)
        keyfile.remove()
        with pytest.raises(FileNotFoundError):
            CHPOKey.detect(self.MockRepository(), chunk_cdata)

    def test_keyfile2(self, monkeypatch, keys_dir):
        with keys_dir.join("keyfile").open("w") as fd:
            fd.write(self.keyfile2_key_file)
        monkeypatch.setenv("BORG_PASSPHRASE", "passphrase")
        key = AESCTRKey.detect(self.MockRepository(), self.keyfile2_cdata)
        assert key.decrypt(self.keyfile2_id, self.keyfile2_cdata) == b"payload"

    def test_keyfile2_kfenv(self, tmpdir, monkeypatch):
        keyfile = tmpdir.join("keyfile")
        with keyfile.open("w") as fd:
            fd.write(self.keyfile2_key_file)
        monkeypatch.setenv("BORG_KEY_FILE", str(keyfile))
        monkeypatch.setenv("BORG_PASSPHRASE", "passphrase")
        key = AESCTRKey.detect(self.MockRepository(), self.keyfile2_cdata)
        assert key.decrypt(self.keyfile2_id, self.keyfile2_cdata) == b"payload"

    def test_keyfile_blake2(self, monkeypatch, keys_dir):
        with keys_dir.join("keyfile").open("w") as fd:
            fd.write(self.keyfile_blake2_key_file)
        monkeypatch.setenv("BORG_PASSPHRASE", "passphrase")
        key = Blake2AESCTRKey.detect(self.MockRepository(), self.keyfile_blake2_cdata)
        assert key.decrypt(self.keyfile_blake2_id, self.keyfile_blake2_cdata) == b"payload"

    def test_legacy_named_keyfile_still_loads(self, monkeypatch, keys_dir):
        monkeypatch.setenv("BORG_PASSPHRASE", "test")
        key = CHPOKey.create(self.MockRepository(), self.kf_args())
        hashed_keyfile = key.target
        legacy_keyfile = str(keys_dir.join("legacy-name"))
        os.replace(hashed_keyfile, legacy_keyfile)
        key2 = CHPOKey.detect(self.MockRepository(), key.encrypt(b"", b"payload"))
        assert key2.target == legacy_keyfile

    def _corrupt_byte(self, key, data, offset):
        data = bytearray(data)
        # note: we corrupt in a way so that even corruption of the unauthenticated encryption type byte
        # will trigger an IntegrityError (does not happen while we stay within TYPES_ACCEPTABLE).
        data[offset] ^= 64
        with pytest.raises(IntegrityErrorBase):
            key.decrypt(b"", data)

    def test_decrypt_integrity(self, monkeypatch, keys_dir):
        with keys_dir.join("keyfile").open("w") as fd:
            fd.write(self.keyfile2_key_file)
        monkeypatch.setenv("BORG_PASSPHRASE", "passphrase")
        key = AESCTRKey.detect(self.MockRepository(), self.keyfile2_cdata)

        data = self.keyfile2_cdata
        for i in range(len(data)):
            self._corrupt_byte(key, data, i)

        with pytest.raises(IntegrityError):
            data = bytearray(self.keyfile2_cdata)
            id = bytearray(key.id_hash(data))  # corrupt chunk id
            id[12] = 0
            plaintext = key.decrypt(id, data)
            key.assert_id(id, plaintext)

    def test_roundtrip(self, key):
        repository = key.repository
        plaintext = b"foo"
        id = key.id_hash(plaintext)
        encrypted = key.encrypt(id, plaintext)
        identified_key_class = identify_key(encrypted)
        assert identified_key_class == key.__class__
        loaded_key = identified_key_class.detect(repository, encrypted)
        decrypted = loaded_key.decrypt(id, encrypted)
        assert decrypted == plaintext

    def test_assert_id(self, key):
        plaintext = b"123456789"
        id = key.id_hash(plaintext)
        key.assert_id(id, plaintext)
        id_changed = bytearray(id)
        id_changed[0] ^= 1
        if not isinstance(key, AEADKeyBase):
            with pytest.raises(IntegrityError):
                key.assert_id(id_changed, plaintext)
            plaintext_changed = plaintext + b"1"
            with pytest.raises(IntegrityError):
                key.assert_id(id, plaintext_changed)

    def test_ocb_session_key_rollover(self, monkeypatch):
        # aes256-ocb must not encrypt too much data with one session key, see #6501.
        monkeypatch.setenv("BORG_PASSPHRASE", "test")
        key = AESOCBKey.create(self.MockRepository(), self.MockArgs())
        assert key.MAX_SESSION_BLOCKS == AES_OCB_MAX_SESSION_BLOCKS
        monkeypatch.setattr(key, "MAX_SESSION_BLOCKS", 32)  # 512B, way below the real limit
        plaintext = b"1234567890123456"  # one cipher block
        id = key.id_hash(plaintext)
        chunks = [key.encrypt(id, plaintext) for _ in range(20)]
        sessionids = [chunk[8:32] for chunk in chunks]  # see Layout
        ivs = [int.from_bytes(chunk[2:8], "big") for chunk in chunks]
        assert len(set(sessionids)) > 1  # borg started new sessions
        for previous, current, iv in zip(sessionids, sessionids[1:], ivs[1:]):
            if current != previous:
                assert iv == 1  # a new session counts the IV from the beginning again
            else:
                assert iv > 1
        for chunk in chunks:  # no matter which session key was used, we can read it all
            assert key.decrypt(id, chunk) == plaintext

    def test_chpo_no_session_key_rollover(self, monkeypatch):
        # chacha20-poly1305 has no limit on the amount of data encrypted with one key, see #6501.
        monkeypatch.setenv("BORG_PASSPHRASE", "test")
        key = CHPOKey.create(self.MockRepository(), self.MockArgs())
        assert key.MAX_SESSION_BLOCKS is None
        plaintext = b"1234567890123456"
        id = key.id_hash(plaintext)
        chunks = [key.encrypt(id, plaintext) for _ in range(20)]
        assert len({chunk[8:32] for chunk in chunks}) == 1

    def test_authenticated_encrypt(self, monkeypatch):
        monkeypatch.setenv("BORG_PASSPHRASE", "test")
        key = AuthenticatedKey.create(self.MockRepository(), self.MockArgs())
        assert AuthenticatedKey.id_hash is ID_HMAC_SHA_256.id_hash
        assert len(key.id_key) == 32
        plaintext = b"123456789"
        id = key.id_hash(plaintext)
        authenticated = key.encrypt(id, plaintext)
        # TYPE(1) + reserved(1) + tag(32) + payload, see MACKeyBase
        assert authenticated[0:2] == b"\x60\x00"
        assert authenticated[34:] == plaintext
        assert key.decrypt(id, authenticated) == plaintext

    def test_blake2_authenticated_encrypt(self, monkeypatch):
        # borg 1.x mode, read-only: its envelope is just the type byte plus the payload.
        monkeypatch.setenv("BORG_PASSPHRASE", "test")
        key = Blake2AuthenticatedKey.create(self.MockRepository(), self.MockArgs())
        assert Blake2AuthenticatedKey.id_hash is ID_BLAKE2b_256.id_hash
        assert len(key.id_key) == 128
        plaintext = b"123456789"
        id = key.id_hash(plaintext)
        authenticated = key.encrypt(id, plaintext)
        # 0x06 is the key TYPE.
        assert authenticated == b"\x06" + plaintext

    def test_blake3_authenticated_encrypt(self, monkeypatch):
        monkeypatch.setenv("BORG_PASSPHRASE", "test")
        key = Blake3AuthenticatedKey.create(self.MockRepository(), self.MockArgs())
        assert Blake3AuthenticatedKey.id_hash is ID_BLAKE3_256.id_hash
        assert len(key.id_key) == 32
        plaintext = b"123456789"
        id = key.id_hash(plaintext)
        authenticated = key.encrypt(id, plaintext)
        assert authenticated[0:2] == b"\x70\x00"
        assert authenticated[34:] == plaintext
        assert key.decrypt(id, authenticated) == plaintext

    def test_blake3_mt_threshold_from_env(self, monkeypatch):
        # the env var gives the threshold in KiB, get_blake3_mt_threshold() returns bytes
        def threshold_for(env_value):
            monkeypatch.setattr("borg.crypto.key._blake3_mt_threshold", None)  # drop the cache
            if env_value is None:
                monkeypatch.delenv("BORG_BLAKE3_MT_THRESHOLD", raising=False)
            else:
                monkeypatch.setenv("BORG_BLAKE3_MT_THRESHOLD", env_value)
            return get_blake3_mt_threshold()

        assert threshold_for(None) == BLAKE3_MT_THRESHOLD_KIB * 1024
        for value, expected_kib in [("0", 0), ("1", 1), ("256", 256), ("1024", 1024)]:
            assert threshold_for(value) == expected_kib * 1024
        for invalid in ["", "yes", "64k", "1.5", "-1"]:
            with pytest.raises(Error):
                threshold_for(invalid)


class TestTAM:
    @pytest.fixture
    def key(self, monkeypatch):
        monkeypatch.setenv("BORG_PASSPHRASE", "test")
        return CHPOKey.create(TestKey.MockRepository(), TestKey.MockArgs())

    def test_unpack_future(self, key):
        blob = b"\xc1\xc1\xc1\xc1foobar"
        with pytest.raises(UnsupportedManifestError):
            key.unpack_manifest(blob)

        blob = b"\xc1\xc1\xc1"
        with pytest.raises(msgpack.UnpackException):
            key.unpack_manifest(blob)

    def test_round_trip_manifest(self, key):
        data = {"foo": "bar"}
        blob = key.pack_metadata(data)
        unpacked = key.unpack_manifest(blob)
        assert unpacked["foo"] == "bar"
        assert "tam" not in unpacked  # legacy

    def test_round_trip_archive(self, key):
        data = {"foo": "bar"}
        blob = key.pack_metadata(data)
        unpacked = key.unpack_archive(blob)
        assert unpacked["foo"] == "bar"
        assert "tam" not in unpacked  # legacy


class TestMACEnvelope:
    """The tagged envelope of the modes that do not encrypt, see MACKeyBase."""

    # fixed key material, so the tests can check exact envelope bytes
    CRYPT_KEY = bytes(range(64))
    ID_KEY = bytes(range(100, 132))

    ALL_CLASSES = (ChecksumKey, Blake3ChecksumKey, AuthenticatedKey, Blake3AuthenticatedKey)
    KEYED_CLASSES = (AuthenticatedKey, Blake3AuthenticatedKey)
    UNKEYED_CLASSES = (ChecksumKey, Blake3ChecksumKey)

    class MockRepository:
        id = bytes(32)
        version = 2

    def make_key(self, cls, crypt_key=None):
        key = cls(self.MockRepository())
        if cls.has_secret_key:
            key.init_from_given_data(crypt_key=crypt_key or self.CRYPT_KEY, id_key=self.ID_KEY, chunk_seed=0)
        return key

    @pytest.fixture(params=ALL_CLASSES)
    def key(self, request):
        return self.make_key(request.param)

    def test_envelope_layout(self, key):
        payload = b"payload"
        id = key.id_hash(payload)
        envelope = key.encrypt(id, payload, aad=b"aad")
        assert envelope[0] == key.TYPE
        assert envelope[1] == 0  # reserved
        assert len(envelope) == key.PAYLOAD_OVERHEAD + len(payload) == 34 + len(payload)
        assert envelope[34:] == payload  # the payload is stored as-is, these modes do not encrypt
        assert key.decrypt(id, envelope, aad=b"aad") == payload

    def test_envelope_is_deterministic(self, key):
        # no nonce, no session: same input -> same bytes (see MACKeyBase)
        payload = b"payload"
        id = key.id_hash(payload)
        assert key.encrypt(id, payload, aad=b"aad") == key.encrypt(id, payload, aad=b"aad")

    @pytest.mark.parametrize("cls", ALL_CLASSES)
    def test_format_is_stable(self, cls):
        # golden vectors: these bytes must not change silently, they are an on-disk format.
        expected = {
            ChecksumKey: "80001ab01692fad0f0b89f27983cbf51b1bd20ab73de736aea83363b749ee6ba314f",
            Blake3ChecksumKey: "90008dec559eda6de95536f198f6b54b3b2728678c94ca1b3f0b77cf37e5b11c9b7c",
            AuthenticatedKey: "600033ecaaf8c34d4142fa502278986c8f49efbcbf879de16d3c2767e1252bfb1994",
            Blake3AuthenticatedKey: "70006de48e2139f8995790ec81b256e87f40ef5810d140d28396a8d07734ab05a358",
        }[cls]
        key = self.make_key(cls)
        plaintext = b"123456789"
        envelope = key.encrypt(key.id_hash(plaintext), plaintext, aad=b"")
        assert bin_to_hex(envelope) == expected + bin_to_hex(plaintext)

    @pytest.mark.parametrize("cls", UNKEYED_CLASSES)
    def test_unkeyed_modes_are_repo_independent(self, cls):
        # no key material at all, so any two repositories of such a mode store identical objects
        # for identical input - that is what allows deduplicating them on the filesystem level.
        key1, key2 = self.make_key(cls), self.make_key(cls)
        payload = b"payload"
        id = key1.id_hash(payload)
        assert key1.id_hash(payload) == key2.id_hash(payload)
        assert key1.encrypt(id, payload, aad=b"aad") == key2.encrypt(id, payload, aad=b"aad")

    @pytest.mark.parametrize("cls", KEYED_CLASSES)
    def test_keyed_modes_depend_on_crypt_key(self, cls):
        # the tag key is derived from crypt_key: same crypt_key -> same objects (that is what
        # "repo-create --other-repo --copy-crypt-key" gives), different crypt_key -> different tag.
        payload = b"payload"
        same = [self.make_key(cls), self.make_key(cls)]
        other = self.make_key(cls, crypt_key=bytes(range(1, 65)))
        id = same[0].id_hash(payload)
        assert same[0].encrypt(id, payload, aad=b"aad") == same[1].encrypt(id, payload, aad=b"aad")
        assert same[0].encrypt(id, payload, aad=b"aad") != other.encrypt(id, payload, aad=b"aad")
        # a key that can not verify the tag must not be able to read
        with pytest.raises(IntegrityError):
            other.decrypt(id, same[0].encrypt(id, payload, aad=b"aad"), aad=b"aad")

    def test_tampered_envelope_detected(self, key):
        # every single byte of the envelope is covered by the tag
        payload = b"0123456789"
        id = key.id_hash(payload)
        envelope = key.encrypt(id, payload, aad=b"aad")
        for offset in range(len(envelope)):
            tampered = bytearray(envelope)
            tampered[offset] ^= 64  # stays within TYPES_ACCEPTABLE if it hits the type byte
            with pytest.raises(IntegrityError):
                key.decrypt(id, bytes(tampered), aad=b"aad")

    def test_tampered_aad_detected(self, key):
        # the AAD carries the object header, the meta/data slot tag and the chunk id, see RepoObj
        payload = b"payload"
        id = key.id_hash(payload)
        envelope = key.encrypt(id, payload, aad=b"aadM")
        with pytest.raises(IntegrityError):
            key.decrypt(id, envelope, aad=b"aadD")  # e.g. meta and data slot swapped
        other_id = key.id_hash(b"other payload")
        with pytest.raises(IntegrityError):
            key.decrypt(other_id, envelope, aad=b"aadM")  # chunk taken from another object

    def test_truncated_envelope_detected(self, key):
        payload = b"payload"
        id = key.id_hash(payload)
        envelope = key.encrypt(id, payload, aad=b"aad")
        for length in range(key.PAYLOAD_OVERHEAD):  # cut into the header/tag
            with pytest.raises(IntegrityError):
                key.decrypt(id, envelope[:length], aad=b"aad")
        with pytest.raises(IntegrityError):  # cut into the payload
            key.decrypt(id, envelope[:-1], aad=b"aad")

    @pytest.mark.parametrize("cls", ALL_CLASSES)
    def test_flags(self, cls):
        key = self.make_key(cls)
        assert not key.encrypts
        assert not key.logically_encrypted
        assert key.IDHASH_IN_ENC_NAME
        assert key.ENC_NAME.endswith("-" + key.IDHASH_NAME)
        if cls in self.KEYED_CLASSES:
            assert key.has_secret_key
            # the envelope tag authenticates every read, so verifying the chunk id on top of that
            # is optional (see BORG_ASSERT_ID), like for the AEAD modes.
            assert not key.id_check_is_authentication
            assert key.STORAGE == KeyBlobStorage.REPO
            assert key.LOCATION_CONFIGURABLE
        else:
            assert not key.has_secret_key
            # the checksum can be recomputed by anybody, thus it is no authentication: the chunk id
            # check is the only one left and must never be skipped.
            assert key.id_check_is_authentication
            assert key.STORAGE == KeyBlobStorage.NO_STORAGE
            assert not key.LOCATION_CONFIGURABLE

    @pytest.mark.parametrize("cls", ALL_CLASSES)
    def test_type_bytes_are_distinct(self, cls):
        # identify_key must be able to tell the modes apart by the first envelope byte
        key = self.make_key(cls)
        envelope = key.encrypt(key.id_hash(b"x"), b"x")
        assert identify_key(envelope) is cls

    def test_authenticated_no_key_workaround(self, monkeypatch):
        # without the key material, the keyed modes can not verify the tag - but they can still
        # read the data (that is the point of the workaround, see BORG_WORKAROUNDS).
        key = self.make_key(AuthenticatedKey)
        payload = b"payload"
        id = key.id_hash(payload)
        envelope = bytearray(key.encrypt(id, payload, aad=b"aad"))
        envelope[5] ^= 1  # corrupt the tag
        monkeypatch.setattr("borg.crypto.key.AUTHENTICATED_NO_KEY", True)
        assert key.decrypt(id, bytes(envelope), aad=b"aad") == payload

    def test_unkeyed_modes_verify_despite_workaround(self, monkeypatch):
        # the unkeyed modes need no key material, so the workaround must not switch their
        # checksum verification off.
        monkeypatch.setattr("borg.crypto.key.AUTHENTICATED_NO_KEY", True)
        key = self.make_key(ChecksumKey)
        payload = b"payload"
        id = key.id_hash(payload)
        envelope = bytearray(key.encrypt(id, payload, aad=b"aad"))
        envelope[5] ^= 1
        with pytest.raises(IntegrityError):
            key.decrypt(id, bytes(envelope), aad=b"aad")


def test_dropped_borg2_beta_key_types(tmpdir):
    # the borg2 beta "none"/"authenticated" formats were dropped, see #9104. A borg2 repository
    # using them must be refused instead of being read with the legacy classes.
    from ...repoobj import RepoObj
    from ...crypto.key import key_factory

    for legacy_cls in (LegacyPlaintextKey, LegacyAuthenticatedKey):
        key = legacy_cls(MagicMock(id=bytes(32)))
        if legacy_cls is LegacyAuthenticatedKey:
            key.id_key = bytes(32)
        manifest_chunk = RepoObj(key).format(bytes(32), {}, b"manifest", ro_type=ROBJ_MANIFEST)
        with pytest.raises(UnsupportedPayloadError):
            key_factory(MagicMock(id=bytes(32)), manifest_chunk, ro_cls=RepoObj)


def test_dropped_blake3_authenticated_type_byte():
    with pytest.raises(UnsupportedPayloadError):
        identify_key(bytes([KeyType.DROPPED_BLAKE3AUTHENTICATED]) + b"payload")


def test_decrypt_key_file_unsupported_algorithm():
    """We will add more algorithms in the future. We should raise a helpful error."""
    key = CHPOKey(None)
    encrypted = msgpack.packb({"algorithm": "THIS ALGORITHM IS NOT SUPPORTED", "version": 1})

    with pytest.raises(UnsupportedKeyFormatError):
        key.decrypt_key_file(encrypted, "hello, pass phrase")


def test_decrypt_key_file_v2_is_unsupported():
    """There may eventually be a version 2 of the format. For now we should raise a helpful error."""
    key = CHPOKey(None)
    encrypted = msgpack.packb({"version": 2})

    with pytest.raises(UnsupportedKeyFormatError):
        key.decrypt_key_file(encrypted, "hello, pass phrase")


def test_key_file_roundtrip(monkeypatch):
    def to_dict(key):
        extract = "repository_id", "crypt_key", "id_key", "chunk_seed"
        return {a: getattr(key, a) for a in extract}

    repository = MagicMock(id=b"repository_id")
    monkeypatch.setenv("BORG_PASSPHRASE", "hello, pass phrase")

    save_me = AESOCBKey.create(repository, args=MagicMock(key_algorithm="argon2"))
    saved = repository.store_key.call_args.args[0]
    repository.load_keys.return_value = [("key0", saved)]
    load_me = AESOCBKey.detect(repository, manifest_data=None)

    assert to_dict(load_me) == to_dict(save_me)
    _, saved_b64 = keyfile_parse(saved)
    assert msgpack.unpackb(a2b_base64(saved_b64))["algorithm"] == KEY_ALGORITHMS["argon2"]


def test_argon2_wrong_passphrase_returns_none(monkeypatch):
    # a wrong passphrase derives a different key, so the Argon2 integrity check fails;
    # decrypt_key_file signals this by returning None, not by raising (refs #8036)
    repository = MagicMock(id=b"repository_id")
    monkeypatch.setenv("BORG_PASSPHRASE", "correct passphrase")
    key = AESOCBKey.create(repository, args=MagicMock(key_algorithm="argon2"))
    saved = repository.store_key.call_args.args[0]
    _, saved_b64 = keyfile_parse(saved)
    assert key.decrypt_key_file(a2b_base64(saved_b64), "wrong passphrase") is None

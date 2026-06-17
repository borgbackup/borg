import os

import pytest

from ..constants import EXIT_SUCCESS, EXIT_WARNING, EXIT_ERROR, EXIT_SIGNAL_BASE
from ..crypto import low_level
from ..crypto.key import AESOCBKey, PlaintextKey
from ..crypto import monitoring as mc
from .. import monitoring as m


def make_key():
    """A minimal AEAD key with a real random crypt_key (enough for derive_key)."""
    key = AESOCBKey.__new__(AESOCBKey)
    key.crypt_key = os.urandom(32)
    key.id_key = os.urandom(32)
    return key


# --- low-level crypto primitives -------------------------------------------------------


def test_ed25519_sign_verify_roundtrip():
    seed = os.urandom(32)
    pub = low_level.ed25519_public_from_seed(seed)
    assert len(pub) == 32
    sig = low_level.ed25519_sign(seed, b"hello")
    assert len(sig) == 64
    low_level.ed25519_verify(pub, b"hello", sig)  # must not raise


def test_ed25519_rejects_tampered_message():
    seed = os.urandom(32)
    pub = low_level.ed25519_public_from_seed(seed)
    sig = low_level.ed25519_sign(seed, b"hello")
    with pytest.raises(low_level.IntegrityError):
        low_level.ed25519_verify(pub, b"hello!", sig)


def test_ed25519_rejects_wrong_key():
    seed = os.urandom(32)
    sig = low_level.ed25519_sign(seed, b"hello")
    other_pub = low_level.ed25519_public_from_seed(os.urandom(32))
    with pytest.raises(low_level.IntegrityError):
        low_level.ed25519_verify(other_pub, b"hello", sig)


def test_hpke_seal_open_roundtrip():
    rseed = os.urandom(32)
    rpub = low_level.x25519_public_from_seed(rseed)
    blob = low_level.hpke_seal(rpub, b"info", b"aad", b"secret payload")
    assert low_level.hpke_open(rseed, b"info", b"aad", blob) == b"secret payload"


def test_hpke_rejects_wrong_recipient():
    rpub = low_level.x25519_public_from_seed(os.urandom(32))
    blob = low_level.hpke_seal(rpub, b"info", b"aad", b"secret")
    with pytest.raises(low_level.IntegrityError):
        low_level.hpke_open(os.urandom(32), b"info", b"aad", blob)


def test_hpke_rejects_wrong_aad():
    rseed = os.urandom(32)
    rpub = low_level.x25519_public_from_seed(rseed)
    blob = low_level.hpke_seal(rpub, b"info", b"aad", b"secret")
    with pytest.raises(low_level.IntegrityError):
        low_level.hpke_open(rseed, b"info", b"other-aad", blob)


# --- key derivation --------------------------------------------------------------------


def test_derivation_is_deterministic():
    key = make_key()
    assert mc.client_material(key) == mc.client_material(key)
    assert mc.monitor_material(key) == mc.monitor_material(key)


def test_client_and_monitor_halves_are_consistent():
    key = make_key()
    sign_seed, hpke_public = mc.client_material(key)
    ed_public, hpke_secret = mc.monitor_material(key)
    assert ed_public == low_level.ed25519_public_from_seed(sign_seed)
    assert hpke_public == low_level.x25519_public_from_seed(hpke_secret)


def test_labels_yield_independent_keys():
    key = make_key()
    sign_seed, _ = mc.client_material(key)
    _, hpke_secret = mc.monitor_material(key)
    assert sign_seed != hpke_secret


def test_monitor_half_does_not_contain_signing_secret():
    key = make_key()
    sign_seed, _ = mc.client_material(key)
    ed_public, hpke_secret = mc.monitor_material(key)
    assert sign_seed not in (ed_public, hpke_secret)


def test_derivation_is_per_key_unique():
    assert mc.client_material(make_key()) != mc.client_material(make_key())


def test_export_parse_monitor_key_roundtrip():
    key = make_key()
    text = mc.export_monitor_key(key)
    assert text.startswith(mc.MONITOR_KEY_PREFIX)
    assert mc.parse_monitor_key(text) == mc.monitor_material(key)


def test_parse_monitor_key_rejects_bad_input():
    with pytest.raises(ValueError):
        mc.parse_monitor_key("nope")
    with pytest.raises(ValueError):
        mc.parse_monitor_key("v1:00")


def test_plaintext_repo_is_not_signed():
    assert mc.is_signed_repo(make_key()) is True
    assert mc.is_signed_repo(PlaintextKey.__new__(PlaintextKey)) is False


# --- report build / serialize / deserialize -------------------------------------------


def sample_report(repo_id_hex):
    return m.build_report(
        command="create",
        repo_id=repo_id_hex,
        time="2026-06-17T11:59:58.123456+00:00",
        rc=EXIT_SUCCESS,
        archive="host-2026-06-17",
        archive_id="aa" * 32,
        stats={"original_size": 10485760, "nfiles": 1234},
    )


def test_status_from_rc():
    assert m.status_from_rc(EXIT_SUCCESS) == "success"
    assert m.status_from_rc(EXIT_WARNING) == "warning"
    assert m.status_from_rc(100) == "warning"  # specific warning range
    assert m.status_from_rc(EXIT_ERROR) == "error"
    assert m.status_from_rc(3) == "error"  # specific error range
    assert m.status_from_rc(EXIT_SIGNAL_BASE + 2) == "error"


def test_build_report_schema():
    report = sample_report("bb" * 32)
    assert report["command"] == "create"
    assert report["status"] == "success"
    assert report["archive_id"] == "aa" * 32
    assert "borg_version" in report and "time" in report


def test_sealed_report_roundtrip_and_trusted():
    key = make_key()
    repo_id = os.urandom(32)
    report = sample_report(repo_id.hex())
    data = m.serialize(key, repo_id, report)
    assert data[0] == m.FORMAT_VERSION and data[1] == m.BODY_SEALED
    monitor_key = mc.parse_monitor_key(mc.export_monitor_key(key))
    got, trusted = m.deserialize(monitor_key, repo_id, data)
    assert got == report and trusted is True


def test_sealed_report_rejects_wrong_repo_id():
    key = make_key()
    repo_id = os.urandom(32)
    data = m.serialize(key, repo_id, sample_report(repo_id.hex()))
    monitor_key = mc.parse_monitor_key(mc.export_monitor_key(key))
    with pytest.raises(low_level.IntegrityError):
        m.deserialize(monitor_key, os.urandom(32), data)


def test_sealed_report_rejects_tamper():
    key = make_key()
    repo_id = os.urandom(32)
    data = bytearray(m.serialize(key, repo_id, sample_report(repo_id.hex())))
    data[-1] ^= 1
    monitor_key = mc.parse_monitor_key(mc.export_monitor_key(key))
    with pytest.raises(low_level.IntegrityError):
        m.deserialize(monitor_key, repo_id, bytes(data))


def test_sealed_report_rejects_wrong_monitor_key():
    key = make_key()
    repo_id = os.urandom(32)
    data = m.serialize(key, repo_id, sample_report(repo_id.hex()))
    wrong = mc.parse_monitor_key(mc.export_monitor_key(make_key()))
    with pytest.raises(low_level.IntegrityError):
        m.deserialize(wrong, repo_id, data)


def test_sealed_report_requires_key():
    key = make_key()
    repo_id = os.urandom(32)
    data = m.serialize(key, repo_id, sample_report(repo_id.hex()))
    with pytest.raises(ValueError):
        m.deserialize(None, repo_id, data)


def test_plaintext_report_roundtrip_is_untrusted():
    key = PlaintextKey.__new__(PlaintextKey)
    key.crypt_key = b""
    key.id_key = b""
    repo_id = os.urandom(32)
    report = sample_report(repo_id.hex())
    data = m.serialize(key, repo_id, report)
    assert data[1] == m.BODY_PLAIN
    got, trusted = m.deserialize(None, repo_id, data)
    assert got == report and trusted is False

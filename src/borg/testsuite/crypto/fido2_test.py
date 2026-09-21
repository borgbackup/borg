"""Tests for the FIDO2 hmac-secret wrapper (borg.crypto.fido2).

All tests run against a scripted fake CTAP2 stack - no hardware and no python-fido2
package is needed: every python-fido2 name the wrapper uses is monkeypatched on the
wrapper module.
"""

import enum
import hashlib
import hmac
import os
from types import SimpleNamespace

import pytest

from ...crypto import fido2 as fido2_module
from ...crypto.fido2 import Fido2Operations, get_pin
from ...crypto.key import Fido2Error, Fido2DeviceNotFoundError, Fido2PinError
from ...helpers.errors import RTError

SHARED_SECRET = b"S" * 32
PIN_TOKEN = b"P" * 32
UV_TOKEN = b"U" * 32


class FakeErr(enum.IntEnum):
    NO_CREDENTIALS = 0x2E
    UP_REQUIRED = 0x2D
    PIN_INVALID = 0x31
    PIN_BLOCKED = 0x32
    PIN_AUTH_BLOCKED = 0x34
    UV_BLOCKED = 0x3C
    UV_INVALID = 0x3F
    USER_ACTION_TIMEOUT = 0x2F
    ACTION_TIMEOUT = 0x3A
    PUAT_REQUIRED = 0x36
    OPERATION_DENIED = 0x27
    UNSUPPORTED_OPTION = 0x2B
    INVALID_OPTION = 0x2C


class FakeCtapError(Exception):
    ERR = FakeErr

    def __init__(self, code):
        self.code = code
        super().__init__(f"CTAP error: {code!r}")


class FakeProtocol:
    VERSION = 1

    @staticmethod
    def _xor(key, data):
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

    def encrypt(self, secret, data):
        return self._xor(secret, data)

    def decrypt(self, secret, data):
        return self._xor(secret, data)

    def authenticate(self, secret, data):
        return hashlib.sha256(bytes(secret) + data).digest()[:16]


class FakePermission(enum.IntFlag):
    MAKE_CREDENTIAL = 1
    GET_ASSERTION = 2


class FakeClientPin:
    PERMISSION = FakePermission

    def __init__(self, ctap2):
        self.ctap = ctap2
        self.protocol = FakeProtocol()
        self._device = ctap2.device

    def _get_shared_secret(self):
        return {"fake": "key-agreement"}, SHARED_SECRET

    def get_pin_token(self, pin, permissions=None, permissions_rpid=None):
        device = self._device
        device.pin_token_calls += 1
        if pin != device.pin:
            raise FakeCtapError(FakeErr.PIN_INVALID)
        return PIN_TOKEN

    def get_uv_token(self, permissions=None, permissions_rpid=None):
        device = self._device
        device.uv_token_calls += 1
        if device.uv_fails:
            raise FakeCtapError(FakeErr.UV_BLOCKED)
        return UV_TOKEN

    def get_pin_retries(self):
        return 5, None


class FakeDevice:
    """A scriptable fake FIDO2 HID device.

    client_pin / uv: None = option unsupported, False = supported but not configured,
    True = configured (mirrors the CTAP getInfo semantics the wrapper relies on).
    """

    def __init__(
        self,
        path="/dev/hidraw7",
        name="FakeKey",
        *,
        ctap2=True,
        broken=False,
        hmac_secret=True,
        hmac_secret_on_create=True,
        up=True,
        enforce_up=True,
        enforce_up_error=FakeErr.UP_REQUIRED,
        rk=True,
        client_pin=None,
        uv=None,
        pin=None,
        uv_fails=False,
        preflight_error=None,
    ):
        self.descriptor = SimpleNamespace(path=path, product_name=name, _device=self)
        self.ctap2 = ctap2
        self.broken = broken
        self.hmac_secret = hmac_secret
        self.hmac_secret_on_create = hmac_secret_on_create
        self.up = up
        self.enforce_up = enforce_up
        self.enforce_up_error = enforce_up_error
        self.rk = rk
        self.client_pin = client_pin
        self.uv = uv
        self.pin = pin
        self.uv_fails = uv_fails
        self.preflight_error = preflight_error
        self.closed = False
        self.credentials = {}  # credential_id -> {False: cred_random_without_uv, True: cred_random_with_uv}
        self.pin_token_calls = 0
        self.uv_token_calls = 0
        self.make_credential_calls = []
        self.get_assertion_calls = []

    def close(self):
        self.closed = True

    def add_credential(self):
        credential_id = os.urandom(16)
        self.credentials[credential_id] = {False: os.urandom(32), True: os.urandom(32)}
        return credential_id


class FakeCtap2:
    def __init__(self, device):
        if not device.ctap2:
            raise ValueError("Device does not support CTAP2.")
        if device.broken:
            raise OSError("fake I/O error")
        self.device = device
        options = {}
        if device.up is not None:
            options["up"] = device.up
        if device.rk is not None:
            options["rk"] = device.rk
        if device.client_pin is not None:
            options["clientPin"] = device.client_pin
        if device.uv is not None:
            options["uv"] = device.uv
        extensions = ["hmac-secret"] if device.hmac_secret else None
        self.info = SimpleNamespace(extensions=extensions, options=options)

    def _check_pin_uv(self, pin_uv_param, client_data_hash):
        """Return whether user verification was performed (with a valid token)."""
        if pin_uv_param is None:
            return False
        protocol = FakeProtocol()
        valid = pin_uv_param in (
            protocol.authenticate(PIN_TOKEN, client_data_hash),
            protocol.authenticate(UV_TOKEN, client_data_hash),
        )
        assert valid, "invalid pin_uv_param sent to the fake authenticator"
        return True

    def make_credential(
        self,
        client_data_hash,
        rp,
        user,
        key_params,
        exclude_list=None,
        extensions=None,
        options=None,
        pin_uv_param=None,
        pin_uv_protocol=None,
        **kwargs,
    ):
        device = self.device
        device.make_credential_calls.append(
            dict(rp=rp, user=user, extensions=extensions, options=options, pin_uv_param=pin_uv_param)
        )
        uv = self._check_pin_uv(pin_uv_param, client_data_hash)
        if device.client_pin is True and not uv:
            raise FakeCtapError(FakeErr.PUAT_REQUIRED)
        credential_id = device.add_credential()
        if device.hmac_secret_on_create and extensions and extensions.get("hmac-secret"):
            ext_out = {"hmac-secret": True}
        else:
            ext_out = None  # a token without hmac-secret output sets no ED flag -> None, not {}
        auth_data = SimpleNamespace(extensions=ext_out, credential_data=SimpleNamespace(credential_id=credential_id))
        return SimpleNamespace(auth_data=auth_data)

    def get_assertion(
        self,
        rp_id,
        client_data_hash,
        allow_list=None,
        extensions=None,
        options=None,
        pin_uv_param=None,
        pin_uv_protocol=None,
        **kwargs,
    ):
        device = self.device
        device.get_assertion_calls.append(
            dict(rp_id=rp_id, allow_list=allow_list, extensions=extensions, options=options, pin_uv_param=pin_uv_param)
        )
        is_preflight = not extensions
        if is_preflight and device.preflight_error is not None:
            raise FakeCtapError(device.preflight_error)
        credential_id = allow_list[0]["id"]
        if credential_id not in device.credentials:
            raise FakeCtapError(FakeErr.NO_CREDENTIALS)
        up = not (options and options.get("up") is False)
        uv = self._check_pin_uv(pin_uv_param, client_data_hash)
        if extensions and not up and device.enforce_up:
            # the CTAP spec requires refusing touchless hmac-secret derivation: with
            # UNSUPPORTED_OPTION per CTAP 2.1 section 12.5; YubiKeys send UP_REQUIRED.
            raise FakeCtapError(device.enforce_up_error)
        if extensions and "hmac-secret" in extensions:
            protocol = FakeProtocol()
            salt = protocol.decrypt(SHARED_SECRET, extensions["hmac-secret"][2])
            # the hmac-secret output depends on whether UV was performed (CredRandomWithUV
            # vs CredRandomWithoutUV) - exactly what makes storing the uv flag necessary.
            cred_random = device.credentials[credential_id][uv]
            digest = hmac.new(cred_random, salt, hashlib.sha256).digest()
            ext_out = {"hmac-secret": protocol.encrypt(SHARED_SECRET, digest)}
        else:
            ext_out = None
        return SimpleNamespace(auth_data=SimpleNamespace(extensions=ext_out))


@pytest.fixture
def fake_fido2(monkeypatch):
    """Patch the wrapper module onto the fake CTAP2 stack; returns the plugged-in device list."""
    devices = []

    class FakeCtapHidDevice:
        def __new__(cls, descriptor, connection):
            return descriptor._device

        @classmethod
        def list_devices(cls):
            return iter(list(devices))

    def fake_get_descriptor(path):
        for device in devices:
            if str(device.descriptor.path) == str(path):
                return device.descriptor
        raise OSError(f"no such HID device: {path}")

    monkeypatch.setattr(fido2_module, "has_fido2", True)
    monkeypatch.setattr(fido2_module, "Ctap2", FakeCtap2)
    monkeypatch.setattr(fido2_module, "ClientPin", FakeClientPin)
    monkeypatch.setattr(fido2_module, "CtapError", FakeCtapError)
    monkeypatch.setattr(fido2_module, "ES256", SimpleNamespace(ALGORITHM=-7))
    monkeypatch.setattr(fido2_module, "CtapHidDevice", FakeCtapHidDevice)
    monkeypatch.setattr(fido2_module, "get_descriptor", fake_get_descriptor)
    monkeypatch.setattr(fido2_module, "open_connection", lambda descriptor: None)
    monkeypatch.delenv("BORG_FIDO2_DEVICE", raising=False)
    monkeypatch.delenv("BORG_FIDO2_PIN", raising=False)
    return devices


REPO_ID = b"R" * 32


def test_require_fido2_without_package(monkeypatch):
    monkeypatch.setattr(fido2_module, "has_fido2", False)
    with pytest.raises(RTError):
        fido2_module.require_fido2()


def test_enroll_and_derive_roundtrip(fake_fido2):
    device = FakeDevice()
    fake_fido2.append(device)
    ops = Fido2Operations(device)
    credential_id, salt, secret, uv_required = ops.enroll(REPO_ID)
    assert len(salt) == 32
    assert len(secret) == 32
    assert uv_required is False
    assert not device.pin_token_calls and not device.uv_token_calls
    # a non-resident credential is requested (nothing gets stored on the token).
    assert device.make_credential_calls[0]["options"] == {"rk": False}
    assert device.make_credential_calls[0]["extensions"] == {"hmac-secret": True}
    assert device.make_credential_calls[0]["user"]["id"] == REPO_ID
    # unlock via a fresh wrapper instance derives the same secret.
    ops2 = Fido2Operations(device)
    assert ops2.derive_secret(credential_id, salt) == secret
    # a different salt gives a different secret.
    assert ops2.derive_secret(credential_id, os.urandom(32)) != secret


@pytest.mark.parametrize("error_code", [FakeErr.UP_REQUIRED, FakeErr.UNSUPPORTED_OPTION, FakeErr.INVALID_OPTION])
def test_enroll_touchless_refused_by_token(fake_fido2, error_code):
    # a UP-enforcing token must fail --fido2-touch=no at enrollment instead of storing a key
    # that can never unlock touchlessly. The CTAP spec mandates the refusal and prescribes
    # UNSUPPORTED_OPTION; YubiKeys send UP_REQUIRED - all variants get the clear message.
    device = FakeDevice(enforce_up=True, enforce_up_error=error_code)
    fake_fido2.append(device)
    with pytest.raises(Fido2Error, match="touchless"):
        Fido2Operations(device).enroll(REPO_ID, up_required=False)


def test_enroll_and_derive_touchless(fake_fido2, capsys):
    device = FakeDevice(enforce_up=False)
    fake_fido2.append(device)
    credential_id, salt, secret, _ = Fido2Operations(device).enroll(REPO_ID, up_required=False)
    assert device.get_assertion_calls[-1]["options"] == {"up": False}
    capsys.readouterr()
    assert Fido2Operations(device).derive_secret(credential_id, salt, up_required=False) == secret
    # no touch prompt for a touchless unlock.
    assert "Touch" not in capsys.readouterr().err


def test_device_without_hmac_secret(fake_fido2):
    device = FakeDevice(hmac_secret=False)
    fake_fido2.append(device)
    with pytest.raises(Fido2Error, match="hmac-secret"):
        Fido2Operations(device)
    assert device.closed


def test_ctap1_only_device(fake_fido2):
    device = FakeDevice(ctap2=False)
    fake_fido2.append(device)
    with pytest.raises(Fido2Error, match="CTAP2"):
        Fido2Operations(device)
    assert device.closed


def test_make_credential_without_hmac_secret_output(fake_fido2):
    # AuthenticatorData.extensions is None (not {}) when the token ignored the extension.
    device = FakeDevice(hmac_secret_on_create=False)
    fake_fido2.append(device)
    with pytest.raises(Fido2Error, match="hmac-secret"):
        Fido2Operations(device).enroll(REPO_ID)


def test_pin_device_enroll_and_unlock(fake_fido2, monkeypatch):
    device = FakeDevice(client_pin=True, pin="123456")
    fake_fido2.append(device)
    monkeypatch.setenv("BORG_FIDO2_PIN", "123456")
    credential_id, salt, secret, uv_required = Fido2Operations(device).enroll(REPO_ID)
    assert uv_required is True
    assert device.make_credential_calls[0]["pin_uv_param"] is not None
    # unlock enforces UV, too (a real pin_uv_param goes into the assertion).
    assert Fido2Operations(device).derive_secret(credential_id, salt, uv_required=True) == secret
    assert device.get_assertion_calls[-1]["pin_uv_param"] is not None
    # without UV, the token derives from another cred_random -> different secret, so a
    # possession-only assertion cannot decrypt a UV-enrolled key.
    assert Fido2Operations(device).derive_secret(credential_id, salt, uv_required=False) != secret


def test_wrong_pin_is_sent_only_once(fake_fido2, monkeypatch):
    device = FakeDevice(client_pin=True, pin="123456")
    fake_fido2.append(device)
    monkeypatch.setenv("BORG_FIDO2_PIN", "654321")
    with pytest.raises(Fido2PinError, match="retries"):
        Fido2Operations(device).enroll(REPO_ID)
    # a wrong PIN burns a CTAP retry, so it must never be retried automatically.
    assert device.pin_token_calls == 1


def test_get_pin_blank_input_is_bounded(monkeypatch):
    import getpass as getpass_module

    monkeypatch.delenv("BORG_FIDO2_PIN", raising=False)
    monkeypatch.setattr(getpass_module, "getpass", lambda prompt: "")
    with pytest.raises(Fido2PinError, match="no PIN entered"):
        get_pin("FakeKey")
    monkeypatch.setattr(getpass_module, "getpass", lambda prompt: "123456")
    assert get_pin("FakeKey") == "123456"


def test_biometric_device_never_prompts_for_pin(fake_fido2, monkeypatch):
    # built-in UV (e.g. a fingerprint reader) is used; a PIN prompt must never happen.
    device = FakeDevice(client_pin=True, uv=True, pin="123456")
    fake_fido2.append(device)

    def no_pin_prompt(device_name):
        raise AssertionError("PIN prompt on a biometric token")

    monkeypatch.setattr(fido2_module, "get_pin", no_pin_prompt)
    credential_id, salt, secret, uv_required = Fido2Operations(device).enroll(REPO_ID)
    assert uv_required is True
    assert device.uv_token_calls > 0 and device.pin_token_calls == 0
    assert Fido2Operations(device).derive_secret(credential_id, salt, uv_required=True) == secret


def test_uv_blocked_falls_back_to_pin(fake_fido2, monkeypatch):
    device = FakeDevice(client_pin=True, uv=True, pin="123456", uv_fails=True)
    fake_fido2.append(device)
    monkeypatch.setenv("BORG_FIDO2_PIN", "123456")
    credential_id, salt, secret, uv_required = Fido2Operations(device).enroll(REPO_ID)
    assert uv_required is True
    assert device.uv_token_calls > 0 and device.pin_token_calls > 0


def test_derive_uv_required_without_uv_configured(fake_fido2):
    device = FakeDevice()  # neither clientPin nor uv configured
    fake_fido2.append(device)
    credential_id = device.add_credential()
    with pytest.raises(Fido2Error, match="user verification"):
        Fido2Operations(device).derive_secret(credential_id, os.urandom(32), uv_required=True)


def test_find_device_scans_and_keeps_only_the_match(fake_fido2):
    match = FakeDevice(path="/dev/hidraw5", name="MatchKey")
    credential_id = match.add_credential()
    u2f_only = FakeDevice(path="/dev/hidraw1", ctap2=False)
    no_hmac = FakeDevice(path="/dev/hidraw2", hmac_secret=False)
    broken = FakeDevice(path="/dev/hidraw3", broken=True)
    probe_fails = FakeDevice(path="/dev/hidraw4", preflight_error=FakeErr.OPERATION_DENIED)
    no_cred = FakeDevice(path="/dev/hidraw6")
    fake_fido2.extend([u2f_only, no_hmac, broken, probe_fails, no_cred, match])
    ops = Fido2Operations.find_device(credential_id)
    assert ops._device is match
    # stray devices must not abort the scan and must not leak open handles.
    for device in (u2f_only, no_hmac, broken, probe_fails, no_cred):
        assert device.closed
    assert not match.closed
    # the pre-flight probe was silent (up=false, no extensions -> no secret, no touch).
    preflight = no_cred.get_assertion_calls[0]
    assert preflight["options"] == {"up": False}
    assert preflight["extensions"] is None


def test_find_device_no_match(fake_fido2):
    device = FakeDevice()
    fake_fido2.append(device)
    with pytest.raises(Fido2DeviceNotFoundError):
        Fido2Operations.find_device(b"unknown-credential")
    assert device.closed


def test_find_device_env_pinning(fake_fido2, monkeypatch):
    other = FakeDevice(path="/dev/hidraw1")
    pinned = FakeDevice(path="/dev/hidraw2")
    credential_id = pinned.add_credential()
    fake_fido2.extend([other, pinned])
    monkeypatch.setenv("BORG_FIDO2_DEVICE", "/dev/hidraw2")
    ops = Fido2Operations.find_device(credential_id)
    assert ops._device is pinned
    # pinning skips the scan entirely - the other device is not even probed.
    assert other.get_assertion_calls == []


def test_from_path_nonexistent(fake_fido2):
    with pytest.raises(Fido2DeviceNotFoundError, match="cannot open"):
        Fido2Operations.from_path("/dev/hidraw99")


def test_list_devices(fake_fido2):
    good = FakeDevice(path="/dev/hidraw1", name="GoodKey")
    u2f_only = FakeDevice(path="/dev/hidraw2", ctap2=False)
    no_hmac = FakeDevice(path="/dev/hidraw3", hmac_secret=False)
    fake_fido2.extend([good, u2f_only, no_hmac])
    assert Fido2Operations.list_devices() == [("/dev/hidraw1", "GoodKey")]
    for device in (good, u2f_only, no_hmac):
        assert device.closed

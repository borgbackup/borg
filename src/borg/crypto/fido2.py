"""FIDO2 hmac-secret support for protecting borg keys.

A FIDO2 authenticator with the hmac-secret extension holds a device-bound HMAC key and
reproduces a stable 32-byte secret from a stored salt. borg uses that secret (after HKDF,
see crypto.key) as the key-encryption-key for a borg key, instead of a passphrase run
through argon2. The design is modeled on systemd's libfido2-util.c; see also PR
borgbackup/borg#8995 which this is based on.

This module wraps the raw CTAP2 protocol (python-fido2, "fido2" on PyPI, >= 1.1). It must
only be imported lazily from the fido2 code paths in crypto.key: importing fido2.hid pulls
in ctypes HID backends and the cryptography package, a startup cost every borg invocation
would otherwise pay. The module itself imports cleanly without python-fido2 installed
(has_fido2 is False then, require_fido2() reports the missing package).
"""

import getpass
import os
import sys

from ..helpers import bin_to_hex
from ..helpers.errors import RTError
from ..logger import create_logger

from .key import Fido2Error, Fido2DeviceNotFoundError, Fido2PinError

logger = create_logger()

try:
    from fido2.ctap import CtapError
    from fido2.ctap2 import ClientPin, Ctap2
    from fido2.cose import ES256
    from fido2.hid import CtapHidDevice, get_descriptor, open_connection

    has_fido2 = True
except ImportError:
    Ctap2 = ClientPin = CtapError = ES256 = CtapHidDevice = get_descriptor = open_connection = None
    has_fido2 = False

# The relying party ID all borg FIDO2 credentials are scoped to (the single definition).
RP_ID = "org.borgbackup.fido2"

# CTAP wants a SHA-256 hash of the client data in every request. borg talks CTAP directly
# (it is not a WebAuthn client and has no client data), so an all-zero hash is used, like
# systemd-cryptenroll does.
_CLIENT_DATA_HASH = b"\x00" * 32


def require_fido2():
    """Raise RTError if the python-fido2 package is not installed."""
    if not has_fido2:
        raise RTError("FIDO2 support requires the 'fido2' python package (e.g. pip install 'borgbackup[fido2]').")


def get_pin(device_name):
    """Return the FIDO2 PIN: from BORG_FIDO2_PIN if set, otherwise prompted interactively.

    PIN acquisition is deliberately separate from the passphrase machinery: a PIN must never
    be sourced from BORG_PASSPHRASE / BORG_PASSCOMMAND. Every wrong PIN sent to the token
    burns one of its few CTAP retries: 3 consecutive failures soft-block the token until it
    is re-inserted, 8 block the PIN entirely, and the only recovery from that is a reset that
    wipes ALL credentials on the token. The bounded retry below is for blank input only - a
    typed PIN is sent to the token exactly once per borg invocation.
    """
    pin = os.environ.get("BORG_FIDO2_PIN")
    if pin:
        return pin
    for _ in range(3):
        pin = getpass.getpass(f"Enter PIN for FIDO2 device {device_name}: ")
        if pin:
            return pin
        print("PIN must not be blank.", file=sys.stderr)
    raise Fido2PinError("no PIN entered")


class Fido2Operations:
    """One open FIDO2 authenticator, wrapped for borg's enrollment and unlock operations."""

    def __init__(self, device):
        # device: an open fido2.hid.CtapHidDevice. The instance takes ownership (see close()).
        require_fido2()
        self._device = device
        descriptor = device.descriptor
        self.device_name = descriptor.product_name or str(descriptor.path)
        try:
            # raises ValueError for CTAP1/U2F-only devices (no CBOR capability).
            self._ctap2 = Ctap2(device)
        except ValueError:
            device.close()
            raise Fido2Error(f"device {self.device_name} does not support CTAP2 (FIDO2)") from None
        info = self._ctap2.info
        # a token without hmac-secret would silently ignore the extension in our requests,
        # so check support up front. extensions may be None.
        if "hmac-secret" not in (info.extensions or []):
            device.close()
            raise Fido2Error(f"device {self.device_name} does not support the hmac-secret extension")
        self._client_pin = ClientPin(self._ctap2)
        # authenticator options: absent means unsupported, False supported but not configured,
        # True configured (CTAP 2.1 authenticatorGetInfo).
        self.has_rk = info.options.get("rk", False)
        self.has_up = info.options.get("up", True)
        self.pin_configured = info.options.get("clientPin") is True
        self.uv_configured = info.options.get("uv") is True

    def close(self):
        self._device.close()

    @classmethod
    def from_path(cls, path):
        """Open the FIDO2 device named by the given platform device identifier.

        Device identifiers are only filesystem paths on Linux (/dev/hidrawN); on macOS the
        identifier is a decimal IOKit registry entry id, on Windows a ``\\\\?\\hid#vid_...``
        interface string. So no filesystem-based validation happens here - get_descriptor()
        fails naturally for identifiers that do not name a HID device.
        """
        require_fido2()
        try:
            descriptor = get_descriptor(path)
            device = CtapHidDevice(descriptor, open_connection(descriptor))
        except Exception as exc:  # noqa: BLE001 - backend-specific exception types per platform
            raise Fido2DeviceNotFoundError(f"cannot open FIDO2 device {path}: {exc}") from None
        return cls(device)

    @classmethod
    def _scan_hmac_secret_devices(cls):
        """Yield (device, ctap2) for each plugged-in CTAP2 device supporting hmac-secret.

        Devices that are not usable (CTAP1/U2F-only, no hmac-secret, enumeration errors) are
        closed and skipped; the consumer is responsible for closing the yielded devices.
        """
        for device in CtapHidDevice.list_devices():
            try:
                try:
                    ctap2 = Ctap2(device)
                except ValueError:
                    logger.debug("FIDO2 scan: skipping CTAP1/U2F-only device %s", device.descriptor.path)
                    device.close()
                    continue
                if "hmac-secret" not in (ctap2.info.extensions or []):
                    logger.debug("FIDO2 scan: device %s has no hmac-secret extension", device.descriptor.path)
                    device.close()
                    continue
            except Exception as exc:  # noqa: BLE001 - a broken device must not abort the scan
                logger.debug("FIDO2 scan: skipping device %s: %s", device.descriptor.path, exc)
                device.close()
                continue
            yield device, ctap2

    @classmethod
    def list_devices(cls):
        """Return [(path, product_name)] for all plugged-in FIDO2 devices supporting hmac-secret."""
        require_fido2()
        result = []
        for device, _ in cls._scan_hmac_secret_devices():
            descriptor = device.descriptor
            result.append((str(descriptor.path), descriptor.product_name))
            device.close()
        return result

    @classmethod
    def find_device(cls, credential_id):
        """Find and open the plugged-in authenticator holding *credential_id*.

        BORG_FIDO2_DEVICE (env-only) pins a specific device (multi-token machines, scripting);
        by default all plugged-in tokens are probed with a silent pre-flight get_assertion
        against the credential id - the key blob carries everything needed for that.
        """
        require_fido2()
        pinned = os.environ.get("BORG_FIDO2_DEVICE")
        if pinned:
            return cls.from_path(pinned)
        for device, ctap2 in cls._scan_hmac_secret_devices():
            found = False
            try:
                # CTAP 2.1 pre-flight: a get_assertion with up=false does not prompt for a touch
                # and reports (via NO_CREDENTIALS) whether the credential is on this
                # authenticator. Omit the option if the authenticator does not advertise "up"
                # (a CTAP 2.0 device may answer up=false with UNSUPPORTED_OPTION).
                options = {"up": False} if ctap2.info.options.get("up", True) else None
                try:
                    ctap2.get_assertion(
                        rp_id=RP_ID,
                        client_data_hash=_CLIENT_DATA_HASH,
                        allow_list=[{"type": "public-key", "id": credential_id}],
                        options=options,
                    )
                except CtapError as exc:
                    if exc.code != CtapError.ERR.NO_CREDENTIALS:
                        logger.debug("FIDO2 scan: pre-flight probe on %s failed: %s", device.descriptor.path, exc)
                    continue
                logger.debug("FIDO2 scan: device %s holds the credential", device.descriptor.path)
                found = True
                # hand over the still-open device instead of reopening it by path: a second
                # open can fail on platforms with exclusive HID access.
                return cls(device)
            finally:
                if not found:
                    device.close()
        raise Fido2DeviceNotFoundError(
            "no plugged-in FIDO2 device holds the credential of this borg key "
            "(BORG_FIDO2_DEVICE can pin a specific device)"
        )

    def _prompt_touch(self):
        print(f"Touch your FIDO2 device now ({self.device_name})...", file=sys.stderr)

    def _pin_uv_error(self, exc):
        """Map a CtapError from PIN/UV token acquisition to a borg error."""
        if exc.code == CtapError.ERR.PIN_INVALID:
            try:
                retries, _ = self._client_pin.get_pin_retries()
                remaining = f", {retries} retries left before the token blocks the PIN"
            except Exception:  # noqa: BLE001 - the retry count is optional information
                remaining = ""
            return Fido2PinError(f"wrong PIN for FIDO2 device {self.device_name}{remaining}")
        if exc.code == CtapError.ERR.PIN_AUTH_BLOCKED:
            return Fido2PinError(
                f"FIDO2 device {self.device_name} temporarily blocks PIN use, " "unplug and re-insert it to try again"
            )
        if exc.code == CtapError.ERR.PIN_BLOCKED:
            return Fido2PinError(f"the PIN of FIDO2 device {self.device_name} is blocked")
        return Fido2Error(f"PIN/user verification failed on FIDO2 device {self.device_name}: {exc}")

    def _get_pin_uv_token(self, permissions):
        """Get a pinUvAuthToken when the authenticator has user verification configured.

        A token may enforce UV via a client PIN or via built-in user verification (e.g.
        biometrics) - a biometric token must never cause a PIN prompt. Returns None when the
        authenticator has no UV method configured at all (pure possession factor).
        """
        if self.uv_configured:
            self._prompt_touch()
            try:
                return self._client_pin.get_uv_token(permissions, RP_ID)
            except CtapError as exc:
                # when built-in UV is blocked (too many failed attempts), CTAP prescribes
                # falling back to the PIN, if one is configured.
                if exc.code not in (CtapError.ERR.UV_BLOCKED, CtapError.ERR.UV_INVALID) or not self.pin_configured:
                    raise self._pin_uv_error(exc) from None
                logger.debug("FIDO2 built-in user verification failed (%s), falling back to PIN", exc)
        if self.pin_configured:
            pin = get_pin(self.device_name)
            try:
                return self._client_pin.get_pin_token(pin, permissions, RP_ID)
            except CtapError as exc:
                raise self._pin_uv_error(exc) from None
        return None

    def _pin_uv_params(self, pin_uv_token):
        """Return the (pin_uv_param, pin_uv_protocol) pair for a request.

        Pass None/None together when there is no token: the CBOR argument helper drops None
        values, and a pin_uv_protocol without pin_uv_param would put key 0x07 alone into the
        request.
        """
        if pin_uv_token is None:
            return None, None
        protocol = self._client_pin.protocol
        return protocol.authenticate(pin_uv_token, _CLIENT_DATA_HASH), protocol.VERSION

    def _hmac_secret_input(self, salt):
        # the hmac-secret salt travels encrypted (and the output comes back encrypted) inside
        # the PIN-protocol shared-secret channel. _get_shared_secret() is private python-fido2
        # API (stable 0.9 through 2.2, but unversioned); this method and _hmac_secret_output
        # are the only places touching that channel.
        key_agreement, self._shared_secret = self._client_pin._get_shared_secret()
        protocol = self._client_pin.protocol
        salt_enc = protocol.encrypt(self._shared_secret, salt)
        salt_auth = protocol.authenticate(self._shared_secret, salt_enc)
        return {1: key_agreement, 2: salt_enc, 3: salt_auth, 4: protocol.VERSION}

    def _hmac_secret_output(self, assertion):
        # extensions is None (not {}) when the authenticator returned no extension output.
        extensions = assertion.auth_data.extensions
        output = extensions.get("hmac-secret") if extensions else None
        if not output:
            raise Fido2Error(f"FIDO2 device {self.device_name} did not return an hmac-secret output")
        return self._client_pin.protocol.decrypt(self._shared_secret, output)[:32]

    def _derive_secret(self, credential_id, salt, *, up, pin_uv_token):
        """One hmac-secret get_assertion: reproduce the 32-byte secret for (credential_id, salt)."""
        extensions = {"hmac-secret": self._hmac_secret_input(salt)}
        # only pass the "up" option to switch the touch off; explicitly passing up=true is
        # invalid for some authenticators (and it is the default anyway).
        options = None if up else {"up": False}
        pin_uv_param, pin_uv_protocol = self._pin_uv_params(pin_uv_token)
        if up:
            self._prompt_touch()
        try:
            assertion = self._ctap2.get_assertion(
                rp_id=RP_ID,
                client_data_hash=_CLIENT_DATA_HASH,
                allow_list=[{"type": "public-key", "id": credential_id}],
                extensions=extensions,
                options=options,
                pin_uv_param=pin_uv_param,
                pin_uv_protocol=pin_uv_protocol,
            )
        except CtapError as exc:
            # CTAP 2.1 (section 12.5, hmac-secret) requires authenticators to reject up=false
            # ("If \"up\" is set to false, authenticator returns CTAP2_ERR_UNSUPPORTED_OPTION");
            # YubiKeys answer CTAP2_ERR_UP_REQUIRED instead. Only tokens deviating from the
            # spec on this point support touchless derivation at all.
            touchless_refusals = (
                CtapError.ERR.UP_REQUIRED,
                CtapError.ERR.UNSUPPORTED_OPTION,
                CtapError.ERR.INVALID_OPTION,
            )
            if exc.code in touchless_refusals and not up:
                raise Fido2Error(
                    f"FIDO2 device {self.device_name} refuses touchless (no user presence) "
                    "hmac-secret derivation, as the CTAP spec requires, and thus does not "
                    "support touchless borg keys"
                ) from None
            if exc.code in (CtapError.ERR.USER_ACTION_TIMEOUT, CtapError.ERR.ACTION_TIMEOUT):
                raise Fido2Error(f"FIDO2 device {self.device_name} was not touched within the timeout") from None
            if exc.code == CtapError.ERR.NO_CREDENTIALS:
                raise Fido2Error(
                    f"FIDO2 device {self.device_name} does not hold the credential of this borg key"
                ) from None
            raise Fido2Error(f"get_assertion failed on FIDO2 device {self.device_name}: {exc}") from None
        return self._hmac_secret_output(assertion)

    def enroll(self, user_id, *, up_required=True):
        """Create a new non-resident hmac-secret credential and derive its secret once.

        Returns (credential_id, salt, secret, uv_required). Two touches are inherent:
        makeCredential always requires user presence per CTAP, and deriving the secret needs a
        separate get_assertion (hmac-secret-mc is not available on common tokens).

        uv_required reports whether user verification (PIN or built-in) was performed: the
        hmac-secret output differs between assertions with and without UV (CredRandomWithUV vs
        CredRandomWithoutUV), so unlock must repeat exactly what enrollment did - the caller
        stores the flag in the key blob.

        With up_required=False, the touchless derivation is verified right here at enrollment:
        the CTAP spec (2.1 section 12.5) requires tokens to reject up=false for hmac-secret
        (CTAP2_ERR_UNSUPPORTED_OPTION per spec; YubiKeys answer CTAP2_ERR_UP_REQUIRED), so
        only tokens deviating from the spec on this point support it at all - better to fail
        now than to store a key that can never unlock touchlessly.
        """
        permissions = ClientPin.PERMISSION.MAKE_CREDENTIAL | ClientPin.PERMISSION.GET_ASSERTION
        pin_uv_token = self._get_pin_uv_token(permissions)
        uv_required = pin_uv_token is not None
        pin_uv_param, pin_uv_protocol = self._pin_uv_params(pin_uv_token)
        # rk=False: non-resident credential, nothing is stored on the token (the credential id
        # in the key blob is all that is needed). Only mention the option when supported.
        options = {"rk": False} if self.has_rk else None
        self._prompt_touch()
        try:
            result = self._ctap2.make_credential(
                client_data_hash=_CLIENT_DATA_HASH,
                rp={"id": RP_ID, "name": "Borg Repository"},
                user={"id": user_id, "name": bin_to_hex(user_id)},
                key_params=[{"type": "public-key", "alg": ES256.ALGORITHM}],
                extensions={"hmac-secret": True},
                options=options,
                pin_uv_param=pin_uv_param,
                pin_uv_protocol=pin_uv_protocol,
            )
        except CtapError as exc:
            if exc.code in (CtapError.ERR.USER_ACTION_TIMEOUT, CtapError.ERR.ACTION_TIMEOUT):
                raise Fido2Error(f"FIDO2 device {self.device_name} was not touched within the timeout") from None
            raise Fido2Error(f"creating a credential failed on FIDO2 device {self.device_name}: {exc}") from None
        extensions = result.auth_data.extensions
        if not (extensions and extensions.get("hmac-secret")):
            raise Fido2Error(
                f"FIDO2 device {self.device_name} did not enable the hmac-secret extension for the new credential"
            )
        credential_id = result.auth_data.credential_data.credential_id
        logger.debug("FIDO2: created a new credential with the hmac-secret extension")
        salt = os.urandom(32)
        secret = self._derive_secret(credential_id, salt, up=up_required, pin_uv_token=pin_uv_token)
        return credential_id, salt, secret, uv_required

    def derive_secret(self, credential_id, salt, *, up_required=True, uv_required=False):
        """Reproduce the stored borg key's hmac-secret (the KEK input) with one assertion."""
        if uv_required:
            pin_uv_token = self._get_pin_uv_token(ClientPin.PERMISSION.GET_ASSERTION)
            if pin_uv_token is None:
                raise Fido2Error(
                    f"this borg key requires user verification, but FIDO2 device {self.device_name} "
                    "has neither a PIN nor built-in user verification configured"
                )
        else:
            pin_uv_token = None
        return self._derive_secret(credential_id, salt, up=up_required, pin_uv_token=pin_uv_token)

import os
import sys

from binascii import b2a_hex
from ..logger import create_logger

logger = create_logger()

try:
    from fido2.ctap2 import Ctap2, ClientPin
    from fido2.ctap import CtapError
    from fido2.hid import CtapHidDevice, get_descriptor, open_connection
    from fido2.cose import ES256

    has_fido2 = True
except ImportError:
    has_fido2 = False


class Fido2Operations:
    @classmethod
    def find_device(cls, credential_id, rp_id="org.borgbackup.fido2"):
        if not has_fido2:
            raise ValueError("No FIDO2 support found. Install the 'fido2' module.")
        for d in CtapHidDevice.list_devices():
            ctap2 = Ctap2(d)

            # It's not our device
            if "hmac-secret" not in ctap2.info.extensions:
                continue

            # According to CTAP 2.1 specification, to do pre-flight we
            # need to set up option to false with optionally
            # pinUvAuthParam in assertion[1]. But for authenticator
            # that doesn't support user presence, once up option is
            # present, the authenticator may return
            # CTAP2_ERR_UNSUPPORTED_OPTION[2].  So we simplely omit
            # the option in that case.
            # Reference:
            # 1: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#pre-flight
            # 2: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetAssertion
            #    (in step 5)
            options = None
            if ctap2.info.options.get("up", True):
                options = {"up": False}
            try:
                ctap2.get_assertion(
                    rp_id=rp_id,
                    client_data_hash=b"\x00" * 32,
                    allow_list=[{"type": "public-key", "id": credential_id}],
                    extensions=None,
                    options=options,
                    pin_uv_param=None,
                    pin_uv_protocol=None,
                    event=None,
                    on_keepalive=None,
                )
            except CtapError as e:
                if CtapError.ERR.NO_CREDENTIALS == e.code:
                    continue
                raise e
            logger.info(f"Found the FIDO2 device matching the credential: {d.descriptor.path}.")
            return d.descriptor.path
        else:
            logger.error("No matching FIDO2 device found.")

    def __init__(self, device=None, pin=None):
        if not has_fido2:
            raise ValueError("No FIDO2 support found. Install the 'fido2' module.")
        if not device:
            raise ValueError("FIDO2 device not specified.")
        self._device_path = device
        self._pin = pin

        descriptor = get_descriptor(self._device_path)
        hid_device = CtapHidDevice(descriptor, open_connection(descriptor))
        self._ctap2 = Ctap2(hid_device)
        self._client_pin = ClientPin(self._ctap2)

        # TODO: verify that the device supports hmac-secret
        # if not 'hmac-secret' in self._ctap2.info.extensions:
        #     # Oh no!

        #  Defaults are per table in 5.4 in FIDO2 spec
        self.has_rk = self._ctap2.info.options.get("rk", False)
        self.has_client_pin = self._ctap2.info.options.get("clientPin", False)
        self.has_up = self._ctap2.info.options.get("up", True)
        self.has_uv = self._ctap2.info.options.get("uv", False)

    def _hmac_secret_input(self, salt1):
        key_agreement, self._shared_secret = self._client_pin._get_shared_secret()
        salt_enc = self._client_pin.protocol.encrypt(self._shared_secret, salt1)
        salt_auth = self._client_pin.protocol.authenticate(self._shared_secret, salt_enc)
        return {1: key_agreement, 2: salt_enc, 3: salt_auth, 4: self._client_pin.protocol.VERSION}

    def _hmac_secret_output(self, data):
        decrypted = self._client_pin.protocol.decrypt(self._shared_secret, data)
        return decrypted[:32]

    def _get_assertion(self, salt, credential_id, rp_id="org.borgbackup.fido2"):
        return self._ctap2.get_assertion(
            rp_id=rp_id,
            client_data_hash=b"\x00" * 32,
            allow_list=[{"type": "public-key", "id": credential_id}],
            extensions={"hmac-secret": self._hmac_secret_input(salt)},
            options=None,
            pin_uv_param=None,
            pin_uv_protocol=self._client_pin.protocol.VERSION,
            event=None,
            on_keepalive=None,
        )

    def use_hmac_hash(self, salt, credential_id):

        # TODO: replace with…
        print("\nTouch your authenticator device now...\n", file=sys.stderr)
        assertion = self._get_assertion(salt, credential_id)
        if not assertion.auth_data.extensions.get("hmac-secret"):
            raise Exception("Failed to get assertion with hmac-secret")

        secret = self._hmac_secret_output(assertion.auth_data.extensions["hmac-secret"])
        return secret

    def generate_hmac_hash(self, user, rp_id="org.borgbackup.fido2"):
        # TODO: decide whether to use or not credentialProtectionPolicy
        if self._pin:
            pin_token = self._client_pin.get_pin_token(self._pin, ClientPin.PERMISSION.MAKE_CREDENTIAL, rp_id)
            pin_auth = self._client_pin.protocol.authenticate(pin_token, b"\x00" * 32)
        elif self.has_client_pin:
            raise ValueError("PIN required but not provided")

        if not (self.has_rk or self.has_uv):
            cred_options = None
        else:
            cred_options = {}
            if self.has_rk:
                cred_options["rk"] = False
            if self.has_uv:
                cred_options["uv"] = False

        print("\nTouch your authenticator device now...\n", file=sys.stderr)
        result = self._ctap2.make_credential(
            client_data_hash=b"\x00" * 32,
            rp={"id": rp_id, "name": "Borg Repository"},
            user={"id": user, "name": b2a_hex(user).decode("ascii")},
            key_params=[{"type": "public-key", "alg": ES256.ALGORITHM}],
            exclude_list=None,
            extensions={"hmac-secret": True},
            options=cred_options,
            pin_uv_param=pin_auth,
            pin_uv_protocol=self._client_pin.protocol.VERSION,
            event=None,
            on_keepalive=None,
        )

        if result.auth_data.extensions.get("hmac-secret") is None:
            raise Exception("Failed to create credential with hmac-secret")
        logger.info("New credential created with the hmac-secret extension.")

        credential_id = result.auth_data.credential_data.credential_id

        salt = os.urandom(32)
        print("\nTouch your authenticator device now...\n", file=sys.stderr)
        assertion = self._get_assertion(salt, credential_id)

        if not assertion.auth_data.extensions.get("hmac-secret"):
            raise Exception("Failed to get assertion with hmac-secret")
        logger.info("An assertion with hmac-secret value created.")

        secret = self._hmac_secret_output(assertion.auth_data.extensions["hmac-secret"])

        return credential_id, salt, secret

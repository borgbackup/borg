"""Crypto for monitoring reports published into the (untrusted) repository.

A backup client publishes a small state report into the repo's ``monitoring/``
namespace after each relevant operation. A monitoring system pulls and verifies it
from the same untrusted server, needing no repo passphrase and no trust in the server:

- **Authenticity** comes from an Ed25519 signature. The client signs; the monitor only
  ever holds the public verify key, so neither the server nor the monitor can forge a
  report.
- **Confidentiality from the server** comes from HPKE-sealing the signed payload to the
  monitor's X25519 public key, so the server sees ciphertext only.

All key material is derived deterministically from the existing borg key using borg's
own ``derive_key()`` (the same one-step KDF used for session keys) with fixed monitoring
labels and no random salt. Nothing extra is generated, stored, or rotated.

For ``--encryption none`` repositories there is no borg key to derive from, so reports
are published as plain JSON, unsigned and unencrypted - consistent with such a repo
being unsafe anyway. The monitor must treat those as untrusted.
"""

from binascii import hexlify, unhexlify

from . import low_level
from .key import PlaintextKey

# derive_key domains (labels). Fixed and distinct so the two seeds are independent.
SIGN_DOMAIN = b"borg-monitoring-sign"
SEAL_DOMAIN = b"borg-monitoring-seal"

# HPKE info string, bound into the sealed context (domain separation / versioning).
HPKE_INFO = b"borg-monitoring-report-v1"

# BORG_MONITORING_KEY wire format: "<version>:<hex>". Bump on incompatible changes.
MONITOR_KEY_PREFIX = "v1:"


def is_signed_repo(key):
    """True if this repo has a real borg key, so reports can be signed and sealed."""
    return not isinstance(key, PlaintextKey)


def _derive_seed(key, domain):
    # Same one-step KDF as session keys (sha256(crypt_key + salt + domain)), but with a
    # fixed label and NO random salt, so the result is deterministic. Derived from
    # crypt_key (not id_key, which related repos share).
    return key.derive_key(salt=b"", domain=domain, size=32)


def client_material(key):
    """Client half: (ed25519_sign_seed, hpke_recipient_public).

    Used by the publishing side to sign with the Ed25519 secret seed and seal
    to the monitor's HPKE public key.
    """
    sign_seed = _derive_seed(key, SIGN_DOMAIN)
    seal_seed = _derive_seed(key, SEAL_DOMAIN)
    hpke_public = low_level.x25519_public_from_seed(seal_seed)
    return sign_seed, hpke_public


def monitor_material(key):
    """Monitor half: (ed25519_verify_public, hpke_recipient_secret).

    This is everything the monitoring system needs to verify and decrypt and
    nothing more: it cannot derive the signing secret or the borg key from it.
    """
    sign_seed = _derive_seed(key, SIGN_DOMAIN)
    seal_seed = _derive_seed(key, SEAL_DOMAIN)
    ed_public = low_level.ed25519_public_from_seed(sign_seed)
    return ed_public, seal_seed


def export_monitor_key(key):
    """Return the env-safe BORG_MONITORING_KEY string (the monitor half)."""
    ed_public, hpke_secret = monitor_material(key)
    return MONITOR_KEY_PREFIX + hexlify(ed_public + hpke_secret).decode("ascii")


def parse_monitor_key(text):
    """Parse a BORG_MONITORING_KEY string into (ed25519_verify_public, hpke_secret)."""
    text = text.strip()
    if not text.startswith(MONITOR_KEY_PREFIX):
        raise ValueError("BORG_MONITORING_KEY: unsupported format/version")
    raw = unhexlify(text[len(MONITOR_KEY_PREFIX) :])
    if len(raw) != low_level.ED25519_PUBLIC_SIZE + low_level.X25519_SEED_SIZE:
        raise ValueError("BORG_MONITORING_KEY: wrong length")
    return raw[: low_level.ED25519_PUBLIC_SIZE], raw[low_level.ED25519_PUBLIC_SIZE :]


def seal_report(key, payload, aad):
    """Sign *payload* (bytes) with the client's Ed25519 secret, then HPKE-seal it.

    *aad* (bytes, e.g. the repo id) is bound into both the HPKE seal context, so a sealed
    report cannot be transplanted to a different repo. Returns the sealed envelope bytes.
    """
    sign_seed, hpke_public = client_material(key)
    signature = low_level.ed25519_sign(sign_seed, payload)
    return low_level.hpke_seal(hpke_public, HPKE_INFO, aad, signature + payload)


def open_report(ed_public, hpke_secret, blob, aad):
    """HPKE-open *blob*, verify the Ed25519 signature, and return the *payload* bytes.

    Raises low_level.IntegrityError if decryption or signature verification fails.
    """
    signed = low_level.hpke_open(hpke_secret, HPKE_INFO, aad, blob)
    siglen = low_level.ED25519_SIGNATURE_SIZE
    signature, payload = signed[:siglen], signed[siglen:]
    low_level.ed25519_verify(ed_public, payload, signature)
    return payload

.. include:: ../global.rst.inc
.. highlight:: none

Passphrases from a YubiKey (challenge-response)
===============================================

The YubiKey's OTP application offers HMAC-SHA1 challenge-response: the YubiKey holds a
secret key and computes ``HMAC-SHA1(secret, challenge)`` for any challenge sent to it.
This can derive the borg passphrase on demand - the passphrase is never stored anywhere,
only a random challenge is - by wiring the derivation into ``BORG_PASSCOMMAND`` (see
:ref:`env_vars`). It is the same long-proven mechanism used by e.g. KeePassXC.

This is the most minimal hardware-backed setup for YubiKey owners: one tool
(``ykman``, from the yubikey-manager package), no other files than a challenge, and the
slot can be programmed with or without a touch requirement - so it covers both
unattended backups and presence-gated interactive use. The trade-offs: it is a
Yubico-proprietary mechanism (it does not exist on other vendors' security keys, nor on
Yubico's FIDO2-only "Security Key" series), and a YubiKey has only two OTP slots, which
may be shared with other uses of challenge-response. For a vendor-neutral approach that
also covers other hardware (any FIDO2 security key, TPM, Apple Secure Enclave), see the
age-based deployment guide.

Program a challenge-response slot
---------------------------------

Check which slots are free first - **programming a slot overwrites its previous
content** (slot 1 usually holds the factory Yubico OTP credential; slot 2 is typically
free)::

  ykman otp info

Program slot 2 with a random secret::

  ykman otp chalresp --generate 2

Without ``--touch``, responses are computed silently - that is what enables unattended
use. Add ``--touch`` instead if every unlock shall require a touch on the YubiKey
(presence-gated, for interactive use; not usable for unattended backups).

``--generate`` prints the generated secret once. Either store that hex secret offline
(it allows programming a *second* YubiKey with the same secret later, see below) or
discard it - afterwards it cannot be read back from the YubiKey.

For two YubiKeys as redundant twins, generate the secret yourself and program it into
both - they will then derive identical passphrases::

  openssl rand -hex 20   # the slot secret; store it offline or destroy it afterwards
  ykman otp chalresp 2 <SECRET>    # run once per YubiKey

Derive the borg passphrase
--------------------------

Create a random challenge and keep it with your borg configuration (the HMAC challenge
is limited to 64 bytes, so 32 random bytes = 64 hex digits is a good choice)::

  openssl rand -hex 32 > ~/.config/borg/yubikey-challenge
  chmod 600 ~/.config/borg/yubikey-challenge

The passphrase is the response to that challenge::

  ykman otp calculate 2 "$(cat ~/.config/borg/yubikey-challenge)"
  d2f19d6c2b48e1665d2ea1042ee5d1c34e29bb2e

Keep an offline copy of this response (e.g. on paper, in a safe place): it is the
actual borg passphrase, and it is your recovery path if the YubiKey is lost - without
YubiKey and without the paper copy, this borg key cannot be unlocked.

The challenge file is not usable without the YubiKey holding the slot secret, but keep
it protected anyway: both "factors" are needed to derive the passphrase.

Wire it into borg
-----------------

``BORG_PASSCOMMAND`` runs its command *without* a shell, so ``$(...)`` substitution is
not available there. Put the derivation into a small script, e.g.
``~/.config/borg/yubikey-passphrase.sh`` (make it executable: ``chmod 700``)::

  #!/bin/sh
  exec ykman otp calculate 2 "$(cat ~/.config/borg/yubikey-challenge)"

and use it::

  export BORG_PASSCOMMAND=~/.config/borg/yubikey-passphrase.sh

For a **new** repository, set ``BORG_PASSCOMMAND`` before ``borg repo-create``: the
command's output is then used as the new repository's passphrase.

For an **existing** repository, add the derived passphrase as an additional borg key
(keeping the existing passphrase as an independent way in, e.g. for recovery)::

  BORG_NEW_PASSPHRASE="$(~/.config/borg/yubikey-passphrase.sh)" borg key add --label yubikey

With a touchless slot, scheduled backups (cron, systemd timers) now work while the
YubiKey is plugged in; with ``--touch``, every borg command asks for a touch.

Notes and caveats
-----------------

- A touchless slot makes the YubiKey act like an *uncopyable keyfile*: stealing the
  challenge file (or any other file) is useless without the physical YubiKey, but code
  running on the machine can derive the passphrase silently while the YubiKey is
  plugged in - it is device-bound, not presence-gated. A ``--touch`` slot prevents
  silent derivation, at the price of unattended use. In both cases, borg necessarily
  obtains the passphrase and key material at unlock time - a compromised client still
  gets them.
- Reprogramming the slot (or losing all YubiKeys programmed with its secret)
  permanently breaks this derivation. Keep the paper copy of the derived passphrase,
  or another borg key with its own passphrase, as the recovery path - and remember
  that a repository is only as secure as its *weakest* borg key.
- The response is 160 bits (HMAC-SHA1). SHA-1's known weaknesses do not matter here
  (it is used as a keyed PRF, not for collision resistance), and 160 random bits are
  far beyond brute force.
- On macOS, the ``ykman otp`` commands access the YubiKey's keyboard (HID) interface,
  which requires the *Input Monitoring* permission for your terminal application
  (System Settings > Privacy & Security > Input Monitoring).
- The legacy ``ykchalresp -2 -i <challengefile>`` tool (from the deprecated ykpers
  package) computes the same responses; prefer the maintained ``ykman``.

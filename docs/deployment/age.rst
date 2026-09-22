.. include:: ../global.rst.inc
.. highlight:: none

Passphrases from age: hardware security keys, TPM, Secure Enclave
=================================================================

Borg protects each borg key with a passphrase, and that passphrase can be supplied
programmatically via ``BORG_PASSCOMMAND`` (see :ref:`env_vars`). This guide shows how to
combine that with age_, a small and modern file encryption tool: a strong random
passphrase is stored age-encrypted on disk, and borg decrypts it on demand through the
passcommand.

The point of this indirection is age's plugin ecosystem: age identities can live in
hardware. That way, the borg passphrase - and with it, the repository - can be bound to a
FIDO2 security key, a YubiKey's PIV application, a machine's TPM 2.0 chip, or a Mac's
Secure Enclave, without borg itself needing to know anything about that hardware.
Depending on the hardware and its configuration, unlocking either requires user presence
(a touch on the token - good for interactive use) or works silently (good for unattended
backups).

.. _age: https://age-encryption.org/

The pattern
-----------

All variants below follow the same three steps; only the age recipient differs.

1. Generate a strong random passphrase and keep an offline copy of it (e.g. on paper, in
   a safe place). This copy is your recovery path if the age setup or the hardware is
   ever lost::

     head -c 32 /dev/urandom | base64 > passphrase
     cat passphrase   # write this down / print it, then store it offline

2. Encrypt the passphrase to one or more age recipients and remove the plaintext::

     age --recipient <RECIPIENT> --output ~/.config/borg/passphrase.age passphrase
     shred --remove passphrase   # or: rm -P passphrase (BSD/macOS)

3. Let borg obtain the passphrase through the matching age identity. What the identity
   is and how it is created depends on the chosen variant (a key file, or a reference to
   a hardware key) - each example below creates its own ``identity.txt``::

     export BORG_PASSCOMMAND="age --decrypt --identity ~/.config/borg/identity.txt ~/.config/borg/passphrase.age"

With ``BORG_PASSCOMMAND`` set, all borg commands work as usual - including
``borg repo-create``, which uses the passcommand's output as the new repository's
passphrase, so the whole setup can be done before the repository even exists.

The encrypted ``passphrase.age`` file and the identity file must be available on every
machine that shall unlock the repository. Neither is usable without the corresponding
secret (the age key resp. the hardware), so they do not need the same level of protection
as a plaintext passphrase - but treat them as part of your backup configuration and back
them up accordingly.

First example: no hardware
--------------------------

To get familiar with the pattern, start with a plain age key pair (no hardware
involved)::

  age-keygen --output ~/.config/borg/identity.txt
  # note the "public key: age1..." line it prints - that is the recipient

  head -c 32 /dev/urandom | base64 > passphrase
  age --recipient age1... --output ~/.config/borg/passphrase.age passphrase
  shred --remove passphrase

  export BORG_PASSCOMMAND="age --decrypt --identity ~/.config/borg/identity.txt ~/.config/borg/passphrase.age"
  borg -r /path/to/repo repo-create --encryption=aes256-ocb
  borg -r /path/to/repo repo-info

Security-wise this is roughly equivalent to keeping the passphrase in a protected file
(the identity file *is* the secret here), so by itself it mainly buys convenience: one
identity can unlock the passphrases of many repositories, and you can later re-encrypt
``passphrase.age`` to additional recipients - including hardware ones - without touching
borg. The interesting setups bind the identity to hardware, below.

Hardware options at a glance
----------------------------

===========================  ==================================  ===============  =============================
age plugin                   hardware                            unattended use   user presence per unlock
===========================  ==================================  ===============  =============================
age-plugin-fido2-hmac_       any FIDO2 security key with the     no               always a touch; PIN optional
                             hmac-secret extension (YubiKey,
                             Nitrokey, SoloKeys, ...)
age-plugin-yubikey_          YubiKey series 4/5 (PIV)            yes (policy      configurable: never, cached
                                                                 ``never``)       or always (+ optional PIN)
age-plugin-tpm_              TPM 2.0 chip (bound to the          yes              none (optional PIN)
                             machine, no token needed)
age-plugin-se_               Apple Secure Enclave                yes (access      configurable: none, or
                             (macOS 14+, bound to the Mac)       control          Touch ID and/or passcode
                                                                 ``none``)
===========================  ==================================  ===============  =============================

.. _age-plugin-fido2-hmac: https://github.com/olastor/age-plugin-fido2-hmac
.. _age-plugin-yubikey: https://github.com/str4d/age-plugin-yubikey
.. _age-plugin-tpm: https://github.com/foxboron/age-plugin-tpm
.. _age-plugin-se: https://github.com/remko/age-plugin-se

Choosing:

- For **interactive** use (manual backups, restores, browsing), a FIDO2 security key with
  ``age-plugin-fido2-hmac`` is the most universal choice: it works with any vendor's
  FIDO2 token, and every unlock requires a physical touch - malware on the machine cannot
  silently unlock the repository while the token is plugged in. Note that the touch
  requirement is mandated by the FIDO2/CTAP specification, so this option can *not* serve
  unattended backups.
- For **unattended** backups with a token, use a YubiKey's PIV application with touch and
  PIN policies set to ``never``. Such a key acts like an *uncopyable keyfile*: stealing
  all files from the machine is useless without the physical YubiKey, but code running on
  the machine can unlock silently while the YubiKey is plugged in (it is device-bound,
  not presence-gated).
- For **unattended** backups bound to the machine itself - no token to plug in or lose -
  use the TPM on Linux/Windows hardware, or the Secure Enclave on Macs. Same trade-off:
  copied files are useless elsewhere, code on the machine can unlock.

A repository can combine these: the same passphrase encrypted to several recipients, or
several borg keys (see ``borg key add``) for different purposes.

Example: FIDO2 security key (interactive, touch-gated)
------------------------------------------------------

Generate a credential on the token (you will be asked whether decryption shall also
require the token's PIN, and whether to use a separate identity file)::

  age-plugin-fido2-hmac -g > ~/.config/borg/identity.txt

Then encrypt the passphrase to the identity and set the passcommand::

  age --encrypt --identity ~/.config/borg/identity.txt --output ~/.config/borg/passphrase.age passphrase
  export BORG_PASSCOMMAND="age --decrypt --identity ~/.config/borg/identity.txt ~/.config/borg/passphrase.age"

Every borg command that needs the key will now make the token blink and wait for a touch.
The credential is stateless (nothing is stored on the token), so you can create as many
as you like. The identity file contains the credential id and salt - useless without the
token, like everything else in this setup.

Example: YubiKey PIV (unattended)
---------------------------------

Requires the PC/SC smartcard service (``pcscd``) on Linux. Generate a P-256 key on the
YubiKey with policies that allow silent use::

  age-plugin-yubikey --generate --name borg --pin-policy never --touch-policy never
  # prints the recipient: age1yubikey1...

  age --recipient age1yubikey1... --output ~/.config/borg/passphrase.age passphrase

The identity file is only a reference (serial and slot) and can be regenerated from the
plugged-in YubiKey at any time - nothing to lose::

  age-plugin-yubikey --identity --slot <SLOT> > ~/.config/borg/identity.txt
  export BORG_PASSCOMMAND="age --decrypt --identity ~/.config/borg/identity.txt ~/.config/borg/passphrase.age"

Backups from cron or a systemd timer now work while the YubiKey is plugged in. For an
interactive, presence-gated variant of the same mechanism, generate with
``--touch-policy always`` (or ``cached``, which allows further unlocks for 15 seconds
after a touch) and/or a PIN policy.

Example: TPM or Secure Enclave (unattended, machine-bound)
----------------------------------------------------------

TPM 2.0 (Linux/Windows)::

  age-plugin-tpm --generate --output ~/.config/borg/identity.txt
  age-plugin-tpm -y ~/.config/borg/identity.txt   # prints the recipient
  age --recipient age1tpm1... --output ~/.config/borg/passphrase.age passphrase
  export BORG_PASSCOMMAND="age --decrypt --identity ~/.config/borg/identity.txt ~/.config/borg/passphrase.age"

The identity file is a TPM-sealed key blob: it only works on this machine's TPM.

Apple Secure Enclave (macOS 14+)::

  age-plugin-se keygen --access-control=none --output ~/.config/borg/identity.txt
  age-plugin-se recipients --input ~/.config/borg/identity.txt   # prints the recipient

``--access-control=none`` allows silent, unattended use; policies like
``any-biometry`` instead require Touch ID for every unlock (presence-gated, like the
FIDO2 option - but bound to this Mac).

Redundancy: several recipients, one passphrase
----------------------------------------------

age encrypts to any number of recipients, and *any one* of them can decrypt. This is the
recommended way to handle hardware loss or failure - for example, two YubiKeys (for the
drawer and the keychain) plus the machine's TPM::

  age --recipient age1yubikey1...A --recipient age1yubikey1...B \
      --recipient age1tpm1... --output ~/.config/borg/passphrase.age passphrase

If one YubiKey is lost, the other (or the TPM) still unlocks; then generate a replacement
and re-create ``passphrase.age`` with a new recipient set. Note that age's built-in
passphrase encryption (``age --passphrase``) cannot be combined with other recipients - that is
what the offline paper copy of the borg passphrase is for.

To *revoke* a compromised unlocker (not just stop using it), re-creating
``passphrase.age`` is not enough - whoever had the hardware may have decrypted and kept
the passphrase. Change it: ``borg key change-passphrase`` with a fresh random passphrase,
then re-encrypt that one to the remaining recipients.

Notes and caveats
-----------------

- If the hardware is unavailable (token unplugged, TPM of another machine), the
  passcommand fails and the borg command aborts. There is no automatic fallback: to use
  the recovery passphrase, unset ``BORG_PASSCOMMAND`` and enter it at the prompt (or use
  another borg key, see ``borg key add``).
- All of these setups protect the passphrase (and thus the borg key and repository) *at
  rest*. On the machine at unlock time, borg necessarily obtains the passphrase and the
  decrypted key material - a compromised client still gets them, whatever holds the age
  identity. Presence-gated options (FIDO2, PIV/SE with touch policies) at least prevent
  *silent* unlocking; device-bound options without presence do not.
- A repository is only as secure as its weakest borg key: an age-protected passphrase on
  one borg key does not strengthen a weak passphrase on another one.
- age and its plugins are separate binaries that must be installed (they are packaged in
  the usual distributions and Homebrew) and available in ``PATH`` (or, for the plugins,
  given via ``AGE_PLUGIN_PATH``) wherever borg shall unlock the repository - including on
  the machine you will one day restore on. The offline paper copy of the passphrase keeps
  working without any of them.

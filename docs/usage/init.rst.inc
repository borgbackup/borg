.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_init:

borg init
---------
::

    borg init <options> REPOSITORY

positional arguments
    REPOSITORY
        repository to create

optional arguments
    ``-e``, ``--encryption``
        | select encryption key mode (default: "repokey")
    ``-a``, ``--append-only``
        | create an append-only mode repository

`Common options`_
    |

Description
~~~~~~~~~~~

This command initializes an empty repository. A repository is a filesystem
directory containing the deduplicated data from zero or more archives.

Encryption can be enabled at repository init time (the default).

It is not recommended to disable encryption. Repository encryption protects you
e.g. against the case that an attacker has access to your backup repository.

But be careful with the key / the passphrase:

If you want "passphrase-only" security, use the repokey mode. The key will
be stored inside the repository (in its "config" file). In above mentioned
attack scenario, the attacker will have the key (but not the passphrase).

If you want "passphrase and having-the-key" security, use the keyfile mode.
The key will be stored in your home directory (in .config/borg/keys). In
the attack scenario, the attacker who has just access to your repo won't have
the key (and also not the passphrase).

Make a backup copy of the key file (keyfile mode) or repo config file
(repokey mode) and keep it at a safe place, so you still have the key in
case it gets corrupted or lost. Also keep the passphrase at a safe place.
The backup that is encrypted with that key won't help you with that, of course.

Make sure you use a good passphrase. Not too short, not too simple. The real
encryption / decryption key is encrypted with / locked by your passphrase.
If an attacker gets your key, he can't unlock and use it without knowing the
passphrase.

Be careful with special or non-ascii characters in your passphrase:

- Borg processes the passphrase as unicode (and encodes it as utf-8),
  so it does not have problems dealing with even the strangest characters.
- BUT: that does not necessarily apply to your OS / VM / keyboard configuration.

So better use a long passphrase made from simple ascii chars than one that
includes non-ascii stuff or characters that are hard/impossible to enter on
a different keyboard layout.

You can change your passphrase for existing repos at any time, it won't affect
the encryption/decryption key or other secrets.

Encryption modes
++++++++++++++++

repokey and keyfile use AES-CTR-256 for encryption and HMAC-SHA256 for
authentication in an encrypt-then-MAC (EtM) construction. The chunk ID hash
is HMAC-SHA256 as well (with a separate key).

repokey-blake2 and keyfile-blake2 use the same authenticated encryption, but
use a keyed BLAKE2b-256 hash for the chunk ID hash.

"authenticated" mode uses no encryption, but authenticates repository contents
through the same keyed BLAKE2b-256 hash as the other blake2 modes.
The key is stored like repokey.

Hardware acceleration will be used automatically.

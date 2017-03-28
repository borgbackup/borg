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
        | select encryption key mode
    ``-a``, ``--append-only``
        | create an append-only mode repository

`Common options`_
    |

Description
~~~~~~~~~~~

This command initializes an empty repository. A repository is a filesystem
directory containing the deduplicated data from zero or more archives.

Encryption can be enabled at repository init time.

It is not recommended to work without encryption. Repository encryption protects
you e.g. against the case that an attacker has access to your backup repository.

But be careful with the key / the passphrase:

If you want "passphrase-only" security, use one of the repokey modes. The
key will be stored inside the repository (in its "config" file). In above
mentioned attack scenario, the attacker will have the key (but not the
passphrase).

If you want "passphrase and having-the-key" security, use one of the keyfile
modes. The key will be stored in your home directory (in .config/borg/keys).
In the attack scenario, the attacker who has just access to your repo won't
have the key (and also not the passphrase).

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

`repokey` and `keyfile` use AES-CTR-256 for encryption and HMAC-SHA256 for
authentication in an encrypt-then-MAC (EtM) construction. The chunk ID hash
is HMAC-SHA256 as well (with a separate key).
These modes are compatible with borg 1.0.x.

`repokey-blake2` and `keyfile-blake2` are also authenticated encryption modes,
but use BLAKE2b-256 instead of HMAC-SHA256 for authentication. The chunk ID
hash is a keyed BLAKE2b-256 hash.
These modes are new and *not* compatible with borg 1.0.x.

`authenticated` mode uses no encryption, but authenticates repository contents
through the same keyed BLAKE2b-256 hash as the other blake2 modes (it uses it
as chunk ID hash). The key is stored like repokey.
This mode is new and not compatible with borg 1.0.x.

`none` mode uses no encryption and no authentication. It uses sha256 as chunk
ID hash. Not recommended, rather consider using an authenticated or
authenticated/encrypted mode.
This mode is compatible with borg 1.0.x.

Hardware acceleration will be used automatically.

On modern Intel/AMD CPUs (except very cheap ones), AES is usually
hardware-accelerated. BLAKE2b is faster than SHA256 on Intel/AMD 64bit CPUs,
which makes `authenticated` faster than `none`.

On modern ARM CPUs, NEON provides hardware acceleration for SHA256 making it faster
than BLAKE2b-256 there.
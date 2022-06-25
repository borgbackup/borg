.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_rcreate:

borg rcreate
------------
.. code-block:: none

    borg [common options] rcreate [options]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **optional arguments**                                                                                                                                                                                                                                                                                                              |
    +-------------------------------------------------------+------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--other-repo SRC_REPOSITORY``    | reuse the key material from the other repository                                                                                                                                                                                       |
    +-------------------------------------------------------+------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``-e MODE``, ``--encryption MODE`` | select encryption key mode **(required)**                                                                                                                                                                                              |
    +-------------------------------------------------------+------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--append-only``                  | create an append-only mode repository. Note that this only affects the low level structure of the repository, and running `delete` or `prune` will still be allowed. See :ref:`append_only_mode` in Additional Notes for more details. |
    +-------------------------------------------------------+------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--storage-quota QUOTA``          | Set storage quota of the new repository (e.g. 5G, 1.5T). Default: no quota.                                                                                                                                                            |
    +-------------------------------------------------------+------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--make-parent-dirs``             | create the parent directories of the repository directory, if they are missing.                                                                                                                                                        |
    +-------------------------------------------------------+------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--key-algorithm``                | the algorithm we use to derive a key encryption key from your passphrase. Default: argon2                                                                                                                                              |
    +-------------------------------------------------------+------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                                                                                                                      |
    |                                                                                                                                                                                                                                                                                                                                     |
    | :ref:`common_options`                                                                                                                                                                                                                                                                                                               |
    +-------------------------------------------------------+------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    optional arguments
        --other-repo SRC_REPOSITORY    reuse the key material from the other repository
        -e MODE, --encryption MODE     select encryption key mode **(required)**
        --append-only                  create an append-only mode repository. Note that this only affects the low level structure of the repository, and running `delete` or `prune` will still be allowed. See :ref:`append_only_mode` in Additional Notes for more details.
        --storage-quota QUOTA          Set storage quota of the new repository (e.g. 5G, 1.5T). Default: no quota.
        --make-parent-dirs             create the parent directories of the repository directory, if they are missing.
        --key-algorithm                the algorithm we use to derive a key encryption key from your passphrase. Default: argon2


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

This command creates a new, empty repository. A repository is a filesystem
directory containing the deduplicated data from zero or more archives.

Encryption mode TLDR
++++++++++++++++++++

The encryption mode can only be configured when creating a new repository - you can
neither configure it on a per-archive basis nor change the mode of an existing repository.
This example will likely NOT give optimum performance on your machine (performance
tips will come below):

::

    borg rcreate --encryption repokey-aes-ocb

Borg will:

1. Ask you to come up with a passphrase.
2. Create a borg key (which contains some random secrets. See :ref:`key_files`).
3. Derive a "key encryption key" from your passphrase
4. Encrypt and sign the key with the key encryption key
5. Store the encrypted borg key inside the repository directory (in the repo config).
   This is why it is essential to use a secure passphrase.
6. Encrypt and sign your backups to prevent anyone from reading or forging them unless they
   have the key and know the passphrase. Make sure to keep a backup of
   your key **outside** the repository - do not lock yourself out by
   "leaving your keys inside your car" (see :ref:`borg_key_export`).
   For remote backups the encryption is done locally - the remote machine
   never sees your passphrase, your unencrypted key or your unencrypted files.
   Chunking and id generation are also based on your key to improve
   your privacy.
7. Use the key when extracting files to decrypt them and to verify that the contents of
   the backups have not been accidentally or maliciously altered.

Picking a passphrase
++++++++++++++++++++

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

Choosing an encryption mode
+++++++++++++++++++++++++++

Depending on your hardware, hashing and crypto performance may vary widely.
The easiest way to find out about what's fastest is to run ``borg benchmark cpu``.

`repokey` modes: if you want ease-of-use and "passphrase" security is good enough -
the key will be stored in the repository (in ``repo_dir/config``).

`keyfile` modes: if you rather want "passphrase and having-the-key" security -
the key will be stored in your home directory (in ``~/.config/borg/keys``).

The following table is roughly sorted in order of preference, the better ones are
in the upper part of the table, in the lower part is the old and/or unsafe(r) stuff:

.. nanorst: inline-fill

+-----------------------------------+--------------+----------------+--------------------+---------+
| Mode (K = keyfile or repokey)     | ID-Hash      | Encryption     | Authentication     | V >=    |
+-----------------------------------+--------------+----------------+--------------------+---------+
| K-blake2-chacha20-poly1305        | BLAKE2b      | CHACHA20       | POLY1305           | 2.0     |
+-----------------------------------+--------------+----------------+--------------------+---------+
| K-chacha20-poly1305               | HMAC-SHA-256 | CHACHA20       | POLY1305           | 2.0     |
+-----------------------------------+--------------+----------------+--------------------+---------+
| K-blake2-aes-ocb                  | BLAKE2b      | AES256-OCB     | AES256-OCB         | 2.0     |
+-----------------------------------+--------------+----------------+--------------------+---------+
| K-aes-ocb                         | HMAC-SHA-256 | AES256-OCB     | AES256-OCB         | 2.0     |
+-----------------------------------+--------------+----------------+--------------------+---------+
| K-blake2                          | BLAKE2b      | AES256-CTR     | BLAKE2b            | 1.1     |
+-----------------------------------+--------------+----------------+--------------------+---------+
| K                                 | HMAC-SHA-256 | AES256-CTR     | HMAC-SHA256        | any     |
+-----------------------------------+--------------+----------------+--------------------+---------+
| authenticated-blake2              | BLAKE2b      | none           | BLAKE2b            | 1.1     |
+-----------------------------------+--------------+----------------+--------------------+---------+
| authenticated                     | HMAC-SHA-256 | none           | HMAC-SHA256        | 1.1     |
+-----------------------------------+--------------+----------------+--------------------+---------+
| none                              | SHA-256      | none           | none               | any     |
+-----------------------------------+--------------+----------------+--------------------+---------+

.. nanorst: inline-replace

`none` mode uses no encryption and no authentication. You're advised to NOT use this mode
as it would expose you to all sorts of issues (DoS, confidentiality, tampering, ...) in
case of malicious activity in the repository.

If you do **not** want to encrypt the contents of your backups, but still want to detect
malicious tampering use an `authenticated` mode. It's like `repokey` minus encryption.

Key derivation functions
++++++++++++++++++++++++

- ``--key-algorithm argon2`` is the default and is recommended.
  The key encryption key is derived from your passphrase via argon2-id.
  Argon2 is considered more modern and secure than pbkdf2.

Our implementation of argon2-based key algorithm follows the cryptographic best practices:

- It derives two separate keys from your passphrase: one to encrypt your key and another one
  to sign it. ``--key-algorithm pbkdf2`` uses the same key for both.

- It uses encrypt-then-mac instead of encrypt-and-mac used by ``--key-algorithm pbkdf2``

Neither is inherently linked to the key derivation function, but since we were going
to break backwards compatibility anyway we took the opportunity to fix all 3 issues at once.
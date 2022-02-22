.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_init:

borg init
---------
.. code-block:: none

    borg [common options] init [options] [REPOSITORY]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **positional arguments**                                                                                                                                                                                                                                                                                                            |
    +-------------------------------------------------------+------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``REPOSITORY``                     | repository to create                                                                                                                                                                                                                   |
    +-------------------------------------------------------+------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **optional arguments**                                                                                                                                                                                                                                                                                                              |
    +-------------------------------------------------------+------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``-e MODE``, ``--encryption MODE`` | select encryption key mode **(required)**                                                                                                                                                                                              |
    +-------------------------------------------------------+------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--append-only``                  | create an append-only mode repository. Note that this only affects the low level structure of the repository, and running `delete` or `prune` will still be allowed. See :ref:`append_only_mode` in Additional Notes for more details. |
    +-------------------------------------------------------+------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--storage-quota QUOTA``          | Set storage quota of the new repository (e.g. 5G, 1.5T). Default: no quota.                                                                                                                                                            |
    +-------------------------------------------------------+------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--make-parent-dirs``             | create the parent directories of the repository directory, if they are missing.                                                                                                                                                        |
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

    REPOSITORY
        repository to create


    optional arguments
        -e MODE, --encryption MODE     select encryption key mode **(required)**
        --append-only                  create an append-only mode repository. Note that this only affects the low level structure of the repository, and running `delete` or `prune` will still be allowed. See :ref:`append_only_mode` in Additional Notes for more details.
        --storage-quota QUOTA          Set storage quota of the new repository (e.g. 5G, 1.5T). Default: no quota.
        --make-parent-dirs             create the parent directories of the repository directory, if they are missing.


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

This command initializes an empty repository. A repository is a filesystem
directory containing the deduplicated data from zero or more archives.

Encryption mode TLDR
++++++++++++++++++++

The encryption mode can only be configured when creating a new repository -
you can neither configure it on a per-archive basis nor change the
encryption mode of an existing repository.

Use ``repokey``::

    borg init --encryption repokey /path/to/repo

Or ``repokey-blake2`` depending on which is faster on your client machines (see below)::

    borg init --encryption repokey-blake2 /path/to/repo

Borg will:

1. Ask you to come up with a passphrase.
2. Create a borg key (which contains 3 random secrets. See :ref:`key_files`).
3. Encrypt the key with your passphrase.
4. Store the encrypted borg key inside the repository directory (in the repo config).
   This is why it is essential to use a secure passphrase.
5. Encrypt and sign your backups to prevent anyone from reading or forging them unless they
   have the key and know the passphrase. Make sure to keep a backup of
   your key **outside** the repository - do not lock yourself out by
   "leaving your keys inside your car" (see :ref:`borg_key_export`).
   For remote backups the encryption is done locally - the remote machine
   never sees your passphrase, your unencrypted key or your unencrypted files.
   Chunking and id generation are also based on your key to improve
   your privacy.
6. Use the key when extracting files to decrypt them and to verify that the contents of
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

More encryption modes
+++++++++++++++++++++

Only use ``--encryption none`` if you are OK with anyone who has access to
your repository being able to read your backups and tamper with their
contents without you noticing.

If you want "passphrase and having-the-key" security, use ``--encryption keyfile``.
The key will be stored in your home directory (in ``~/.config/borg/keys``).

If you do **not** want to encrypt the contents of your backups, but still
want to detect malicious tampering use ``--encryption authenticated``.

If ``BLAKE2b`` is faster than ``SHA-256`` on your hardware, use ``--encryption authenticated-blake2``,
``--encryption repokey-blake2`` or ``--encryption keyfile-blake2``. Note: for remote backups
the hashing is done on your local machine.

.. nanorst: inline-fill

+----------+---------------+------------------------+--------------------------+
| Hash/MAC | Not encrypted | Not encrypted,         | Encrypted (AEAD w/ AES)  |
|          | no auth       | but authenticated      | and authenticated        |
+----------+---------------+------------------------+--------------------------+
| SHA-256  | none          | `authenticated`        | repokey                  |
|          |               |                        | keyfile                  |
+----------+---------------+------------------------+--------------------------+
| BLAKE2b  | n/a           | `authenticated-blake2` | `repokey-blake2`         |
|          |               |                        | `keyfile-blake2`         |
+----------+---------------+------------------------+--------------------------+

.. nanorst: inline-replace

Modes `marked like this` in the above table are new in Borg 1.1 and are not
backwards-compatible with Borg 1.0.x.

On modern Intel/AMD CPUs (except very cheap ones), AES is usually
hardware-accelerated.
BLAKE2b is faster than SHA256 on Intel/AMD 64-bit CPUs
(except AMD Ryzen and future CPUs with SHA extensions),
which makes `authenticated-blake2` faster than `none` and `authenticated`.

On modern ARM CPUs, NEON provides hardware acceleration for SHA256 making it faster
than BLAKE2b-256 there. NEON accelerates AES as well.

Hardware acceleration is always used automatically when available.

`repokey` and `keyfile` use AES-CTR-256 for encryption and HMAC-SHA256 for
authentication in an encrypt-then-MAC (EtM) construction. The chunk ID hash
is HMAC-SHA256 as well (with a separate key).
These modes are compatible with Borg 1.0.x.

`repokey-blake2` and `keyfile-blake2` are also authenticated encryption modes,
but use BLAKE2b-256 instead of HMAC-SHA256 for authentication. The chunk ID
hash is a keyed BLAKE2b-256 hash.
These modes are new and *not* compatible with Borg 1.0.x.

`authenticated` mode uses no encryption, but authenticates repository contents
through the same HMAC-SHA256 hash as the `repokey` and `keyfile` modes (it uses it
as the chunk ID hash). The key is stored like `repokey`.
This mode is new and *not* compatible with Borg 1.0.x.

`authenticated-blake2` is like `authenticated`, but uses the keyed BLAKE2b-256 hash
from the other blake2 modes.
This mode is new and *not* compatible with Borg 1.0.x.

`none` mode uses no encryption and no authentication. It uses SHA256 as chunk
ID hash. This mode is not recommended, you should rather consider using an authenticated
or authenticated/encrypted mode. This mode has possible denial-of-service issues
when running ``borg create`` on contents controlled by an attacker.
Use it only for new repositories where no encryption is wanted **and** when compatibility
with 1.0.x is important. If compatibility with 1.0.x is not important, use
`authenticated-blake2` or `authenticated` instead.
This mode is compatible with Borg 1.0.x.
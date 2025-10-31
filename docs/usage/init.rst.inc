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
    | **options**                                                                                                                                                                                                                                                                                                                         |
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


    options
        -e MODE, --encryption MODE     select encryption key mode **(required)**
        --append-only                  create an append-only mode repository. Note that this only affects the low level structure of the repository, and running `delete` or `prune` will still be allowed. See :ref:`append_only_mode` in Additional Notes for more details.
        --storage-quota QUOTA          Set storage quota of the new repository (e.g. 5G, 1.5T). Default: no quota.
        --make-parent-dirs             create the parent directories of the repository directory, if they are missing.


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

This command initializes an empty repository. A repository is a
filesystem directory containing the deduplicated data from zero or more
archives.

Encryption mode TL;DR
+++++++++++++++++++++

The encryption mode can only be configured when creating a new
repository. You can neither configure encryption on a per-archive
basis, nor change the encryption mode of an existing repository. You
should thus take possible future use into account when deciding on an
encryption mode.

As a general rule of thumb, use ``repokey`` with a strong passphrase:

    borg init --encryption repokey /path/to/repo

However, there are many reasons to choose differently. See the section
below for details. In any case, Borg will:

1. Ask you to enter a unique and strong passphrase.
2. Create a random Borg key (which actually consists of three random
   secrets, see :ref:`key_files` for details).
3. Encrypt the Borg key with your passphrase.
4. Store the encrypted Borg key inside the repository directory (with
   ``repokey`` and ``repokey-blake2`` modes; with ``keyfile`` and
   ``keyfile-blake2`` modes the Borg key is stored in your home
   directory instead, see below). Since we usually have to assume that
   an attacker could gain access to the repository (that's why we
   encrypt the data in the first place), choosing a strong and unique
   passphrase is absolutely crucial.
5. Encrypt and sign your backups with the Borg key to prevent anyone
   from reading or forging them unless they have the Borg key *and*
   know the passphrase.
6. Use the Borg key to decrypt and thus access the data stored in your
   repository, e.g. when extracting files. The contents can also be
   verified to detect accidental corruption or malicious tampering.

As you can see, you always need *both* the Borg key and passphrase to
access your data. Thus it's crucial to keep a backup of your key
*outside* both the repository and the system you create backups of.
You can easily run into a "leaving your keys inside your car" situation
otherwise. See :ref:`borg_key_export` to create a backup of your key
(e.g., by printing it on paper).

Encryption is done locally - i.e., if you back up to a remote machine,
the remote machine neither sees your passphrase, nor your unencrypted
Borg key, nor your unencrypted files. Chunking and ID generation are
based on your key to improve privacy.

**About hardware acceleration:**

Borg encrypts data with AES, which is pretty fast thanks to hardware
acceleration on basically all modern Intel, AMD, and ARM CPUs since
around the early 2010s (very cheap models since the mid-2010s).

As the hashing algorithm, Borg can use either SHA256 or BLAKE2b. ARM
CPUs support hardware-accelerated SHA256 hashing since ARMv7 with NEON
(around 2011), or ARMv8 (around 2013). AMD CPUs support it since Zen 1
(around 2017), i.e. all AMD Ryzen CPUs. Intel CPUs support it since Ice
Lake on mobile (10th gen, around 2021), and Rocket Lake on desktop
(11th gen, around 2021). Very cheap models have received support a few
years later. If your CPU doesn't support hardware-accelerated SHA256
hashing, you might want to give BLAKE2b hashing a try - it's likely
faster then. So, instead of ``repokey`` mode, use ``repokey-blake2``
(or any of the other ``-blake2`` modes for that matter).

Hardware acceleration is always used automatically when available.

Picking a passphrase
++++++++++++++++++++

Make sure you use a good passphrase. Not too short, not too simple. The
real encryption / decryption key is encrypted with / locked by your
passphrase. If an attacker gets your borg key, they can't unlock and use
it without knowing the passphrase.

Be careful with special or non-ASCII characters in your passphrase:

- Borg processes the passphrase as Unicode (and encodes it as UTF-8), so
  it does not have problems dealing with even the strangest characters.
- BUT: that does not necessarily apply to your OS / VM / keyboard
  configuration.

So it is better to use a long passphrase made from simple ASCII
characters than one that includes non-ASCII characters or characters
that are hard or impossible to enter on a different keyboard layout.

You can change your passphrase for existing repositories at any time; it
won't affect the encryption/decryption key or other secrets. See
:ref:`borg_key_change-passphrase`.

More about encryption modes
+++++++++++++++++++++++++++

Choosing the right encryption mode isn't always easy and many factors
can change which mode is best for you. However, note that you can't
really do anything *wrong* if you choose ``repokey`` with a strong
passphrase. So, if you're not sure, choose ``repokey`` (or
``repokey-blake2``, depending on your hardware, see above).

Borg supports the following encryption modes:

.. nanorst: inline-fill
.. class:: borg-encryption-table

+----------+-------------------+--------------------------+-------------------------+
| Hash/MAC | Not Encrypted                                | Encrypted (AEAD w/ AES) |
+          +-------------------+--------------------------+-------------------------+
|          | Not Authenticated | Authenticated                                      |
+==========+===================+==========================+=========================+
| SHA-256  | ``none``          | ``authenticated``        | ``repokey``             |
|          |                   |                          | ``keyfile``             |
+----------+-------------------+--------------------------+-------------------------+
| BLAKE2b  | n/a               | ``authenticated-blake2`` | ``repokey-blake2``      |
|          |                   |                          | ``keyfile-blake2``      |
+----------+-------------------+--------------------------+-------------------------+

.. nanorst: inline-replace

Borg 1.0 and older support ``none``, ``repokey``, and ``keyfile``
modes only. If you need such old clients to be able to access your
repo, you can't use any of the other modes.

**About modes without encryption:**

Avoid using ``none`` mode. If you think about using ``none`` mode,
please reconsider and be absolutely sure. Using any mode other than
``none`` allows Borg to detect accidental corruption or malicious
tampering with the repo. It also prevents denial-of-service attacks
against clients. Instead of ``none`` mode, you likely want to use
``authenticated`` mode, or ``repokey`` or ``keyfile`` modes with an
empty passphrase instead (see below).

If you don't want to encrypt your data, use ``authenticated`` or
``authenticated-blake2`` modes. These modes require a passphrase in
normal operation, but in emergency situations you can access the repo
without the passphrase with ``BORG_WORKAROUNDS=authenticated_no_key``
(see :ref:`environment-variables`).

If you just don't want to choose a passphrase, use ``keyfile`` or
``keyfile-blake2`` modes with an empty passphrase. These modes are
generally safe even without a passphrase, but keeping an offsite
backup of the Borg key is also important then. See below for details.

If you can assure that an attacker can't gain access to your repo, e.g.
when independently encrypting your repository disk or filesystem, you
can think about using ``repokey`` or ``repokey-blake2`` modes with an
empty passphrase. However, keep in mind that if an attacker still
somehow manages to gain access, they have full access to your repo. In
such situations choosing ``repokey`` over ``authenticated`` mode has
the advantage of allowing you to add a passphrase later using
:ref:`borg_key_change-passphrase`.

**About modes with encryption:**

With ``repokey`` and ``repokey-blake2`` modes the key is stored with
the repo and encrypted with your passphrase. If an attacker gains
access to your repo and knows the passphrase, he can access and tamper
with the repo. The repo's security thus relies on the strength of your
passphrase. Creating an offsite backup of your Borg key (e.g., by
printing it on paper) is recommended, see :ref:`borg_key_export`.

If you're thinking about storing the passphrase on the disk of the
system you're backing up, consider using the ``keyfile`` method
instead. It generally provides the same or better security then.

With ``keyfile`` and ``keyfile-blake2`` modes the key is stored on your
local machine (in ``~/.config/borg/keys``) instead. An attacker gaining
access to your repo then needs both the Borg key, and your passphrase to
access and tamper with the repo. However, if you lose the key, you lose
access to the repo, too. You **must** create an offsite backup of your
Borg key, e.g. by printing it on paper. Storing a copy of the Borg key
on the system you're creating backups of is **NOT** sufficient. Use
:ref:`borg_key_export` to create the backup.

The ``keyfile`` and ``keyfile-blake2`` modes allow for "passphrase and
having-the-key" security when using a strong passphrase, but can also
be used with an empty passphrase. Storing a (easily readable)
passphrase on the disk of the system you're backing up with
``keyfile`` and ``keyfile-blake2`` modes adds no security over using an
empty passphrase.

**Technical details:**

``repokey`` and ``keyfile`` use AES-CTR-256 for encryption and
HMAC-SHA256 for authentication in an encrypt-then-MAC (EtM)
construction. The chunk ID hash is HMAC-SHA256 (with a separate key).
These modes are compatible with all Borg versions.

``repokey-blake2`` and ``keyfile-blake2`` are also authenticated
encryption modes, but use BLAKE2b-256 instead of HMAC-SHA256 for
authentication. The chunk ID hash is a keyed BLAKE2b-256 hash. These
modes are only compatible with Borg 1.1 and later.

``authenticated`` mode uses no encryption, but authenticates repo
contents through the same HMAC-SHA256 hash as the ``repokey`` and
``keyfile`` modes (it uses it as the chunk ID hash). The key is stored
like ``repokey`` within the repo. This mode is only compatible with
Borg 1.1 and later.

``authenticated-blake2`` is like ``authenticated``, but uses the keyed
BLAKE2b-256 hash from the other BLAKE2b modes. This mode is only
compatible with Borg 1.1 and later.

``none`` mode uses no encryption and no authentication. It uses SHA256
as chunk ID hash. This mode is not recommended. You should instead
consider using an authenticated or authenticated/encrypted mode. This
mode has possible denial-of-service issues when running ``borg create``
on contents controlled by an attacker. See above for alternatives.
This mode is compatible with all Borg versions.
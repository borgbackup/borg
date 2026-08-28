.. include:: ../global.rst.inc

.. somewhat surprisingly the "bash" highlighter gives nice results with
   the pseudo-code notation used in the "Encryption" section.

.. highlight:: bash

========
Security
========

.. _borgcrypto:

Cryptography in Borg
====================

.. _attack_model:

Attack model
------------

The attack model of Borg is that the environment of the client process
(e.g. ``borg create``) is trusted and the repository (server) is not. The
attacker has any and all access to the repository, including interactive
manipulation (man-in-the-middle) for remote repositories.

Furthermore, the client environment is assumed to be persistent across
attacks (practically this means that the security database cannot be
deleted between attacks).

Under these circumstances Borg guarantees that the attacker cannot

1. modify the data of any archive without the client detecting the change
2. rename or add an archive without the client detecting the change
3. recover plain-text data
4. recover definite (heuristics based on access patterns are possible)
   structural information such as the object graph (which archives
   refer to what chunks)

The attacker can always impose a denial of service by definition (they could
block connections to the repository, or delete it partly or entirely).


.. _security_structural_auth:

Structural Authentication
-------------------------

Borg is fundamentally based on an object graph structure (see :ref:`internals`),
where the root objects are the archives.

Borg follows the `Horton principle`_, which states that
not only the message must be authenticated, but also its meaning (often
expressed through context), because every object used is referenced by a
parent object through its object ID up to the archive list entry. The object ID in
Borg is a MAC of the object's plaintext, therefore this ensures that
an attacker cannot change the context of an object without forging the MAC.

In other words, the object ID itself only authenticates the plaintext of the
object and not its context or meaning. The latter is established by a different
object referring to an object ID, thereby assigning a particular meaning to
an object. For example, an archive item contains a list of object IDs that
represent packed file metadata. On their own, it's not clear that these objects
would represent what they do, but by the archive item referring to them
in a particular part of its own data structure assigns this meaning.

This results in a directed acyclic graph of authentication from the archive
list entry to the data chunks of individual files.

Above used to be all for borg 1.x and was the reason why it needed the
tertiary authentication mechanism (TAM) for manifest and archives.

borg 2 now stores the ro_type ("meaning") of a repo object's data into that
object's metadata (like e.g.: manifest vs. archive vs. user file content data).
When loading data from the repo, borg verifies that the type of object it got
matches the type it wanted. borg 2 does not use TAMs any more.

As both the object's metadata and data are authenticated and also bound to
the object ID (via giving the ID as AAD), there is no way an attacker (without
access to the borg key) could change the type of the object or move content
to a different object ID. This holds for the AEAD encryption modes (where the
AEAD tag authenticates them) as well as for the ``authenticated-*`` modes
(where a MAC does, see :ref:`tagged_envelope`).

It does **not** hold for the ``none-*`` modes: they have no key, so their objects
carry an unkeyed checksum rather than a MAC, and an attacker who modifies an
object can simply recompute it. What still constrains an attacker there is the
object ID being the (unkeyed) hash of the plaintext: the content of an existing
object can not be replaced without the ID no longer matching. But the object's
metadata, the archives list and the manifest are not anchored to anything secret,
so a ``none-*`` repository provides no tamper protection - only detection of
accidental corruption.

This effectively 'anchors' each archive to the key, which is controlled by the
client, thereby anchoring the DAG starting from the archives list entry,
making it impossible for an attacker to add or modify any part of the
DAG without Borg being able to detect the tampering.

Please note that removing an archive by removing an entry from archives/*
is possible and is done by ``borg delete`` and ``borg prune`` within their
normal operation. An attacker could also remove some entries there, but, due to
encryption, would not know what exactly they are removing. An attacker with
repository access could also remove other parts of the repository or the whole
repository, so there is not much point in protecting against archive removal.

The borg 1.x way of having the archives list within the manifest chunk was
problematic as it required a read-modify-write operation on the manifest,
requiring a lock on the repository. We want to try less locking and more
parallelism in future.

Passphrase notes
----------------

Note that when using BORG_PASSPHRASE the attacker cannot swap the *entire*
repository against a new repository with e.g. repokey mode and no passphrase,
because Borg will abort access when BORG_PASSPHRASE is incorrect.

However, interactively a user might not notice this kind of attack
immediately, if she assumes that the reason for the absent passphrase
prompt is a set BORG_PASSPHRASE. See issue :issue:`2169` for details.

.. _security_encryption:

Encryption
----------

AEAD modes
~~~~~~~~~~

Modes: ``--encryption (aes256-ocb|chacha20-poly1305)`` plus
``--id-hash (sha256|blake3)``

Supported: borg 2.0+

The cipher is selected by ``--encryption`` (see :ref:`borg_repo-create`), the
key storage location (repokey or keyfile) by ``--key-location``, and the chunk
ID hash function by ``--id-hash`` — these three are orthogonal.

Encryption with these modes is based on AEAD ciphers (authenticated encryption
with associated data) and session keys.

Depending on the chosen mode different AEAD ciphers are used:

- AES-256-OCB - super fast, single-pass algorithm IF you have hw accelerated AES.
- chacha20-poly1305 - very fast, purely software based AEAD cipher.

The chunk ID is derived via a MAC over the plaintext (mac key taken from borg key):

- HMAC-SHA256 (``--id-hash sha256``) - super fast IF you have hw accelerated SHA256 (see section "Encryption" below).
- keyed BLAKE3 (``--id-hash blake3``) - very fast, purely software based algorithm.

For each borg invocation, a new session id is generated by `os.urandom`_.

From that session id, the initial key material (ikm, taken from the borg key)
and an application and cipher specific salt, borg derives a session key using a
"one-step KDF" based on just sha256.

For each session key, IVs (nonces) are generated by a counter which increments for
each encrypted message.

Session::

    sessionid = os.urandom(24)
    domain = "borg-session-key-CIPHERNAME"
    sessionkey = sha256(crypt_key + sessionid + domain)
    message_iv = 0

A repository object has two separately encrypted slots, the object metadata and the
object data, and both are stored behind one unencrypted object header (magic, format
version, chunk id, slot sizes - see :ref:`pack-format`). The header prefix and the
slot a ciphertext belongs to are bound into its authentication tag as well:

Encryption::

    id = MAC(id_key, data)
    compressed = compress(data)

    # the unencrypted repo object header prefix (41 bytes) this ciphertext is stored
    # behind, and which of the object's two slots it goes into:
    obj_header_aad = OBJ_MAGIC || obj_version || id
    slot_tag = "M" for the object metadata slot, "D" for the object data slot

    header = type-byte || 00h || message_iv || sessionid
    aad = obj_header_aad || slot_tag || id || header
    message_iv++
    encrypted, auth_tag = AEAD_encrypt(session_key, message_iv, compressed, aad)
    authenticated = header || auth_tag || encrypted

Decryption::

    # Given: input *authenticated* data, a *chunk-id* to assert, and the object header
    # prefix / slot the ciphertext was read from
    type-byte, past_message_iv, past_sessionid, auth_tag, encrypted = SPLIT(authenticated)

    ASSERT(type-byte is correct)

    domain = "borg-session-key-CIPHERNAME"
    past_key = sha256(crypt_key + past_sessionid + domain)

    header = type-byte || 00h || past_message_iv || past_sessionid
    aad = obj_header_aad || slot_tag || id || header
    decrypted = AEAD_decrypt(past_key, past_message_iv, authenticated, aad)

    decompressed = decompress(decrypted)

Notable:

- More modern and often faster AEAD ciphers instead of self-assembled stuff.
- Due to the usage of session keys, which just start at 0 per session, IVs (nonces)
  do not need long-term special care here as they did for the legacy encryption modes.
- The session key is also changed within a borg invocation if we encrypted a lot of data
  with it (AES-OCB only, see :ref:`aead_usage_limits`). Reading is not affected by this,
  because the session id is part of every message.
- The id is also input into the authentication tag computation.
  This strongly associates the id with the written data (== associates the key with
  the value). When later reading the data for some id, authentication will only
  succeed if what we get was really written by us for that id. Since repo object
  format version 2, the object header prefix (magic, format version and the chunk id
  the header declares) and the slot tag are authenticated along with it, so a
  ciphertext can neither be presented under a forged object header nor be swapped
  between the metadata and the data slot of an object, see :ref:`pack-format`.
- Because of that, additionally verifying ``id == MAC(id_key, decompressed)`` after
  decryption is optional for these modes: it is not what protects against a malicious
  repository (the authentication tag does that), it only detects chunks whose content
  does not match their id - which only a malicious or compromised borg client that had
  the borg key could have written. Borg therefore does not verify that on every read by
  default, see the ``BORG_ASSERT_ID`` environment variable for details and for the places
  where borg verifies it by default (e.g. ``borg check --verify-data``, which is the
  recommended periodic audit for this).


Authenticated modes
~~~~~~~~~~~~~~~~~~~

Modes: ``--encryption authenticated-(sha256|blake3)``

Supported: borg 2.0+

These modes do not encrypt: everything in the repository is readable by anybody who
can read the repository. They do authenticate, though - like an AEAD mode minus the
data encryption:

- Every repository object slot (metadata and data) carries a MAC over the payload, the
  object header and the slot, see :ref:`tagged_envelope`. Reading verifies it before the
  payload is used for anything (in particular before decompressing it), so tampering with
  any of them is detected, whether accidental or malicious.
- The chunk IDs are MACs over the plaintext, as in the encrypted modes.
- The MAC key lives in a borg key (repokey or keyfile, ``--key-location``), protected by a
  passphrase like the keys of the encrypted modes. An attacker without that key can neither
  forge objects nor chunk IDs.

Different from the AEAD modes, the MAC is deterministic (a MAC needs no nonce): there is no
session key, no IV and thus no usage limit to observe, and identical input produces identical
objects.

Unencrypted modes
~~~~~~~~~~~~~~~~~

Modes: ``--encryption none-(sha256|blake3)``

Supported: borg 2.0+

These modes have no key at all: they neither encrypt nor authenticate. Every repository
object slot carries an *unkeyed* checksum (see :ref:`tagged_envelope`), which detects
accidental corruption - bad storage hardware, a truncated write, a read that returned the
wrong bytes - before the data is used. It is not a protection against an attacker: whoever
modifies an object can recompute the checksum, and the chunk IDs are unkeyed hashes as well.

You are advised not to use these modes. Use ``authenticated-*`` instead if you do not want
your data encrypted but do want to detect tampering; it is the same thing plus a key.

Legacy modes
~~~~~~~~~~~~

Modes: ``--encryption (repokey|keyfile)[-blake2]``, ``--encryption (none|authenticated)``

Supported: borg < 2.0

These were the AES-CTR based modes in previous borg versions, with the chunk ID
derived via HMAC-SHA256 or (in the ``-blake2`` variants) Blake2b. ``blake2b`` is
only used by these legacy modes; new repositories use ``sha256`` or ``blake3``
(see above).

The borg 1.x ``none`` and ``authenticated`` modes belong here, too: their repository
objects have no tag at all, so nothing about an object is verified except the chunk ID
over the plaintext - not even the object's metadata. They were replaced by the modes
described above, which cover metadata and object header as well.

borg 2.0 does not support creating new repos using these modes,
but ``borg transfer`` can still read such existing repos.


.. _key_encryption:

Offline key security
--------------------

Borg cannot secure the key material while it is running, because the keys
are needed in plain to decrypt/encrypt repository objects.

For offline storage of the encryption keys they are encrypted with a
user-chosen passphrase.

A 256 bit key encryption key (KEK) is derived from the passphrase
using argon2_ (argon2id, ``ARGON2_ARGS``) with a random 128 bit salt. The KEK is then used
to Encrypt-*then*-MAC a packed representation of the keys using the
chacha20-poly1305 AEAD cipher and a constant IV == 0.
The ciphertext is then converted to base64.

This base64-encoded *borg key* is then stored in the key file or under the
repository's ``keys/`` namespace (keyfile and repokey modes respectively), named
by the sha256 of its content.

The use of a constant IV is secure because an identical passphrase will
result in a different derived KEK for every key encryption due to the salt.

.. _borgcrypto_multiple_keys:

Multiple borg keys
~~~~~~~~~~~~~~~~~~

A repository (or a client-side keyfile directory) may hold *multiple* borg keys,
each encrypted with its own passphrase but all wrapping the **same** underlying
key material. This lets several people access a shared repository with
independent passphrases, without sharing one secret. Or you can add borg keys
for redundant, more fault-tolerant storage.

keyfile and repokey borg keys use the same format and the same sha256-content
naming; borg locates a borg key independently of its key type byte and tries each
available one against the supplied passphrase until one decrypts. A borg key may
carry a label for management. The constant-IV argument above still holds, because
each borg key has its own random argon2 salt and therefore a distinct derived KEK.


.. seealso::

   Refer to the :ref:`key_files` section for details on the format.


Implementations used
--------------------

We do not implement cryptographic primitives ourselves, but rely
on widely used libraries providing them:

- AES-OCB and CHACHA20-POLY1305 from OpenSSL 1.1 are used,
  which is also linked into the static binaries we provide.
  We think this is not an additional risk, since we don't ever
  use OpenSSL's networking, TLS or X.509 code, but only their
  primitives implemented in libcrypto.
- SHA-256 and SHA-512 from Python's hashlib_ standard library module are used.
- BLAKE3 is used via the blake3_ package (new repos, ``--id-hash blake3``).
- BLAKE2b from Python's hashlib_ is only used to read legacy (borg < 2.0) repos.
- HMAC and a constant-time comparison from Python's hmac_ standard library module are used.
- argon2 is used from OpenSSL (>= 3.2).

.. _Horton principle: https://en.wikipedia.org/wiki/Horton_Principle
.. _length extension: https://en.wikipedia.org/wiki/Length_extension_attack
.. _hashlib: https://docs.python.org/3/library/hashlib.html
.. _blake3: https://pypi.org/project/blake3/
.. _hmac: https://docs.python.org/3/library/hmac.html
.. _os.urandom: https://docs.python.org/3/library/os.html#os.urandom

.. _remote_access_security:

Remote repository access security
=================================

.. note:: This section could be further expanded / detailed.

Borg 2 has no repository protocol of its own. A repository is a borgstore object
store (see :ref:`internals`), and borgstore owns the client/server transport. The
same set of named objects is what a remote end gets to see, whatever transport is
used:

- ``packs/<hex(pack_id)>`` -- the pack files holding the repository objects. Each
  object's metadata slot and data slot are encrypted and authenticated with the borg
  key (see :ref:`security_encryption`); its per-object header is unencrypted and
  carries the magic, the format version and the chunk id (see :ref:`pack-format`).
- ``index/<sha256>`` -- the chunk id to pack location index. It is not encrypted,
  but it only contains chunk ids and locations, which the pack headers expose anyway.
- ``archives/<hex(archive_id)>`` -- one empty object per archive. The archive name,
  its timestamps, the item metadata and the chunk lists all live inside encrypted
  repository objects, so the pointer object itself only reveals the archive id (a MAC
  over the archive metadata) plus whatever the store records about it, e.g. its
  modification time.
- ``config/manifest`` (an encrypted repository object), plus the plaintext
  ``config/version``, ``config/id`` and ``config/readme``.
- ``keys/<sha256>`` -- in ``repokey`` mode, the borg key(s), encrypted with the
  passphrase-derived KEK (see :ref:`key_encryption`).
- ``locks/*`` and ``cache/*``. Note that the per-archive reference caches
  ``cache/referenced-by-archive.<hex(archive_id)>``, written by ``borg compact`` and
  ``borg analyze``, are *not* encrypted: they list the object ids and plaintext sizes
  an archive references.

Authorization and transport security come from the transport, not from borg.

Remote repositories over SSH: ``rest://``
-----------------------------------------

For a ``rest://`` repository, borg runs ``borg serve --rest --backend FILE:<path>``
on the remote machine and speaks HTTP to it over that process' *stdin/stdout* -- not
over a socket. If the URL contains a host, the process is started through the
system's SSH client (honouring ``BORG_RSH`` / ``BORGSTORE_RSH`` for the ssh command
and ``BORG_REMOTE_PATH`` for the remote borg), so:

- Authorization, confidentiality and integrity of the channel are entirely SSH's and
  are determined by the SSH client and server configuration. Borg contains no
  networking code on this path -- it only talks to a subprocess over pipes. That also
  means borg does not have to use an SSH client (or SSH at all); ``sudo`` or
  ``qrexec`` could be used as an intermediary.
- The stdio REST server binds no port and does no authentication of its own: the
  client has already authenticated to sshd, and sshd is what starts the server, as
  that user.

By using the system's SSH client instead of implementing a cryptographic network
protocol, borg sidesteps many security issues that would otherwise impact
distributing statically linked / standalone binaries.

Server-side restrictions are available and, being server-side, they also hold against
a malicious client:

- ``--restrict-to-path`` / ``--restrict-to-repository`` are checked against the
  requested ``FILE:`` path before anything is served.
- ``--permissions`` (or ``BORG_REPO_PERMISSIONS``) selects one of ``all``,
  ``no-delete``, ``write-only`` or ``read-only``, which map to per-namespace
  list/read/write/overwrite/delete permissions enforced by the borgstore backend.

Other transports
----------------

The remaining transports are implemented inside the borg process by borgstore and
its dependencies, so their security properties are those of the respective library:

- ``sftp://`` speaks SFTP in-process via paramiko. Host keys are taken from the
  user's ``known_hosts`` file and no missing-host-key policy is installed, so an
  unknown host is rejected -- make the first connection with the ``ssh`` or ``sftp``
  command line tool and verify the fingerprint there.
- ``s3:``/``b2:`` use boto3, i.e. in-process HTTPS to the (S3-compatible) endpoint,
  authenticated with the credentials from the URL, a named profile, or the usual
  boto3 environment/configuration.
- ``rclone:`` starts an ``rclone rcd`` process listening on ``127.0.0.1`` on a random
  port with a random user/password and drives it over its rc API. Remote credentials
  and transport security are rclone's.
- ``http(s)://`` talks to a borgstore REST server over plain HTTP, authenticating
  with HTTP Basic auth taken from the URL or from ``BORGSTORE_REST_USERNAME`` /
  ``BORGSTORE_REST_PASSWORD``. Basic auth sends the credentials to the server on
  every request, so use ``https`` if you use this at all. ``rest://`` over SSH needs
  no such credentials.

In every case the repository never receives the borg key or the passphrase, so a
compromised or malicious repository server cannot read the backed up data. What it
can do is deny service and return wrong or missing objects; the latter is detected
client-side, see :ref:`attack_model` and :ref:`security_structural_auth`.

Legacy borg 1.x RPC protocol
----------------------------

``borg serve`` *without* ``--rest`` still speaks the borg 1.x RPC protocol:
msgpack'd messages exchanged over stdio (``borg.legacy.remote``). It exists only so
that borg 2 can *read* a borg 1.x repository through an ``ssh://`` URL, e.g. for
``borg transfer --from-borg1``; ``ssh://`` is rejected for current repositories, and
this protocol cannot serve one. Its transport is the system's SSH client, so the same
"authorization and transport security are SSH's" reasoning as for ``rest://``
applies.

Within that protocol, critical vulnerabilities such as remote code execution are
inhibited by its design:

1. The server cannot send requests to the client on its own accord, it only sends
   log records and responses. This avoids "unexpected inversion of control" issues.
2. msgpack serialization does not allow embedding or referencing code that is
   automatically executed. Incoming messages are unpacked by the msgpack unpacker
   into native Python data structures (like tuples and dictionaries), which are then
   passed to the rest of the program.

   Additional verification of the correct form of the responses could be implemented.
3. Remote errors and log output reach the client in two forms:

   1. Log records sent as msgpack messages on the main data channel and re-emitted
      through the client's logging, using the logger name and level the server
      supplied. A server can therefore send arbitrary log messages, which may confuse
      a user. However, the client only reads from the connection while a request is in
      progress, so the server cannot interfere with security critical dialogue like
      the passphrase prompt. Anything the server (or the ssh process) writes to
      *stderr* is logged verbatim as a client-side warning.
   2. Server-side exceptions passed over the main data channel. These follow the
      general pattern of server-sent responses and are sent instead of response data
      for a request.

Note that the msgpack unpackers of the RPC data channel (``get_limited_unpacker()``
kinds ``client`` and ``server``) are deliberately configured with the maximum buffer
size, because whole repository objects are transferred through them. They therefore
do not bound the memory a peer can make the other side allocate; the stricter limits
of that helper apply to manifest, archive and key data.

The msgpack implementation used (msgpack-python) has a good security track record,
a large test suite and no issues found by fuzzing. It is based on the msgpack-c implementation,
sharing the unpacking engine and some support code. msgpack-c has a good track record as well.
Some issues [#]_ in the past were located in code not included in msgpack-python.
Borg does not use msgpack-c.

.. [#] - `MessagePack fuzzing <https://web.archive.org/web/20171004004418/https://blog.gypsyengineer.com/fun/msgpack-fuzzing.html>`_
       - `Fixed integer overflow and EXT size problem <https://github.com/msgpack/msgpack-c/pull/547>`_
       - `Fixed array and map size overflow <https://github.com/msgpack/msgpack-c/pull/550>`_

Using OpenSSL
=============

Borg uses the OpenSSL library for most cryptography (see `Implementations used`_ above).
OpenSSL is bundled with static releases, thus the bundled copy is not updated with system
updates.

OpenSSL is a large and complex piece of software and has had its share of vulnerabilities,
however, it is important to note that Borg links against ``libcrypto`` **not** ``libssl``.
libcrypto is the low-level cryptography part of OpenSSL,
while libssl implements TLS and related protocols.

The latter historically contained most vulnerabilities, especially critical ones, and Borg's own
extension modules do not use it: they link ``libcrypto`` only. Note that libssl can still be
reached through Python's ``ssl`` module by the transports that do networking inside the borg
process, i.e. ``s3:``/``b2:`` and ``http(s)://`` (see :ref:`remote_access_security`); ``rest://``
and the legacy ``ssh://`` protocol do not need it, as they only talk to a subprocess over pipes.
Accordingly, the binaries released by the project do include Python's ``ssl``/``_ssl`` modules
(they are needed by pyfuse3/trio as well).

Compression and Encryption
==========================

Combining encryption with compression can be insecure in some contexts (e.g. online protocols).

There was some discussion about this in :issue:`1040` and for Borg some developers
concluded this is no problem at all, some concluded this is hard and extremely slow to exploit
and thus no problem in practice.

No matter what, there is always the option not to use compression if you are worried about this.


Fingerprinting
==============

Stored chunk sizes
------------------

A borg repository does not hide the size of the chunks it stores (size
information is needed to operate the repository).

The chunks stored in the repo are the (compressed, encrypted and authenticated)
output of the chunker. The sizes of these stored chunks are influenced by the
compression, encryption and authentication.

buzhash and buzhash64 chunker
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The buzhash chunkers chunk according to the input data, the chunker's
parameters and secret key material (which all influence the chunk boundary
positions).

Secret key material:

- "buzhash": chunker seed (32bits), used for XORing the hardcoded buzhash table
- "buzhash64": bh64_key (256bits) is derived from ID key, used to cryptographically
  generate the table.

Small files below some specific threshold (default: 512 KiB) result in only one
chunk (identical content / size as the original file), bigger files result in
multiple chunks.

fixed chunker
~~~~~~~~~~~~~

This chunker yields fixed sized chunks, with optional support of a differently
sized header chunk. The last chunk is not required to have the full block size
and is determined by the input file size.

Within our attack model, an attacker possessing a specific set of files which
he assumes that the victim also possesses (and backups into the repository)
could try a brute force fingerprinting attack based on the chunk sizes in the
repository to prove his assumption.

To make this more difficult, borg has an ``obfuscate`` pseudo compressor, that
will take the output of the normal compression step and tries to obfuscate
the size of that output. Of course, it can only **add** to the size, not reduce
it. Thus, the optional usage of this mechanism comes at a cost: it will make
your repository larger (ranging from a few percent larger [cheap] to ridiculously
larger [expensive], depending on the algorithm/params you wisely choose).

The output of the compressed-size obfuscation step will then be encrypted and
authenticated, as usual. Of course, using that obfuscation would not make any
sense without encryption. Thus, the additional data added by the obfuscator
are just 0x00 bytes, which is good enough because after encryption it will
look like random anyway.

To summarize, this is making size-based fingerprinting difficult:

- user-selectable chunker algorithm (and parametrization)
- for the buzhash chunker: secret, random per-repo chunker seed
- user-selectable compression algorithm (and level)
- optional ``obfuscate`` pseudo compressor with different choices
  of algorithm and parameters

Secret key usage against fingerprinting
---------------------------------------

Borg uses the borg key also for chunking and chunk ID generation to protect against fingerprinting.
As usual for borg's attack model, the attacker is assumed to have access to a borg repository.

The borg key includes a secret random chunk_seed which (together with the chunking algorithm)
determines the cutting places and thereby the length of the chunks cut. Because the attacker trying
a chunk length fingerprinting attack would use a different chunker secret than the borg setup being
attacked, they would not be able to determine the set of chunk lengths for a known set of files.

The borg key also includes a secret random id_key. The chunk ID generation is not just using a simple
cryptographic hash like sha256 (because that would be insecure as an attacker could see the hashes of
small files that result only in 1 chunk in the repository). Instead, borg uses keyed hash (a MAC,
e.g. HMAC-SHA256) to compute the chunk ID from the content and the secret id_key. Thus, an attacker
can't compute the same chunk IDs for a known set of small files to determine whether these are stored
in the attacked repository.

Stored chunk proximity
----------------------

Borg does not try to obfuscate order / proximity of files it discovers by
recursing through the filesystem. For performance reasons, we sort directory
contents in file inode order (not in file name alphabetical order), so order
fingerprinting is not useful for an attacker.

But, when new files are close to each other (when looking at recursion /
scanning order), the resulting chunks will be also stored close to each other
in the resulting repository pack file(s), see :ref:`packs`.

This might leak additional information for the chunk size fingerprinting
attack (see above).

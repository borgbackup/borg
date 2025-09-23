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

As both the object's metadata and data are AEAD encrypted and also bound to
the object ID (via giving the ID as AAD), there is no way an attacker (without
access to the borg key) could change the type of the object or move content
to a different object ID.

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

Modes: --encryption (repokey|keyfile)-[blake2-](aes-ocb|chacha20-poly1305)

Supported: borg 2.0+

Encryption with these modes is based on AEAD ciphers (authenticated encryption
with associated data) and session keys.

Depending on the chosen mode (see :ref:`borg_repo-create`) different AEAD ciphers are used:

- AES-256-OCB - super fast, single-pass algorithm IF you have hw accelerated AES.
- chacha20-poly1305 - very fast, purely software based AEAD cipher.

The chunk ID is derived via a MAC over the plaintext (mac key taken from borg key):

- HMAC-SHA256 - super fast IF you have hw accelerated SHA256 (see section "Encryption" below).
- Blake2b - very fast, purely software based algorithm.

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

Encryption::

    id = MAC(id_key, data)
    compressed = compress(data)

    header = type-byte || 00h || message_iv || sessionid
    aad = id || header
    message_iv++
    encrypted, auth_tag = AEAD_encrypt(session_key, message_iv, compressed, aad)
    authenticated = header || auth_tag || encrypted

Decryption::

    # Given: input *authenticated* data and a *chunk-id* to assert
    type-byte, past_message_iv, past_sessionid, auth_tag, encrypted = SPLIT(authenticated)

    ASSERT(type-byte is correct)

    domain = "borg-session-key-CIPHERNAME"
    past_key = sha256(crypt_key + past_sessionid + domain)

    decrypted = AEAD_decrypt(past_key, past_message_iv, authenticated)

    decompressed = decompress(decrypted)

Notable:

- More modern and often faster AEAD ciphers instead of self-assembled stuff.
- Due to the usage of session keys, IVs (nonces) do not need special care here as
  they did for the legacy encryption modes.
- The id is now also input into the authentication tag computation.
  This strongly associates the id with the written data (== associates the key with
  the value). When later reading the data for some id, authentication will only
  succeed if what we get was really written by us for that id.


Legacy modes
~~~~~~~~~~~~

Modes: --encryption (repokey|keyfile)-[blake2]

Supported: borg < 2.0

These were the AES-CTR based modes in previous borg versions.

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
using argon2_ with a random 256 bit salt. The KEK is then used
to Encrypt-*then*-MAC a packed representation of the keys using the
chacha20-poly1305 AEAD cipher and a constant IV == 0.
The ciphertext is then converted to base64.

This base64 blob (commonly referred to as *keyblob*) is then stored in
the key file or in the repository config (keyfile and repokey modes
respectively).

The use of a constant IV is secure because an identical passphrase will
result in a different derived KEK for every key encryption due to the salt.


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
- SHA-256, SHA-512 and BLAKE2b from Python's hashlib_ standard library module are used.
- HMAC and a constant-time comparison from Python's hmac_ standard library module are used.
- argon2 is used via argon2-cffi.

.. _Horton principle: https://en.wikipedia.org/wiki/Horton_Principle
.. _length extension: https://en.wikipedia.org/wiki/Length_extension_attack
.. _hashlib: https://docs.python.org/3/library/hashlib.html
.. _hmac: https://docs.python.org/3/library/hmac.html
.. _os.urandom: https://docs.python.org/3/library/os.html#os.urandom

Remote RPC protocol security
============================

.. note:: This section could be further expanded / detailed.

The RPC protocol is fundamentally based on msgpack'd messages exchanged
over an encrypted SSH channel (the system's SSH client is used for this
by piping data from/to it).

This means that the authorization and transport security properties
are inherited from SSH and the configuration of the SSH client and the
SSH server -- Borg RPC does not contain *any* networking
code. Networking is done by the SSH client running in a separate
process, Borg only communicates over the standard pipes (stdout,
stderr and stdin) with this process. This also means that Borg doesn't
have to use a SSH client directly (or SSH at all). For example,
``sudo`` or ``qrexec`` could be used as an intermediary.

By using the system's SSH client and not implementing a
(cryptographic) network protocol Borg sidesteps many security issues
that would normally impact distributing statically linked / standalone
binaries.

The remainder of this section will focus on the security of the RPC
protocol within Borg.

The assumed worst-case a server can inflict to a client is a
denial of repository service.

The situation where a server can create a general DoS on the client
should be avoided, but might be possible by e.g. forcing the client to
allocate large amounts of memory to decode large messages (or messages
that merely indicate a large amount of data follows). The RPC protocol
code uses a limited msgpack Unpacker to prohibit this.

We believe that other kinds of attacks, especially critical vulnerabilities
like remote code execution are inhibited by the design of the protocol:

1. The server cannot send requests to the client on its own accord,
   it only can send responses. This avoids "unexpected inversion of control"
   issues.
2. msgpack serialization does not allow embedding or referencing code that
   is automatically executed. Incoming messages are unpacked by the msgpack
   unpacker into native Python data structures (like tuples and dictionaries),
   which are then passed to the rest of the program.

   Additional verification of the correct form of the responses could be implemented.
3. Remote errors are presented in two forms:

   1. A simple plain-text *stderr* channel. A prefix string indicates the kind of message
      (e.g. WARNING, INFO, ERROR), which is used to suppress it according to the
      log level selected in the client.

      A server can send arbitrary log messages, which may confuse a user. However,
      log messages are only processed when server requests are in progress, therefore
      the server cannot interfere / confuse with security critical dialogue like
      the password prompt.
   2. Server-side exceptions passed over the main data channel. These follow the
      general pattern of server-sent responses and are sent instead of response data
      for a request.

The msgpack implementation used (msgpack-python) has a good security track record,
a large test suite and no issues found by fuzzing. It is based on the msgpack-c implementation,
sharing the unpacking engine and some support code. msgpack-c has a good track record as well.
Some issues [#]_ in the past were located in code not included in msgpack-python.
Borg does not use msgpack-c.

.. [#] - `MessagePack fuzzing <https://blog.gypsyengineer.com/fun/msgpack-fuzzing.html>`_
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

The latter is not used by Borg (cf. `Remote RPC protocol security`_, Borg itself does not implement
any network access) and historically contained most vulnerabilities, especially critical ones.
The static binaries released by the project contain neither libssl nor the Python ssl/_ssl modules.

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
in the resulting repository segment file(s).

This might leak additional information for the chunk size fingerprinting
attack (see above).

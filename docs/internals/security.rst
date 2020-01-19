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

Furthermore the client environment is assumed to be persistent across
attacks (practically this means that the security database cannot be
deleted between attacks).

Under these circumstances Borg guarantees that the attacker cannot

1. modify the data of any archive without the client detecting the change
2. rename, remove or add an archive without the client detecting the change
3. recover plain-text data
4. recover definite (heuristics based on access patterns are possible)
   structural information such as the object graph (which archives
   refer to what chunks)

The attacker can always impose a denial of service per definition (he could
forbid connections to the repository, or delete it entirely).

When the above attack model is extended to include multiple clients
independently updating the same repository, then Borg fails to provide
confidentiality (i.e. guarantees 3) and 4) do not apply any more).

.. _security_structural_auth:

Structural Authentication
-------------------------

Borg is fundamentally based on an object graph structure (see :ref:`internals`),
where the root object is called the manifest.

Borg follows the `Horton principle`_, which states that
not only the message must be authenticated, but also its meaning (often
expressed through context), because every object used is referenced by a
parent object through its object ID up to the manifest. The object ID in
Borg is a MAC of the object's plaintext, therefore this ensures that
an attacker cannot change the context of an object without forging the MAC.

In other words, the object ID itself only authenticates the plaintext of the
object and not its context or meaning. The latter is established by a different
object referring to an object ID, thereby assigning a particular meaning to
an object. For example, an archive item contains a list of object IDs that
represent packed file metadata. On their own it's not clear that these objects
would represent what they do, but by the archive item referring to them
in a particular part of its own data structure assigns this meaning.

This results in a directed acyclic graph of authentication from the manifest
to the data chunks of individual files.

.. _tam_description:

.. rubric:: Authenticating the manifest

Since the manifest has a fixed ID (000...000) the aforementioned authentication
does not apply to it, indeed, cannot apply to it; it is impossible to authenticate
the root node of a DAG through its edges, since the root node has no incoming edges.

With the scheme as described so far an attacker could easily replace the manifest,
therefore Borg includes a tertiary authentication mechanism (TAM) that is applied
to the manifest since version 1.0.9 (see :ref:`tam_vuln`).

TAM works by deriving a separate key through HKDF_ from the other encryption and
authentication keys and calculating the HMAC of the metadata to authenticate [#]_::

    # RANDOM(n) returns n random bytes
    salt = RANDOM(64)

    ikm = id_key || enc_key || enc_hmac_key
    # *context* depends on the operation, for manifest authentication it is
    # the ASCII string "borg-metadata-authentication-manifest".
    tam_key = HKDF-SHA-512(ikm, salt, context)

    # *data* is a dict-like structure
    data[hmac] = zeroes
    packed = pack(data)
    data[hmac] = HMAC(tam_key, packed)
    packed_authenticated = pack(data)

Since an attacker cannot gain access to this key and also cannot make the
client authenticate arbitrary data using this mechanism, the attacker is unable
to forge the authentication.

This effectively 'anchors' the manifest to the key, which is controlled by the
client, thereby anchoring the entire DAG, making it impossible for an attacker
to add, remove or modify any part of the DAG without Borg being able to detect
the tampering.

Note that when using BORG_PASSPHRASE the attacker cannot swap the *entire*
repository against a new repository with e.g. repokey mode and no passphrase,
because Borg will abort access when BORG_PASSPRHASE is incorrect.

However, interactively a user might not notice this kind of attack
immediately, if she assumes that the reason for the absent passphrase
prompt is a set BORG_PASSPHRASE. See issue :issue:`2169` for details.

.. [#] The reason why the authentication tag is stored in the packed
       data itself is that older Borg versions can still read the
       manifest this way, while a changed layout would have broken
       compatibility.

.. _security_encryption:

Encryption
----------

Encryption is currently based on the Encrypt-then-MAC construction,
which is generally seen as the most robust way to create an authenticated
encryption scheme from encryption and message authentication primitives.

Every operation (encryption, MAC / authentication, chunk ID derivation)
uses independent, random keys generated by `os.urandom`_ [#]_.

Borg does not support unauthenticated encryption -- only authenticated encryption
schemes are supported. No unauthenticated encryption schemes will be added
in the future.

Depending on the chosen mode (see :ref:`borg_init`) different primitives are used:

- The actual encryption is currently always AES-256 in CTR mode. The
  counter is added in plaintext, since it is needed for decryption,
  and is also tracked locally on the client to avoid counter reuse.

- The authentication primitive is either HMAC-SHA-256 or BLAKE2b-256
  in a keyed mode. HMAC-SHA-256 uses 256 bit keys, while BLAKE2b-256
  uses 512 bit keys.

  The latter is secure not only because BLAKE2b itself is not
  susceptible to `length extension`_, but also since it truncates the
  hash output from 512 bits to 256 bits, which would make the
  construction safe even if BLAKE2b were broken regarding length
  extension or similar attacks.

- The primitive used for authentication is always the same primitive
  that is used for deriving the chunk ID, but they are always
  used with independent keys.

Encryption::

    id = AUTHENTICATOR(id_key, data)
    compressed = compress(data)

    iv = reserve_iv()
    encrypted = AES-256-CTR(enc_key, 8-null-bytes || iv, compressed)
    authenticated = type-byte || AUTHENTICATOR(enc_hmac_key, encrypted) || iv || encrypted


Decryption::

    # Given: input *authenticated* data, possibly a *chunk-id* to assert
    type-byte, mac, iv, encrypted = SPLIT(authenticated)

    ASSERT(type-byte is correct)
    ASSERT( CONSTANT-TIME-COMPARISON( mac, AUTHENTICATOR(enc_hmac_key, encrypted) ) )

    decrypted = AES-256-CTR(enc_key, 8-null-bytes || iv, encrypted)
    decompressed = decompress(decrypted)

    ASSERT( CONSTANT-TIME-COMPARISON( chunk-id, AUTHENTICATOR(id_key, decompressed) ) )

The client needs to track which counter values have been used, since
encrypting a chunk requires a starting counter value and no two chunks
may have overlapping counter ranges (otherwise the bitwise XOR of the
overlapping plaintexts is revealed).

The client does not directly track the counter value, because it
changes often (with each encrypted chunk), instead it commits a
"reservation" to the security database and the repository by taking
the current counter value and adding 4 GiB / 16 bytes (the block size)
to the counter. Thus the client only needs to commit a new reservation
every few gigabytes of encrypted data.

This mechanism also avoids reusing counter values in case the client
crashes or the connection to the repository is severed, since any
reservation would have been committed to both the security database
and the repository before any data is encrypted. Borg uses its
standard mechanism (SaveFile) to ensure that reservations are durable
(on most hardware / storage systems), therefore a crash of the
client's host would not impact tracking of reservations.

However, this design is not infallible, and requires synchronization
between clients, which is handled through the repository. Therefore in
a multiple-client scenario a repository can trick a client into
reusing counter values by ignoring counter reservations and replaying
the manifest (which will fail if the client has seen a more recent
manifest or has a more recent nonce reservation). If the repository is
untrusted, but a trusted synchronization channel exists between
clients, the security database could be synchronized between them over
said trusted channel. This is not part of Borg's functionality.

.. [#] Using the :ref:`borg key migrate-to-repokey <borg_key_migrate-to-repokey>`
       command a user can convert repositories created using Attic in "passphrase"
       mode to "repokey" mode. In this case the keys were directly derived from
       the user's passphrase at some point using PBKDF2.

       Borg does not support "passphrase" mode otherwise any more.

.. _key_encryption:

Offline key security
--------------------

Borg cannot secure the key material while it is running, because the keys
are needed in plain to decrypt/encrypt repository objects.

For offline storage of the encryption keys they are encrypted with a
user-chosen passphrase.

A 256 bit key encryption key (KEK) is derived from the passphrase
using PBKDF2-HMAC-SHA256 with a random 256 bit salt which is then used
to Encrypt-*and*-MAC (unlike the Encrypt-*then*-MAC approach used
otherwise) a packed representation of the keys with AES-256-CTR with a
constant initialization vector of 0. A HMAC-SHA256 of the plaintext is
generated using the same KEK and is stored alongside the ciphertext,
which is converted to base64 in its entirety.

This base64 blob (commonly referred to as *keyblob*) is then stored in
the key file or in the repository config (keyfile and repokey modes
respectively).

This scheme, and specifically the use of a constant IV with the CTR
mode, is secure because an identical passphrase will result in a
different derived KEK for every key encryption due to the salt.

The use of Encrypt-and-MAC instead of Encrypt-then-MAC is seen as
uncritical (but not ideal) here, since it is combined with AES-CTR mode,
which is not vulnerable to padding attacks.


.. seealso::

   Refer to the :ref:`key_files` section for details on the format.

   Refer to issue :issue:`747` for suggested improvements of the encryption
   scheme and password-based key derivation.

Implementations used
--------------------

We do not implement cryptographic primitives ourselves, but rely
on widely used libraries providing them:

- AES-CTR and HMAC-SHA-256 from OpenSSL 1.0 / 1.1 are used,
  which is also linked into the static binaries we provide.
  We think this is not an additional risk, since we don't ever
  use OpenSSL's networking, TLS or X.509 code, but only their
  primitives implemented in libcrypto.
- SHA-256 and SHA-512 from Python's hashlib_ standard library module are used.
  Borg requires a Python built with OpenSSL support (due to PBKDF2), therefore
  these functions are delegated to OpenSSL by Python.
- HMAC, PBKDF2 and a constant-time comparison from Python's hmac_ standard
  library module is used. While the HMAC implementation is written in Python,
  the PBKDF2 implementation is provided by OpenSSL. The constant-time comparison
  (``compare_digest``) is written in C and part of Python.
- BLAKE2b is either provided by the system's libb2, an official implementation,
  or a bundled copy of the BLAKE2 reference implementation (written in C).

Implemented cryptographic constructions are:

- Encrypt-then-MAC based on AES-256-CTR and either HMAC-SHA-256
  or keyed BLAKE2b256 as described above under Encryption_.
- Encrypt-and-MAC based on AES-256-CTR and HMAC-SHA-256
  as described above under `Offline key security`_.
- HKDF_-SHA-512

.. _Horton principle: https://en.wikipedia.org/wiki/Horton_Principle
.. _HKDF: https://tools.ietf.org/html/rfc5869
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
have to directly use a SSH client (or SSH at all). For example,
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

There was some discussion about this in `github issue #1040`_ and for Borg some developers
concluded this is no problem at all, some concluded this is hard and extremely slow to exploit
and thus no problem in practice.

No matter what, there is always the option not to use compression if you are worried about this.

.. _github issue #1040: https://github.com/borgbackup/borg/issues/1040

Fingerprinting
==============

Stored chunk sizes
------------------

A borg repository does not hide the size of the chunks it stores (size
information is needed to operate the repository).

The chunks stored in the repo are the (compressed, encrypted and authenticated)
output of the chunker. The sizes of these stored chunks are influenced by the
compression, encryption and authentication.

buzhash chunker
+++++++++++++++

The buzhash chunker chunks according to the input data, the chunker's
parameters and the secret chunker seed and permutation (which all influence the
chunk boundary positions).

Small files below some specific threshold (default: 512 KiB) result in only one
chunk (identical content / size as the original file), bigger files result in
multiple chunks.

fixed chunker
+++++++++++++

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

.. include:: global.rst.inc
.. _internals:

Internals
=========


Key files
---------

When initialized with the ``init -e keyfile`` command, |project_name|
needs an associated file in ``$HOME/.attic/keys`` to read and write
the repository. As with most crypto code in |project_name|, the format
of those files is defined in `attic/key.py`_.  The format is based on
msgpack_, base64 encoding and PBKDF2_ SHA256 encryption, which is
then encoded again in a msgpack_.

The internal data structure is as follows:

version
  currently always an integer, 1

repository_id
  the ``id`` field in the ``config`` ``INI`` file of the repository.

enc_key
  the AES encryption key
  
enc_hmac_key
  the HMAC key (32 bytes)

id_key
  another HMAC key? unclear.

chunk_seed
  unknown

Those fields are encoded using msgpack_. The utf-8-encoded phassphrase
is encrypted with a PBKDF2_ and SHA256_ using 100000 iterations and a
random 32 bytes salt to give us a derived key. The derived key is 32
bytes long.  A HMAC_ SHA256_ checksum of the above fields is generated
with the derived key, then the derived key is also used to encrypt the
above pack of fields. Then the result is stored in a another msgpack_
formatted as follows:

version
  currently always an integer, 1

salt
  random 32 bytes salt used to encrypt the passphrase

iterations
  number of iterations used to encrypt the passphrase

algorithm
  the hashing algorithm used to encrypt the passphrase and do the HMAC
  checksum

hash
  the HMAC checksum of the encrypted passphrase key

data
  the passphrase key, encrypted with AES over a PBKDF2_ SHA256 hash
  described above

The resulting msgpack_ is then encoded using base64 and written to the
key file, wrapped using the textwrap_ module with a header. The header
is a single line with the string ``ATTIC_KEY``, a space and a
hexadecimal representation of the repository id.

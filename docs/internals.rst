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
  the key used to encrypt data with AES (256 bits)
  
enc_hmac_key
  the key used to HMAC the resulting AES-encrypted data (256 bits)

id_key
  the key used to HMAC the above chunks, the resulting hash is
  stored out of band (256 bits)

chunk_seed
  the seed for the buzhash chunking table (signed 32 bit integer)

Those fields are encoded using msgpack_. The utf-8-encoded phassphrase
is encrypted with a PBKDF2_ and SHA256_ using 100000 iterations and a
random 256 bits salt to give us a derived key. The derived key is 256
bits long.  A HMAC_ SHA256_ checksum of the above fields is generated
with the derived key, then the derived key is also used to encrypt the
above pack of fields. Then the result is stored in a another msgpack_
formatted as follows:

version
  currently always an integer, 1

salt
  random 256 bits salt used to encrypt the passphrase

iterations
  number of iterations used to encrypt the passphrase (currently 100000)

algorithm
  the hashing algorithm used to encrypt the passphrase and do the HMAC
  checksum (currently the string ``sha256``)

hash
  the HMAC checksum of the encrypted derived key

data
  the derived key, encrypted with AES over a PBKDF2_ SHA256 hash
  described above

The resulting msgpack_ is then encoded using base64 and written to the
key file, wrapped using the textwrap_ module with a header. The header
is a single line with the string ``ATTIC_KEY``, a space and a
hexadecimal representation of the repository id.

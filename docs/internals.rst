.. include:: global.rst.inc
.. _internals:

Internals
=========

This page documents the internal data structures and storage
mechanisms of |project_name|. It is partly based on `mailing list
discussion about internals`_ and also on static code analysis. It may
not be exactly up to date with the current source code.

Indexes and memory usage
------------------------

Repository index
  40 bytes x N ~ 200MB (If a remote repository is
  used this will be allocated on the remote side)

Chunk lookup index
  44 bytes x N ~ 220MB

File chunk cache
  probably 80-100 bytes x N ~ 400MB

The chunk lookup index (chunk hash -> reference count, size, ciphered
size ; in file cache/chunk) and the repository index (chunk hash ->
segment, offset ; in file ``repo/index.%d``) are stored in a sort of hash
table, directly mapped in memory from the file content, with only one
slot per bucket, but that spreads the collisions to the following
buckets. As a consequence the hash is just a start position for a linear
search, and if the element is not in the table the index is linearly
crossed until an empty bucket is found. When the table is full at 90%
its size is doubled, when it's empty at 25% its size is halfed. So
operations on it have a variable complexity between constant and linear
with low factor, and memory overhead varies between 10% and 300%.

The file chunk cache (file path hash -> age, inode number, size,
mtime_ns, chunks hashes ; in file cache/files) is stored as a python
associative array storing python objects, which generate a lot of
overhead. This takes around 240 bytes per file without the chunk
list, to be compared to at most 64 bytes of real data (depending on data
alignment), and around 80 bytes per chunk hash (vs 32), with a minimum
of ~250 bytes even if only one chunck hash. The inode number is stored
to make sure we distinguish between different files, as a single path
may not be unique accross different archives in different setups.

The ``index.%d`` files are random access but those files can be
recreated if damaged or lost using "attic check --repair".

Repository structure
--------------------

|project_name| is a "filesystem based transactional key value store".

Objects referenced by a key (256bits id/hash) are stored in line in
files (segments) of size approx 5MB in ``repo/data``. They contain :
header size, crc, size, tag, key, data. Tag is either ``PUT``,
``DELETE``, or ``COMMIT``.  Segments are built locally, and then
uploaded. Those files are strictly append-only and modified only once.

A segment file is basically a transaction log where each repository
operation is appended to the file. So if an object is written to the
repository a ``PUT`` tag is written to the file followed by the object
id and data. And if an object is deleted a ``DELETE`` tag is appended
followed by the object id. A ``COMMIT`` tag is written when a
repository transaction is committed.  When a repository is opened any
``PUT`` or ``DELETE`` operations not followed by a ``COMMIT`` tag are
discarded since they are part of a partial/uncommitted transaction.

The manifest is an object with an id of only zeros (32 bytes), that
references all the archives. It contains : version, list of archives,
timestamp, config. Each archive contains: name, id, time. It is the last
object stored, in the last segment, and is replaced each time.

The archive metadata does not contain the file items directly. Only
references to other objects that contain that data. An archive is an
object that contain metadata : version, name, items list, cmdline,
hostname, username, time. Each item represents a file or directory or
symlink is stored as a ``item`` dictionnary that contains: path, list
of chunks, user, group, uid, gid, mode (item type + permissions),
source (for links), rdev (for devices), mtime, xattrs, acl,
bsdfiles. ``ctime`` (change time) is not stored because there is no
API to set it and it is reset every time an inode's metadata is changed.

All items are serialized using msgpack and the resulting byte stream
is fed into the same chunker used for regular file data and turned
into deduplicated chunks. The reference to these chunks is then added
to the archvive metadata. This allows the archive to store many files,
beyond the ``MAX_OBJECT_SIZE`` barrier of 20MB.

A chunk is an object as well, of course, and its id is the hash of its
(unencrypted and uncompressed) content.

Hints are stored in a file (repo/hints) and contain: version, list of
segments, compact.

Chunks
------

|project_name| uses a rolling checksum with Buzhash_ algorithm, with
window size of 4095 bytes, with a minimum of 1024, and triggers when
the last 16 bits of the checksum are null, producing chunks of 64kB on
average. All these parameters are fixed. The buzhash table is altered
by XORing it with a seed randomly generated once for the archive, and
stored encrypted in the keyfile.

Repository config file
----------------------

Each repository has a ``config`` file which which is a ``INI``
formatted file which looks like this:

  [repository]
  version = 1
  segments_per_dir = 10000
  max_segment_size = 5242880
  id = 57d6c1d52ce76a836b532b0e42e677dec6af9fca3673db511279358828a21ed6

This is where the ``repository.id`` is stored. It is a unique
identifier for repositories. It will not change if you move the
repository around so you can make a local transfer then decide to move
the repository in another (even remote) location at a later time.

|project_name| will do a POSIX read lock on that file when operating
on the repository.

Encryption
----------

AES_ is used with CTR mode of operation (so no need of padding). A 64
bits initialization vector is used, a SHA256_ based HMAC_ is computed
on the encrypted chunk with a random 64 bits nonce and both are stored
in the chunk. The header of each chunk is actually : TYPE(1) +
HMAC(32) + NONCE(8). Encryption and HMAC use two different keys.

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

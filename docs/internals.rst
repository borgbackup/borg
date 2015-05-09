.. include:: global.rst.inc
.. _internals:

Internals
=========

This page documents the internal data structures and storage
mechanisms of |project_name|. It is partly based on `mailing list
discussion about internals`_ and also on static code analysis. It may
not be exactly up to date with the current source code.

|project_name| stores its data in a `Repository`. Each repository can
hold multiple `Archives`, which represent individual backups that
contain a full archive of the files specified when the backup was
performed. Deduplication is performed across multiple backups, both on
data and metadata, using `Segments` chunked with the Buzhash_
algorithm. Each repository has the following file structure:

README
  simple text file describing the repository

config
  description of the repository, includes the unique identifier. also
  acts as a lock file

data/
  directory where the actual data (`segments`) is stored

hints.%d
  undocumented

index.%d
  cache of the file indexes. those files can be regenerated with
  ``check --repair``

Config file
-----------

Each repository has a ``config`` file which which is a ``INI``
formatted file which looks like this::

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

Segments and archives
---------------------

|project_name| is a "filesystem based transactional key value
store". It makes extensive use of msgpack_ to store data and, unless
otherwise noted, data is stored in msgpack_ encoded files.

Objects referenced by a key (256bits id/hash) are stored inline in
files (`segments`) of size approx 5MB in ``repo/data``. They contain:

* header size
* crc
* size
* tag
* key
* data

Segments are built locally, and then uploaded. Those files are
strictly append-only and modified only once.

Tag is either ``PUT``, ``DELETE``, or ``COMMIT``. A segment file is
basically a transaction log where each repository operation is
appended to the file. So if an object is written to the repository a
``PUT`` tag is written to the file followed by the object id and
data. And if an object is deleted a ``DELETE`` tag is appended
followed by the object id. A ``COMMIT`` tag is written when a
repository transaction is committed.  When a repository is opened any
``PUT`` or ``DELETE`` operations not followed by a ``COMMIT`` tag are
discarded since they are part of a partial/uncommitted transaction.

The manifest is an object with an id of only zeros (32 bytes), that
references all the archives. It contains:

* version
* list of archives
* timestamp
* config

Each archive contains:

* name
* id
* time

It is the last object stored, in the last segment, and is replaced
each time.

The archive metadata does not contain the file items directly. Only
references to other objects that contain that data. An archive is an
object that contain metadata:

* version
* name
* items list
* cmdline
* hostname
* username
* time

Each item represents a file or directory or
symlink is stored as an ``item`` dictionary that contains:

* path
* list of chunks
* user
* group
* uid
* gid
* mode (item type + permissions)
* source (for links)
* rdev (for devices)
* mtime
* xattrs
* acl
* bsdfiles

``ctime`` (change time) is not stored because there is no API to set
it and it is reset every time an inode's metadata is changed.

All items are serialized using msgpack and the resulting byte stream
is fed into the same chunker used for regular file data and turned
into deduplicated chunks. The reference to these chunks is then added
to the archive metadata. This allows the archive to store many files,
beyond the ``MAX_OBJECT_SIZE`` barrier of 20MB.

A chunk is an object as well, of course. The chunk id is either 
HMAC-SHA256_, when encryption is used, or a SHA256_ hash otherwise.

Hints are stored in a file (``repo/hints``) and contain:

* version
* list of segments
* compact

Chunks
------

|project_name| uses a rolling checksum with Buzhash_ algorithm, with
window size of 4095 bytes (`0xFFF`), with a minimum of 1024, and triggers when
the last 16 bits of the checksum are null, producing chunks of 64kB on
average. All these parameters are fixed. The buzhash table is altered
by XORing it with a seed randomly generated once for the archive, and
stored encrypted in the keyfile.

Indexes
-------

There are two main indexes: the chunk lookup index and the repository
index. There is also the file chunk cache.

The chunk lookup index is stored in ``cache/chunk`` and is indexed on
the ``chunk hash``. It contains:

* reference count
* size
* ciphered size

The repository index is stored in ``repo/index.%d`` and is also
indexed on ``chunk hash`` and contains:

* segment
* offset

The repository index files are random access but those files can be
recreated if damaged or lost using ``check --repair``.

Both indexes are stored as hash tables, directly mapped in memory from
the file content, with only one slot per bucket, but that spreads the
collisions to the following buckets. As a consequence the hash is just
a start position for a linear search, and if the element is not in the
table the index is linearly crossed until an empty bucket is
found. When the table is full at 90% its size is doubled, when it's
empty at 25% its size is halfed. So operations on it have a variable
complexity between constant and linear with low factor, and memory
overhead varies between 10% and 300%.

The file chunk cache is stored in ``cache/files`` and is indexed on
the ``file path hash`` and contains:

* age
* inode number
* size
* mtime_ns
* chunks hashes

The inode number is stored to make sure we distinguish between
different files, as a single path may not be unique across different
archives in different setups.

The file chunk cache is stored as a python associative array storing
python objects, which generate a lot of overhead. This takes around
240 bytes per file without the chunk list, to be compared to at most
64 bytes of real data (depending on data alignment), and around 80
bytes per chunk hash (vs 32), with a minimum of ~250 bytes even if
only one chunk hash.

Indexes memory usage
--------------------

Here is the estimated memory usage of |project_name| when using those
indexes.

Repository index
  40 bytes x N ~ 200MB (If a remote repository is
  used this will be allocated on the remote side)

Chunk lookup index
  44 bytes x N ~ 220MB

File chunk cache
  probably 80-100 bytes x N ~ 400MB

In the above we assume 350GB of data that we divide on an average 64KB
chunk size, so N is around 5.3 million.

Encryption
----------

AES_ is used with CTR mode of operation (so no need for padding). A 64
bits initialization vector is used, a `HMAC-SHA256`_ is computed
on the encrypted chunk with a random 64 bits nonce and both are stored
in the chunk. The header of each chunk is : ``TYPE(1)`` +
``HMAC(32)`` + ``NONCE(8)`` + ``CIPHERTEXT``. Encryption and HMAC use
two different keys.

In AES CTR mode you can think of the IV as the start value for the
counter. The counter itself is incremented by one after each 16 byte
block. The IV/counter is not required to be random but it must NEVER be
reused. So to accomplish this |project_name| initializes the encryption counter
to be higher than any previously used counter value before encrypting
new data.

To reduce payload size only 8 bytes of the 16 bytes nonce is saved in
the payload, the first 8 bytes are always zeroes. This does not affect
security but limits the maximum repository capacity to only 295
exabytes (2**64 * 16 bytes).

Encryption keys are either a passphrase, passed through the
``BORG_PASSPHRASE`` environment or prompted on the commandline, or
stored in automatically generated key files.

Key files
---------

When initialized with the ``init -e keyfile`` command, |project_name|
needs an associated file in ``$HOME/.borg/keys`` to read and write
the repository. The format is based on msgpack_, base64 encoding and
PBKDF2_ SHA256 hashing, which is then encoded again in a msgpack_.

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

Those fields are processed using msgpack_. The utf-8 encoded phassphrase
is encrypted with PBKDF2_ and SHA256_ using 100000 iterations and a
random 256 bits salt to give us a derived key. The derived key is 256
bits long.  A `HMAC-SHA256`_ checksum of the above fields is generated
with the derived key, then the derived key is also used to encrypt the
above pack of fields. Then the result is stored in a another msgpack_
formatted as follows:

version
  currently always an integer, 1

salt
  random 256 bits salt used to process the passphrase

iterations
  number of iterations used to process the passphrase (currently 100000)

algorithm
  the hashing algorithm used to process the passphrase and do the HMAC
  checksum (currently the string ``sha256``)

hash
  the HMAC of the encrypted derived key

data
  the derived key, encrypted with AES over a PBKDF2_ SHA256 key
  described above

The resulting msgpack_ is then encoded using base64 and written to the
key file, wrapped using the standard ``textwrap`` module with a header.
The header is a single line with a MAGIC string, a space and a hexadecimal
representation of the repository id.

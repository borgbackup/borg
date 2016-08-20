.. include:: global.rst.inc
.. highlight:: none
.. _internals:

Internals
=========

This page documents the internal data structures and storage
mechanisms of |project_name|. It is partly based on `mailing list
discussion about internals`_ and also on static code analysis.


Repository and Archives
-----------------------

|project_name| stores its data in a `Repository`. Each repository can
hold multiple `Archives`, which represent individual backups that
contain a full archive of the files specified when the backup was
performed. Deduplication is performed across multiple backups, both on
data and metadata, using `Chunks` created by the chunker using the Buzhash_
algorithm.

Each repository has the following file structure:

README
  simple text file telling that this is a |project_name| repository

config
  repository configuration

data/
  directory where the actual data is stored

hints.%d
  hints for repository compaction

index.%d
  repository index

lock.roster and lock.exclusive/*
  used by the locking system to manage shared and exclusive locks


Lock files
----------

|project_name| uses locks to get (exclusive or shared) access to the cache and
the repository.

The locking system is based on creating a directory `lock.exclusive` (for
exclusive locks). Inside the lock directory, there is a file indicating
hostname, process id and thread id of the lock holder.

There is also a json file `lock.roster` that keeps a directory of all shared
and exclusive lockers.

If the process can create the `lock.exclusive` directory for a resource, it has
the lock for it. If creation fails (because the directory has already been
created by some other process), lock acquisition fails.

The cache lock is usually in `~/.cache/borg/REPOID/lock.*`.
The repository lock is in `repository/lock.*`.

In case you run into troubles with the locks, you can use the ``borg break-lock``
command after you first have made sure that no |project_name| process is
running on any machine that accesses this resource. Be very careful, the cache
or repository might get damaged if multiple processes use it at the same time.


Config file
-----------

Each repository has a ``config`` file which which is a ``INI``-style file
and looks like this::

    [repository]
    version = 1
    segments_per_dir = 10000
    max_segment_size = 5242880
    id = 57d6c1d52ce76a836b532b0e42e677dec6af9fca3673db511279358828a21ed6

This is where the ``repository.id`` is stored. It is a unique
identifier for repositories. It will not change if you move the
repository around so you can make a local transfer then decide to move
the repository to another (even remote) location at a later time.


Keys
----
The key to address the key/value store is usually computed like this:

key = id = id_hash(unencrypted_data)

The id_hash function is:

* sha256 (no encryption keys available)
* hmac-sha256 (encryption keys available)


Segments and archives
---------------------

A |project_name| repository is a filesystem based transactional key/value
store. It makes extensive use of msgpack_ to store data and, unless
otherwise noted, data is stored in msgpack_ encoded files.

Objects referenced by a key are stored inline in files (`segments`) of approx.
5MB size in numbered subdirectories of ``repo/data``.

They contain:

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
data. If an object is deleted a ``DELETE`` tag is appended
followed by the object id. A ``COMMIT`` tag is written when a
repository transaction is committed.  When a repository is opened any
``PUT`` or ``DELETE`` operations not followed by a ``COMMIT`` tag are
discarded since they are part of a partial/uncommitted transaction.


The manifest
------------

The manifest is an object with an all-zero key that references all the
archives.
It contains:

* version
* list of archive infos
* timestamp
* config

Each archive info contains:

* name
* id
* time

It is the last object stored, in the last segment, and is replaced
each time.

The Archive
-----------

The archive metadata does not contain the file items directly. Only
references to other objects that contain that data. An archive is an
object that contains:

* version
* name
* list of chunks containing item metadata (size: count * ~40B)
* cmdline
* hostname
* username
* time

.. _archive_limitation:

Note about archive limitations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The archive is currently stored as a single object in the repository
and thus limited in size to MAX_OBJECT_SIZE (20MiB).

As one chunk list entry is ~40B, that means we can reference ~500.000 item
metadata stream chunks per archive.

Each item metadata stream chunk is ~128kiB (see hardcoded ITEMS_CHUNKER_PARAMS).

So that means the whole item metadata stream is limited to ~64GiB chunks.
If compression is used, the amount of storable metadata is bigger - by the
compression factor.

If the medium size of an item entry is 100B (small size file, no ACLs/xattrs),
that means a limit of ~640 million files/directories per archive.

If the medium size of an item entry is 2kB (~100MB size files or more
ACLs/xattrs), the limit will be ~32 million files/directories per archive.

If one tries to create an archive object bigger than MAX_OBJECT_SIZE, a fatal
IntegrityError will be raised.

A workaround is to create multiple archives with less items each, see
also :issue:`1452`.

The Item
--------

Each item represents a file, directory or other fs item and is stored as an
``item`` dictionary that contains:

* path
* list of data chunks (size: count * ~40B)
* user
* group
* uid
* gid
* mode (item type + permissions)
* source (for links)
* rdev (for devices)
* mtime, atime, ctime in nanoseconds
* xattrs
* acl
* bsdfiles

All items are serialized using msgpack and the resulting byte stream
is fed into the same chunker algorithm as used for regular file data
and turned into deduplicated chunks. The reference to these chunks is then added
to the archive metadata. To achieve a finer granularity on this metadata
stream, we use different chunker params for this chunker, which result in
smaller chunks.

A chunk is stored as an object as well, of course.

.. _chunker_details:

Chunks
------

The |project_name| chunker uses a rolling hash computed by the Buzhash_ algorithm.
It triggers (chunks) when the last HASH_MASK_BITS bits of the hash are zero,
producing chunks of 2^HASH_MASK_BITS Bytes on average.

``borg create --chunker-params CHUNK_MIN_EXP,CHUNK_MAX_EXP,HASH_MASK_BITS,HASH_WINDOW_SIZE``
can be used to tune the chunker parameters, the default is:

- CHUNK_MIN_EXP = 19 (minimum chunk size = 2^19 B = 512 kiB)
- CHUNK_MAX_EXP = 23 (maximum chunk size = 2^23 B = 8 MiB)
- HASH_MASK_BITS = 21 (statistical medium chunk size ~= 2^21 B = 2 MiB)
- HASH_WINDOW_SIZE = 4095 [B] (`0xFFF`)

The buzhash table is altered by XORing it with a seed randomly generated once
for the archive, and stored encrypted in the keyfile. This is to prevent chunk
size based fingerprinting attacks on your encrypted repo contents (to guess
what files you have based on a specific set of chunk sizes).

For some more general usage hints see also ``--chunker-params``.


Indexes / Caches
----------------

The **files cache** is stored in ``cache/files`` and is indexed on the
``file path hash``. At backup time, it is used to quickly determine whether we
need to chunk a given file (or whether it is unchanged and we already have all
its pieces).
It contains:

* age
* file inode number
* file size
* file mtime_ns
* file content chunk hashes

The inode number is stored to make sure we distinguish between
different files, as a single path may not be unique across different
archives in different setups.

The files cache is stored as a python associative array storing
python objects, which generates a lot of overhead.

The **chunks cache** is stored in ``cache/chunks`` and is indexed on the
``chunk id_hash``. It is used to determine whether we already have a specific
chunk, to count references to it and also for statistics.
It contains:

* reference count
* size
* encrypted/compressed size

The **repository index** is stored in ``repo/index.%d`` and is indexed on the
``chunk id_hash``. It is used to determine a chunk's location in the repository.
It contains:

* segment (that contains the chunk)
* offset (where the chunk is located in the segment)

The repository index file is random access.

Hints are stored in a file (``repo/hints.%d``).
It contains:

* version
* list of segments
* compact

hints and index can be recreated if damaged or lost using ``check --repair``.

The chunks cache and the repository index are stored as hash tables, with
only one slot per bucket, but that spreads the collisions to the following
buckets. As a consequence the hash is just a start position for a linear
search, and if the element is not in the table the index is linearly crossed
until an empty bucket is found.

When the hash table is filled to 75%, its size is grown. When it's
emptied to 25%, its size is shrinked. So operations on it have a variable
complexity between constant and linear with low factor, and memory overhead
varies between 33% and 300%.

.. _cache-memory-usage:

Indexes / Caches memory usage
-----------------------------

Here is the estimated memory usage of |project_name|:

  chunk_count ~= total_file_size / 2 ^ HASH_MASK_BITS

  repo_index_usage = chunk_count * 40

  chunks_cache_usage = chunk_count * 44

  files_cache_usage = total_file_count * 240 + chunk_count * 80

  mem_usage ~= repo_index_usage + chunks_cache_usage + files_cache_usage
             = chunk_count * 164 + total_file_count * 240

All units are Bytes.

It is assuming every chunk is referenced exactly once (if you have a lot of
duplicate chunks, you will have less chunks than estimated above).

It is also assuming that typical chunk size is 2^HASH_MASK_BITS (if you have
a lot of files smaller than this statistical medium chunk size, you will have
more chunks than estimated above, because 1 file is at least 1 chunk).

If a remote repository is used the repo index will be allocated on the remote side.

E.g. backing up a total count of 1 Mi (IEC binary prefix i.e. 2^20) files with a total size of 1TiB.

a) with ``create --chunker-params 10,23,16,4095`` (custom, like borg < 1.0 or attic):

  mem_usage  =  2.8GiB

b) with ``create --chunker-params 19,23,21,4095`` (default):

  mem_usage  =  0.31GiB

.. note:: There is also the ``--no-files-cache`` option to switch off the files cache.
   You'll save some memory, but it will need to read / chunk all the files as
   it can not skip unmodified files then.

Encryption
----------

AES_-256 is used in CTR mode (so no need for padding). A 64bit initialization
vector is used, a `HMAC-SHA256`_ is computed on the encrypted chunk with a
random 64bit nonce and both are stored in the chunk.
The header of each chunk is: ``TYPE(1)`` + ``HMAC(32)`` + ``NONCE(8)`` + ``CIPHERTEXT``.
Encryption and HMAC use two different keys.

In AES CTR mode you can think of the IV as the start value for the counter.
The counter itself is incremented by one after each 16 byte block.
The IV/counter is not required to be random but it must NEVER be reused.
So to accomplish this |project_name| initializes the encryption counter to be
higher than any previously used counter value before encrypting new data.

To reduce payload size, only 8 bytes of the 16 bytes nonce is saved in the
payload, the first 8 bytes are always zeros. This does not affect security but
limits the maximum repository capacity to only 295 exabytes (2**64 * 16 bytes).

Encryption keys (and other secrets) are kept either in a key file on the client
('keyfile' mode) or in the repository config on the server ('repokey' mode).
In both cases, the secrets are generated from random and then encrypted by a
key derived from your passphrase (this happens on the client before the key
is stored into the keyfile or as repokey).

The passphrase is passed through the ``BORG_PASSPHRASE`` environment variable
or prompted for interactive usage.


Key files
---------

When initialized with the ``init -e keyfile`` command, |project_name|
needs an associated file in ``$HOME/.config/borg/keys`` to read and write
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
  the key used to HMAC the encrypted data (256 bits)

id_key
  the key used to HMAC the plaintext chunk data to compute the chunk's id

chunk_seed
  the seed for the buzhash chunking table (signed 32 bit integer)

Those fields are processed using msgpack_. The utf-8 encoded passphrase
is processed with PBKDF2_ (SHA256_, 100000 iterations, random 256 bit salt)
to give us a derived key. The derived key is 256 bits long.
A `HMAC-SHA256`_ checksum of the above fields is generated with the derived
key, then the derived key is also used to encrypt the above pack of fields.
Then the result is stored in a another msgpack_ formatted as follows:

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


Compression
-----------

|project_name| supports the following compression methods:

- none (no compression, pass through data 1:1)
- lz4 (low compression, but super fast)
- zlib (level 0-9, level 0 is no compression [but still adding zlib overhead],
  level 1 is low, level 9 is high compression)
- lzma (level 0-9, level 0 is low, level 9 is high compression).

Speed:  none > lz4 > zlib > lzma
Compression: lzma > zlib > lz4 > none

Be careful, higher zlib and especially lzma compression levels might take a
lot of resources (CPU and memory).

The overall speed of course also depends on the speed of your target storage.
If that is slow, using a higher compression level might yield better overall
performance. You need to experiment a bit. Maybe just watch your CPU load, if
that is relatively low, increase compression until 1 core is 70-100% loaded.

Even if your target storage is rather fast, you might see interesting effects:
while doing no compression at all (none) is a operation that takes no time, it
likely will need to store more data to the storage compared to using lz4.
The time needed to transfer and store the additional data might be much more
than if you had used lz4 (which is super fast, but still might compress your
data about 2:1). This is assuming your data is compressible (if you backup
already compressed data, trying to compress them at backup time is usually
pointless).

Compression is applied after deduplication, thus using different compression
methods in one repo does not influence deduplication.

See ``borg create --help`` about how to specify the compression level and its default.

.. include:: ../global.rst.inc
.. highlight:: none

.. _data-structures:

Data structures and file formats
================================

This page documents the internal data structures and storage
mechanisms of Borg. It is partly based on mailing list
discussions and also on static code analysis.

.. todo:: Clarify terms, perhaps create a glossary.
          ID (client?) vs. key (repository?),
          chunks (blob of data in repo?) vs. object (blob of data in repo, referred to from another object?),

.. _repository:

Repository
----------

Borg stores its data in a `Repository`, which is a key-value store and has
the following structure:

config/
  readme
    simple text object telling that this is a Borg repository
  id
    the unique repository ID encoded as hexadecimal number text
  version
    the repository version encoded as decimal number text
  manifest
    some data about the repository, binary
  space-reserve.N
    purely random binary data to reserve space, e.g. for disk-full emergencies

cache/
  checked-packs
    repository check results (pack id -> timestamp, result), as a hashtable with an
    appended integrity hash. Records are kept across checks: ``check --max-age``
    skips packs whose intact record is younger than the given age, which also lets
    partial checks (``--max-duration``) continue where a previous one stopped.
    Records of corrupt packs are kept for repair and always re-verified. Records of
    packs no longer listed in packs/ are pruned when a check finishes scanning
    packs/.

There is a list of pointers to archive objects in this directory:

archives/
  0000... .. ffff...

The actual data is stored into a nested directory structure, using the full
object ID as name. Each (encrypted and compressed) object is stored separately.

data/
  00/ .. ff/
    00/ .. ff/
      0000... .. ffff...

keys/
    When using repokey mode, the encrypted, passphrase protected borg keys are
    stored here as a base64 encoded text. The sha256 content hash of the
    stored borg key is used for the name.

    A repository may contain *multiple* such borg keys (one per passphrase) to
    support the :ref:`multiple borg keys <borgcrypto_multiple_keys>` feature.
    keyfile and repokey borg keys use the same format and naming (only the
    storage location differs).

locks/
  used by the locking system to manage shared and exclusive locks.


Keys
~~~~

Repository object IDs (which are used as key into the key-value store) are
byte strings of fixed length (256-bit, 32 bytes), computed like this::

  key = id = id_hash(plaintext_data)  # plain = not encrypted, not compressed, not obfuscated

The id_hash function is selected via ``borg repo-create --id-hash`` (independently
of ``--encryption``). For encrypted repositories it is a keyed MAC over the
plaintext (keyed by ``id_key``): ``sha256`` selects HMAC-SHA256, ``blake3``
selects a keyed BLAKE3. The unencrypted ``none`` mode uses a plain ``sha256``.

As the id / key is used for deduplication, id_hash must be a cryptographically
strong hash or MAC.

Repository objects
~~~~~~~~~~~~~~~~~~

Each repository object is stored separately, under its ID into data/xx/yy/xxyy...

A repo object has a structure like this:

* 32-bit meta size
* 32-bit data size
* meta
* data

The overall size of repository objects varies from very small (a small source
file will be stored as a single repository object) to medium (big source files will
be cut into medium-sized chunks of some MB).

Metadata and data are separately encrypted and authenticated (depending on
the user's choices).

See :ref:`data-encryption` for a graphic outlining the anatomy of the
encryption.

Repo object metadata
~~~~~~~~~~~~~~~~~~~~

Metadata is a MessagePack-encoded (and encrypted/authenticated) dict with:

- ctype (compression type 0..255)
- clevel (compression level 0..255)
- csize (overall compressed (and maybe obfuscated) data size)
- psize (only when obfuscated: payload size without the obfuscation trailer)
- size (uncompressed size of the data)

Having this separately encrypted metadata makes it more efficient to query
the metadata without having to read, transfer and decrypt the (usually much
bigger) data part.

The compression `ctype` and `clevel` is explained in :ref:`data-compression`.


Compaction
~~~~~~~~~~

``borg compact`` is used to free repository space. It will:

- list all object IDs present in the repository
- read all archives and determine which object IDs are in use
- remove all unused objects from the repository
- inform / warn about anything remarkable it found:

  - warn about IDs used, but not present (data loss!)
  - inform about IDs that reappeared that were previously lost
- compute statistics about:

  - compression and deduplication factors
  - repository space usage and space freed


The object graph
----------------

On top of the simple key-value store offered by the Repository_,
Borg builds a much more sophisticated data structure that is essentially
a completely encrypted object graph. Objects, such as archives_, are referenced
by their chunk ID, which is cryptographically derived from their contents.
More on how this helps security in :ref:`security_structural_auth`.

.. figure:: object-graph.png
    :figwidth: 100%
    :width: 100%

.. _manifest:

The manifest
~~~~~~~~~~~~

Compared to borg 1.x:

- the manifest moved from object ID 0 to config/manifest
- the archives list has been moved from the manifest to archives/*

The manifest is rewritten each time an archive is created, deleted,
or modified. It looks like this:

.. code-block:: python

    {
        'version': 1,
        'timestamp': '2017-05-05T12:42:23.042864',
        'item_keys': ['acl_access', 'acl_default', ...],
        'config': {},
        'archives': {
            '2017-05-05-system-backup': {
                'id': b'<32 byte binary object ID>',
                'time': '2017-05-05T12:42:22.942864',
            },
        },
    }

The *version* field can be either 1 or 2. The versions differ in the
way feature flags are handled, described below.

The *timestamp* field is used to avoid logical replay attacks where
the server just resets the repository to a previous state.

*item_keys* is a list containing all Item_ keys that may be encountered in
the repository. It is used by *borg check*, which verifies that all keys
in all items are a subset of these keys. Thus, an older version of *borg check*
supporting this mechanism can correctly detect keys introduced in later versions.

*config* is a general-purpose location for additional metadata. All versions
of Borg preserve its contents.

Feature flags
+++++++++++++

Feature flags are used to add features to data structures without causing
corruption if older versions are used to access or modify them. The main issues
to consider for a feature flag oriented design are flag granularity,
flag storage, and cache_ invalidation.

Feature flags are divided in approximately three categories, detailed below.
Due to the nature of ID-based deduplication, write (i.e. creating archives) and
read access are not symmetric; it is possible to create archives referencing
chunks that are not readable with the current feature set. The third
category are operations that require accurate reference counts, for example
archive deletion and check.

As the manifest is always updated and always read, it is the ideal place to store
feature flags, comparable to the super-block of a file system. The only problem
is to recover from a lost manifest, i.e. how is it possible to detect which feature
flags are enabled, if there is no manifest to tell. This issue is left open at this time,
but is not expected to be a major hurdle; it doesn't have to be handled efficiently, it just
needs to be handled.

Lastly, cache_ invalidation is handled by noting which feature
flags were and which were not understood while manipulating a cache.
This allows borg to detect whether the cache needs to be invalidated,
i.e. rebuilt from scratch. See `Cache feature flags`_ below.

The *config* key stores the feature flags enabled on a repository:

.. code-block:: python

    config = {
        'feature_flags': {
            'read': {
                'mandatory': ['some_feature'],
            },
            'check': {
                'mandatory': ['other_feature'],
            }
            'write': ...,
            'delete': ...
        },
    }

The top-level distinction for feature flags is the operation the client intends
to perform,

| the *read* operation includes extraction and listing of archives,
| the *write* operation includes creating new archives,
| the *delete* (archives) operation,
| the *check* operation requires full understanding of everything in the repository.
|

These are weakly set-ordered; *check* will include everything required for *delete*,
*delete* will likely include *write* and *read*. However, *read* may require more
features than *write* (due to ID-based deduplication, *write* does not necessarily
require reading/understanding repository contents).

Each operation can contain several sets of feature flags. Only one set,
the *mandatory* set is currently defined.

Upon reading the manifest, the Borg client has already determined which operation
should be performed. If feature flags are found in the manifest, the set
of feature flags supported by the client is compared to the mandatory set
found in the manifest. If any unsupported flags are found (i.e. the mandatory set is
not a subset of the features supported by the Borg client used), the operation
is aborted with a *MandatoryFeatureUnsupported* error:

    Unsupported repository feature(s) {'some_feature'}. A newer version of borg is required to access this repository.

Older Borg releases do not have this concept and do not perform feature flags checks.
These can be locked out with manifest version 2. Thus, the only difference between
manifest versions 1 and 2 is that the latter is only accepted by Borg releases
implementing feature flags.

Therefore, as soon as any mandatory feature flag is enabled in a repository,
the manifest version must be switched to version 2 in order to lock out all
Borg releases unaware of feature flags.

.. _Cache feature flags:
.. rubric:: Cache feature flags

`The cache <cache>`_ does not have its separate set of feature flags. Instead, Borg stores
which flags were used to create or modify a cache.

All mandatory manifest features from all operations are gathered in one set.
Then, two sets of features are computed;

- those features that are supported by the client and mandated by the manifest
  are added to the *mandatory_features* set,
- the *ignored_features* set comprised of those features mandated by the manifest,
  but not supported by the client.

Because the client previously checked compliance with the mandatory set of features
required for the particular operation it is executing, the *mandatory_features* set
will contain all necessary features required for using the cache safely.

Conversely, the *ignored_features* set contains only those features which were not
relevant to operating the cache. Otherwise, the client would not pass the feature
set test against the manifest.

When opening a cache and the *mandatory_features* set is not a subset of the features
supported by the client, the cache is wiped out and rebuilt,
since a client not supporting a mandatory feature that the cache was built with
would be unable to update it correctly.
The assumption behind this behaviour is that any of the unsupported features could have
been reflected in the cache and there is no way for the client to discern whether
that is the case.
Meanwhile, it may not be practical for every feature to have clients using it track
whether the feature had an impact on the cache.
Therefore, the cache is wiped.

When opening a cache and the intersection of *ignored_features* and the features
supported by the client contains any elements, i.e. the client possesses features
that the previous client did not have and those new features are enabled in the repository,
the cache is wiped out and rebuilt.

While the former condition likely requires no tweaks, the latter condition is formulated
in an especially conservative way to play it safe. It seems likely that specific features
might be exempted from the latter condition.

.. rubric:: Defined feature flags

Currently no feature flags are defined.

From currently planned features, some examples follow,
these may/may not be implemented and purely serve as examples.

- A mandatory *read* feature could be using a different encryption scheme (e.g. session keys).
  This may not be mandatory for the *write* operation - reading data is not strictly required for
  creating an archive.
- Any additions to the way chunks are referenced (e.g. to support larger archives) would
  become a mandatory *delete* and *check* feature; *delete* implies knowing correct
  reference counts, so all object references need to be understood. *check* must
  discover the entire object graph as well, otherwise the "orphan chunks check"
  could delete data still in use.

.. _archive:

Archives
~~~~~~~~

Each archive is an object referenced by an entry below archives/.
The archive object itself does not store any of the data contained in the
archive it describes.

Instead, it contains a list of chunks which form a msgpacked stream of items_.
The archive object itself further contains some metadata:

* *version*
* *name*, which might differ from the name set in the archives/* object.
  When :ref:`borg_check` rebuilds the manifest (e.g. if it was corrupted) and finds
  more than one archive object with the same name, it adds a counter to the name
  in archives/*, but leaves the *name* field of the archives as they were.
* *item_ptrs*, a list of "pointer chunk" IDs.
  Each "pointer chunk" contains a list of chunk IDs of item metadata.
* *command_line*, the command line which was used to create the archive
* *hostname*
* *username*
* *time* and *time_end* are the start and end timestamps, respectively
* *comment*, a user-specified archive comment
* *chunker_params* are the :ref:`chunker-params <chunker-params>` used for creating the archive.
  This is used by :ref:`borg_recreate` to determine whether a given archive needs rechunking.
* Some other pieces of information related to recreate.

.. _item:

Items
~~~~~

Each item represents a file, directory or other file system item and is stored as a
dictionary created by the ``Item`` class that contains:

* path
* list of data chunks (size: count * ~40B)
* user
* group
* uid
* gid
* mode (item type + permissions)
* source (for symlinks)
* hlid (for hardlinks)
* rdev (for device files)
* mtime, atime, ctime, birthtime in nanoseconds
* xattrs
* acl (various OS-dependent fields)
* flags

All items are serialized using msgpack and the resulting byte stream
is fed into the same chunker algorithm as used for regular file data
and turned into deduplicated chunks. The reference to these chunks is then added
to the archive metadata. To achieve a finer granularity on this metadata
stream, we use different chunker params for this chunker, which result in
smaller chunks.

A chunk is stored as an object as well, of course.

.. _chunks:
.. _chunker_details:

Chunks
~~~~~~

Borg has these chunkers:

- "fixed": a simple, low cpu overhead, fixed blocksize chunker, optionally
  supporting a header block of different size.
- "buzhash": variable, content-defined blocksize, uses a rolling hash
  computed by the Buzhash_ algorithm.
- "buzhash64": similar to "buzhash", but improved 64bit implementation
- "fastcdc": variable, content-defined blocksize, uses the window-less, keyed
  Gear rolling hash (FastCDC_); faster than buzhash, same deduplication.

For some more general usage hints see also ``--chunker-params``.

"fixed" chunker
+++++++++++++++

The fixed chunker triggers (chunks) at even-spaced offsets, e.g. every 4MiB,
producing chunks of same block size (the last chunk is not required to be
full-size).

Optionally, it supports processing a differently sized "header" first, before
it starts to cut chunks of the desired block size.
The default is not to have a differently sized header.

``borg create --chunker-params fixed,BLOCK_SIZE[,HEADER_SIZE]``

- BLOCK_SIZE: no default value, multiple of the system page size (usually 4096
  bytes) recommended. E.g.: 4194304 would cut 4MiB sized chunks.
- HEADER_SIZE: optional, defaults to 0 (no header).

The fixed chunker also supports processing sparse files (reading only the ranges
with data and seeking over the empty hole ranges).

``borg create --sparse --chunker-params fixed,BLOCK_SIZE[,HEADER_SIZE]``

"buzhash" chunker
+++++++++++++++++

The buzhash chunker triggers (chunks) when the last HASH_MASK_BITS bits of the
hash are zero, producing chunks with a target size of 2^HASH_MASK_BITS bytes.

Buzhash is **only** used for cutting the chunks at places defined by the
content, the buzhash value is **not** used as the deduplication criteria (we
use a cryptographically strong hash/MAC over the chunk contents for this, the
id_hash).

The idea of content-defined chunking is assigning every byte where a
cut *could* be placed a hash. The hash is based on some number of bytes
(the window size) before the byte in question. Chunks are cut
where the hash satisfies some condition
(usually "n numbers of trailing/leading zeroes"). This causes chunks to be cut
in the same location relative to the file's contents, even if bytes are inserted
or removed before/after a cut, as long as the bytes within the window stay the same.
This results in a high chance that a single cluster of changes to a file will only
result in 1-2 new chunks, aiding deduplication.

Using normal hash functions this would be extremely slow,
requiring hashing approximately ``window size * file size`` bytes.
A rolling hash is used instead, which allows to add a new input byte and
compute a new hash as well as *remove* a previously added input byte
from the computed hash. This makes the cost of computing a hash for each
input byte largely independent of the window size.

Borg defines minimum and maximum chunk sizes (CHUNK_MIN_EXP and CHUNK_MAX_EXP, respectively)
which narrows down where cuts may be made, greatly reducing the amount of data
that is actually hashed for content-defined chunking.

``borg create --chunker-params buzhash,CHUNK_MIN_EXP,CHUNK_MAX_EXP,HASH_MASK_BITS,HASH_WINDOW_SIZE``
can be used to tune the chunker parameters, the default is:

- CHUNK_MIN_EXP = 19 (minimum chunk size = 2^19 B = 512 kiB)
- CHUNK_MAX_EXP = 23 (maximum chunk size = 2^23 B = 8 MiB)
- HASH_MASK_BITS = 21 (target chunk size ~= 2^21 B = 2 MiB)
- HASH_WINDOW_SIZE = 4095 [B] (`0xFFF`) (must be an odd number)

The buzhash table is altered by XORing it with a seed randomly generated once
for the repository, and stored encrypted in the keyfile. This is to prevent
chunk size based fingerprinting attacks on your encrypted repo contents (to
guess what files you have based on a specific set of chunk sizes).

"buzhash64" chunker
+++++++++++++++++++

Similar to "buzhash", but using 64bit wide hash values.

The buzhash table is cryptographically derived from secret key material.

These changes should improve resistance against attacks and also solve
some of the issues of the original (32bit / XORed table) implementation.

"fastcdc" chunker
+++++++++++++++++

FastCDC_ content-defined chunker using the Gear rolling hash. Unlike buzhash it
is window-less (each byte's influence simply decays out of the hash), so its
update is cheaper and it chunks noticeably faster, while producing the same
deduplication and (with normalized chunking) the same chunk-size distribution.

Like "buzhash64", the Gear table is cryptographically derived from secret key
material, so chunk cut points are unpredictable without the key.

``borg create --chunker-params fastcdc,CHUNK_MIN_EXP,CHUNK_MAX_EXP,HASH_MASK_BITS,NC_LEVEL``

There is no window size (Gear is window-less). NC_LEVEL is the normalized
chunking level (0 disables it); 2 is a good default. E.g.: ``fastcdc,19,23,21,2``.

.. _cache:

The files cache
---------------

The **files cache** is stored in ``cache/files.<SUFFIX>`` and is used at backup
time to quickly determine whether a given file is unchanged and we have all its
chunks.

In memory, the files cache is a key -> value mapping (a Python *dict*) and contains:

* key: id_hash of the encoded path (same path as seen in archive)
* value:

  - age (0 [newest], ..., BORG_FILES_CACHE_TTL - 1)
  - file inode number
  - file size
  - file ctime_ns
  - file mtime_ns
  - list of chunk (id, size) tuples representing the file's contents

To determine whether a file has not changed, cached values are looked up via
the key in the mapping and compared to the current file attribute values.

If the file's size, timestamp and inode number is still the same, it is
considered not to have changed. In that case, we check that all file content
chunks are (still) present in the repository (we check that via the chunks
cache).

If everything is matching and all chunks are present, the file is not read /
chunked / hashed again (but still a file metadata item is written to the
archive, made from fresh file metadata read from the filesystem). This is
what makes borg so fast when processing unchanged files.

If there is a mismatch or a chunk is missing, the file is read / chunked /
hashed. Chunks already present in repo won't be transferred to repo again.

The inode number is stored and compared to make sure we distinguish between
different files, as a single path may not be unique across different
archives in different setups.

Not all filesystems have stable inode numbers. If that is the case, borg can
be told to ignore the inode number in the check via --files-cache.

The age value is used for cache management. If a file is "seen" in a backup
run, its age is reset to 0, otherwise its age is incremented by one.
If a file was not seen in BORG_FILES_CACHE_TTL backups, its cache entry is
removed.

The files cache is a python dictionary. To keep the memory overhead of python
objects low, the value is not kept as a python tuple, but in a "compressed" form:

- the chunks list is reduced from (256bit chunk id, 32bit size) tuples to bare
  32bit indexes into the chunks index (see ``ChunkIndex.k_to_idx``). The chunk
  id and size are looked up from the chunks index again when the entry is used.
  This only works while that chunks index is in memory.
- the resulting entry is then msgpacked, so one dict value is a single ``bytes``
  object instead of a nested structure of python objects.

Borg can also work without using the files cache (saves memory if you have a
lot of files or not much RAM free), then all files are assumed to have changed.
This is usually much slower than with files cache.

The on-disk format of the files cache is a stream of msgpacked tuples (key, value).
There, the chunks list is stored in its uncompressed form (chunk id and size), as
the chunks index indexes are only valid for one specific in-memory chunks index.
Loading the files cache involves reading the file, one msgpack object at a time,
unpacking it, and compressing the entry as described above.

.. _index:

The chunks index
----------------

The **chunks index** is persisted in the repository as index fragments and loaded in memory.
It is used to determine whether we already have a specific chunk.

The chunks index is a key -> value mapping and contains:

* key (32 bytes):

  - chunk id_hash
* value (48 bytes, ``ChunkIndexEntry`` in ``borg.hashindex``):

  - flags (32bit): ``F_USED`` (chunk is used / referenced), ``F_COMPRESS`` (chunk
    shall get re-compressed), ``F_PENDING`` (the chunk is still buffered in the pack
    writer, so its pack location is not resolved yet). The upper 8 bits are reserved
    for system flags (currently ``F_NEW``) and are not visible to users of the index.
  - size (32bit): plaintext chunk size, 0 if not known (see below)
  - pack_id (32 bytes): id of the pack file the chunk's blob is stored in
  - obj_offset (32bit): byte offset of the blob inside that pack file
  - obj_size (32bit): blob length (header + encrypted_meta + encrypted_data)

The last 3 values are the chunk's location, see :ref:`pack-index-entry`: reading a
chunk is one ranged read of ``[obj_offset, obj_offset + obj_size)`` from
``packs/<hex(pack_id)>``.

So a chunks index entry is 32 + 48 == 80 bytes, and that is also exactly what it
needs on disk (the serialized format is just key/value pairs, no padding, plus a
small header). In memory, there is some additional overhead, see below.

Not all of that is persisted, though: when an index fragment is written, flags and
size are zeroed (only the chunk id and the pack location are of interest there).
Thus, a chunks index that was just built from the repository has size == 0 for all
its entries, no matter whether it came from the index fragments or from the slow
rebuild (which reads the pack headers, where only the stored blob size is known,
not the plaintext size).

The plaintext size of an entry is only filled in while borg is running, for the
chunks it actually processes: by ``borg create`` when it adds or re-uses a chunk,
or when the files cache entries of a previous archive are loaded (their chunks
lists have the plaintext sizes). So code using the chunks index must be prepared
to see size == 0 and must not assume it is the real chunk size.

The chunks index is a HashIndex_.

.. _cache-memory-usage:

Indexes / Caches memory usage
-----------------------------

Here is the estimated memory usage of Borg - it's complicated::

  chunk_size ~= 2 ^ HASH_MASK_BITS  (for buzhash chunker, BLOCK_SIZE for fixed chunker)
  chunk_count ~= total_file_size / chunk_size

  chunks_index_usage = chunk_count * 100

  files_cache_usage = total_file_count * 230 + chunk_count * 6

  mem_usage ~= chunks_index_usage + files_cache_usage
             = chunk_count * 106 + total_file_count * 230

All units are Bytes.

The 100 Bytes per chunks index entry are the 80 Bytes of the entry itself plus
the overhead of the hash table it lives in (see HashIndex_): the keys/values
arrays are over-allocated by up to 30%, and the bucket table adds another 4 Bytes
per bucket at a load factor of 0.25 .. 0.5. So, depending on where between two
resizes the index currently is, the real value is somewhere between 88 and 120
Bytes per entry - 100 is a good average.

The files cache numbers are for CPython on a 64bit platform: the ~230 Bytes per file
cover the dict slot, the 32 Bytes path hash (as a python ``bytes`` object) and the
fixed part of the msgpacked value; the ~6 Bytes per chunk are one msgpacked 32bit
index into the chunks index.

Both data structures grow by re-allocating and copying, so there are short-time
peaks in memory usage while a resize happens (worst case about 2x the values
computed above for the structure being resized). Usually this does not happen for
all data structures at the same time, though.

It is assuming every chunk is referenced exactly once (if you have a lot of
duplicate chunks, you will have fewer chunks than estimated above).

It is also assuming that typical chunk size is 2^HASH_MASK_BITS (if you have
a lot of files smaller than this statistical medium chunk size, you will have
more chunks than estimated above, because 1 file is at least 1 chunk).

The chunks index and files cache are both implemented as hash tables (the chunks
index as a HashIndex_, the files cache as a python dict). A hash table must have a
significant amount of unused entries to be fast - the so-called load factor gives
the used/unused elements ratio.

E.g. backing up a total count of 1 Mi (IEC binary prefix i.e. 2^20) files with a total size of 1TiB.

a) with ``create --chunker-params buzhash,10,23,16,4095`` (custom):

  chunk_count = 16 Mi, chunks_index_usage = 1.56GiB, files_cache_usage = 0.32GiB

  mem_usage  =  1.9GiB

b) with ``create --chunker-params buzhash,19,23,21,4095`` (default):

  chunk_count = 512 Ki, chunks_index_usage = 0.05GiB, files_cache_usage = 0.23GiB

  mem_usage  =  0.28GiB

.. note:: There is also the ``--files-cache=disabled`` option to disable the files cache.
   You'll save some memory, but it will need to read / chunk all the files as
   it can not skip unmodified files then.

.. _internals_hashindex:

HashIndex
---------

The chunks index is implemented on top of ``borghash.HashTableNT``, which comes from
the separate `borghash <https://github.com/borgbackup/borghash>`_ package (Cython).
``borg.hashindex.ChunkIndex`` only adds the borg specific parts on top of it: the
``ChunkIndexEntry`` namedtuple / struct format and the handling of the system flags.

``HashTableNT`` packs/unpacks the namedtuple value to/from ``bytes`` using a
``struct.Struct`` and delegates the actual storage to ``borghash.HashTable``, which
is a fixed key size / fixed value size ``bytes -> bytes`` mapping.

Internally, ``HashTable`` is not one, but three arrays:

- the *bucket table*, an array of ``uint32_t`` indexes into the keys/values arrays.
  ``0xffffffff`` marks an empty bucket, ``0xfffffffe`` marks a deleted bucket
  (tombstone); everything ``>= 0xffffff00`` is reserved, so the usable index range
  (and thus the maximum number of entries) is a bit below 4Gi.
- the *keys* array, holding ``key_size`` (32 for the chunks index) Bytes per entry.
- the *values* array, holding ``value_size`` (48 for the chunks index) Bytes per entry.

Keys and values are appended to their arrays in insertion order, so the index of a
key in the keys array is stable while the hash table is in memory. The files cache
uses that to "compress" chunk ids to 32bit numbers, see ``ChunkIndex.k_to_idx``.

The bucket table has only one slot per bucket, spreading hash collisions to the
following buckets. As a consequence the hash is just a start position for a linear
search. If a key is looked up that is not in the table, then the bucket table is
searched from the start position (the hash) until the first empty bucket is reached.

This particular mode of operation is open addressing with linear probing.

The bucket table is grown (by 2x) when the number of used buckets plus tombstones
exceeds 50% of its capacity, and shrunken (to 40%, but never below 1000 buckets)
when the number of used buckets drops below 10% of its capacity. So its load factor
usually is between 0.25 and 0.5. That is cheap, because a bucket is only 4 Bytes -
the bulk of the data is in the keys/values arrays, which are not hash tables and
thus do not need any unused space for speed. They are just grown by 1.3x whenever
they are full.

If an element is deleted, its bucket is marked with a tombstone (the keys/values
array slots are zeroed, but not reclaimed until the next rebuild). Tombstones are
only removed by resizing / rebuilding the bucket table. They present the same load
to the hash table as a real entry (recall that linear probing for an element not in
the index stops at the first empty bucket), which is why they count towards the load
factor that triggers the growth.

Data in a HashIndex is stored in little-endian format, which increases efficiency
for almost everyone, since basically no one uses big-endian processors any more.

HashIndex does not use a hashing function, because all keys (save manifest) are
outputs of a cryptographic hash or MAC and thus already have excellent distribution.
Thus, HashIndex simply uses the first 32 bits of the key as its "hash".

The on-disk format does not mirror the in-memory layout - neither the bucket table
nor the unused space of the keys/values arrays are written. A serialized HashIndex is:

- First, a header: the eight byte ASCII string "BORGHASH", an ``uint32`` format
  version and an ``uint32`` length of the metadata block (all little-endian).
- Second, the metadata block, a JSON object with the key size, value size, byte
  order, the value namedtuple's name / fields / struct format, the bucket table
  capacity and the number of entries ("used").
- Third, "used" times a (key, value) pair, without any padding or separators.

So the on-disk size is ``entries * (key_size + value_size)`` plus a small header,
i.e. exactly 80 Bytes per entry for the chunks index.

.. _data-encryption:

Encryption
----------

.. seealso:: The :ref:`borgcrypto` section for an in-depth review.

AEAD modes
~~~~~~~~~~

For new repositories, borg only uses modern AEAD ciphers: AES-OCB or CHACHA20-POLY1305.

For each borg invocation, a new sessionkey is derived from the borg key material
and the 48bit IV starts from 0 again (both ciphers internally add a 32bit counter
to our IV, so we'll just count up by 1 per chunk).

The encryption layout is best seen at the bottom of this diagram:

.. figure:: encryption-aead.png
    :figwidth: 100%
    :width: 100%

No special IV/counter management is needed here due to the use of session keys.

A 48 bit IV is way more than needed: If you only backed up 4kiB chunks (2^12B),
the IV would "limit" the data encrypted in one session to 2^(12+48)B == 2.3 exabytes,
meaning you would run against other limitations (RAM, storage, time) way before that.
In practice, chunks are usually bigger, for big files even much bigger, giving an
even higher limit.

Legacy modes
~~~~~~~~~~~~

Old repositories (which used AES-CTR mode) are supported read-only to be able to
``borg transfer`` their archives to new repositories (which use AEAD modes).

AES-CTR mode is not supported for new repositories and the related code will be
removed in a future release.

Both modes
~~~~~~~~~~

Encryption keys (and other secrets) are kept either in the keys directory on
the client ('keyfile' mode) or under the keys/ namespace in the repository
('repokey' mode) using the sha256 of the borg key content as the name.

In both cases, the secrets are generated from random and then encrypted by a
key derived from your passphrase (this happens on the client before the key
is stored as keyfile or repokey).

keyfile and repokey borg keys use the **same** format; only the storage location
differs. Borg finds the correct key by trying each key against the supplied
passphrase. See :ref:`borgcrypto_multiple_keys`.

The passphrase is passed through the ``BORG_PASSPHRASE`` environment variable
or prompted for interactive usage.

.. _key_files:

Key files
---------

.. seealso:: The :ref:`key_encryption` section for an in-depth review of the key encryption.

When initializing a repository with one of the "keyfile" encryption modes,
Borg creates an associated key file in the keys subdirectory of the borg config
directory (see :ref:`env_vars` for platform-specific default paths).

The same key is also used in the "repokey" modes, which store it in the repository.

The internal data structure is as follows:

version
  currently always an integer, 2

repository_id
  the ``id`` field in the ``config`` ``INI`` file of the repository.

crypt_key
  the initial key material used for the AEAD crypto (512 bits)

id_key
  the key used to MAC the plaintext chunk data to compute the chunk's id

chunk_seed
  the seed for the buzhash chunking table (signed 32 bit integer)

These fields are packed using msgpack_. The utf-8 encoded passphrase
is processed with argon2_ to derive a 256 bit key encryption key (KEK).

Then the KEK is used to encrypt and authenticate the packed data using
the chacha20-poly1305 AEAD cipher.

The result is stored in a another msgpack_ formatted as follows:

version
  currently always an integer, 1

salt
  random 256 bits salt used to process the passphrase

argon2_*
  some parameters for the argon2 kdf

algorithm
  the algorithms used to process the passphrase
  (currently the string ``argon2 chacha20-poly1305``)

data
  The encrypted, packed fields.

The resulting msgpack_ is then encoded using base64 and written to the
key file, wrapped using the standard ``textwrap`` module with a header.
The header is a single line with a MAGIC string, a space and a hexadecimal
representation of the repository id.

.. _data-compression:

Compression
-----------

Borg supports the following compression methods, each identified by a ctype value
in the range between 0 and 255 (and augmented by a clevel 0..255 value for the
compression level):

- none (no compression, pass through data 1:1), identified by 0x00
- lz4 (low compression, but super fast), identified by 0x01
- zstd (level 1-22 offering a wide range: level 1 is lower compression and high
  speed, level 22 is higher compression and lower speed) - identified by 0x03
- zlib (level 0-9, level 0 is no compression [but still adding zlib overhead],
  level 1 is low, level 9 is high compression), identified by 0x05
- lzma (level 0-9, level 0 is low, level 9 is high compression), identified
  by 0x02.

The type byte is followed by a byte indicating the compression level.

Speed:  none > lz4 > zlib > lzma, lz4 > zstd
Compression: lzma > zlib > lz4 > none, zstd > lz4

Be careful, higher compression levels might use a lot of resources (CPU/memory).

The overall speed of course also depends on the speed of your target storage.
If that is slow, using a higher compression level might yield better overall
performance. You need to experiment a bit. Maybe just watch your CPU load, if
that is relatively low, increase compression until 1 core is 70-100% loaded.

Even if your target storage is rather fast, you might see interesting effects:
while doing no compression at all (none) is a operation that takes no time, it
likely will need to store more data to the storage compared to using lz4.
The time needed to transfer and store the additional data might be much more
than if you had used lz4 (which is super fast, but still might compress your
data about 2:1). This is assuming your data is compressible (if you back up
already compressed data, trying to compress them at backup time is usually
pointless).

Compression is applied after deduplication, thus using different compression
methods in one repo does not influence deduplication.

See ``borg create --help`` about how to specify the compression level and its default.

Lock files (fslocking)
----------------------

Borg uses filesystem locks to get (exclusive or shared) access to the cache.

The locking system is based on renaming a temporary directory
to `lock.exclusive` (for
exclusive locks). Inside this directory, there is a file indicating
hostname, process id and thread id of the lock holder.

There is also a json file `lock.roster` that keeps a directory of all shared
and exclusive lockers.

If the process is able to rename a temporary directory (with the
host/process/thread identifier prepared inside it) in the resource directory
to `lock.exclusive`, it has the lock for it. If renaming fails
(because this directory already exists and its host/process/thread identifier
denotes a thread on the host which is still alive), lock acquisition fails.

The cache lock is usually in `~/.cache/borg/REPOID/lock.*`.

Locks (storelocking)
--------------------

To implement locking based on ``borgstore``, borg stores objects below locks/.

The objects contain:

- a timestamp when lock was created (or refreshed)
- host / process / thread information about lock owner
- lock type: exclusive or shared

Using that information, borg implements:

- lock auto-expiry: if a lock is old and has not been refreshed in time,
  it will be automatically ignored and deleted. the primary purpose of this
  is to get rid of stale locks by borg processes on other machines.
- lock auto-removal if the owner process is dead. the primary purpose of this
  is to quickly get rid of stale locks by borg processes on the same machine.

Breaking the locks
------------------

In case you run into troubles with the locks, you can use the ``borg break-lock``
command after you first have made sure that no Borg process is
running on any machine that accesses this resource. Be very careful, the cache
or repository might get damaged if multiple processes use it at the same time.

If there is an issue just with the repository lock, it will usually resolve
automatically (see above), just retry later.


Checksumming data structures
----------------------------

As detailed in the previous sections, Borg generates and stores various files
containing important meta data, such as the files cache.

Data corruption in the files cache could create incorrect archives, e.g. due
to wrong object IDs or sizes in the files cache.

Therefore, Borg calculates checksums when writing these files and tests checksums
when reading them. Checksums are generally 256-bit sha256 hashes.
Checksums are stored as hexadecimal ASCII strings.

For compatibility, checksums are not required and absent checksums do not trigger errors.
The mechanisms have been designed to avoid false-positives when various Borg
versions are used alternately on the same repositories.

Checksums are a data safety mechanism. They are not a security mechanism.

.. rubric:: Choice of algorithm

sha256 has been chosen for its wide availability on all platforms and hw acceleration on some.

Lower layer — file_integrity
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There is a lower layer (borg.crypto.file_integrity.IntegrityCheckedFile)
wrapping a file-like object, performing streaming calculation and comparison
of checksums.
Checksum errors are signalled by raising an exception at the earliest possible
moment (borg.crypto.file_integrity.FileIntegrityError).

.. rubric:: Calculating checksums

Before feeding the checksum algorithm any data, the file name (i.e. without any path)
is mixed into the checksum, since the name encodes the context of the data for Borg.

The various indices used by Borg have separate header and main data parts.
IntegrityCheckedFile allows borg to checksum them independently, which avoids
even reading the data when the header is corrupted. When a part is signalled,
the length of the part name is mixed into the checksum state first (encoded
as an ASCII string via `%10d` printf format), then the name of the part
is mixed in as an UTF-8 string. Lastly, the current position (length)
in the file is mixed in as well.

The checksum state is not reset at part boundaries.

A final checksum is always calculated in the same way as the parts described above,
after seeking to the end of the file. The final checksum cannot prevent code
from processing corrupted data during reading, however, it prevents use of the
corrupted data.

.. rubric:: Serializing checksums

All checksums are compiled into a simple JSON structure called *integrity data*:

.. code-block:: json

    {
        "algorithm": "SHA256",
        "digests": {
            "HashHeader": "eab6802590ba39e3...",
            "final": "e2a7f132fc2e8b24..."
        }
    }

The *algorithm* key notes the used algorithm. When reading, integrity data containing
an unknown algorithm is not inspected further.

The *digests* key contains a mapping of part names to their digests.

Integrity data is generally stored by the upper layers, introduced below. An exception
is the DetachedIntegrityCheckedFile, which automatically writes and reads it from
a ".integrity" file next to the data file.

Upper layer
~~~~~~~~~~~

.. rubric:: Main cache files: chunks and files cache

The integrity data of the ``files`` cache is stored in the cache ``config``.

The ``[integrity]`` section is used:

.. code-block:: none

    [cache]
    version = 1
    repository = 3c4...e59
    manifest = 10e...21c
    timestamp = 2017-06-01T21:31:39.699514
    key_type = 2
    previous_location = /path/to/repo

    [integrity]
    manifest = 10e...21c
    files = {"algorithm": "SHA256", "digests": {"HashHeader": "eab...39e3", "final": "e2a...b24"}}

The manifest ID is duplicated in the integrity section due to the way all Borg
versions handle the config file. Instead of creating a "new" config file from
an internal representation containing only the data understood by Borg,
the config file is read in entirety (using the Python ConfigParser) and modified.
This preserves all sections and values not understood by the Borg version
modifying it.

Thus, if an older versions uses a cache with integrity data, it would preserve
the integrity section and its contents. If a integrity-aware Borg version
would read this cache, it would incorrectly report checksum errors, since
the older version did not update the checksums.

However, by duplicating the manifest ID in the integrity section, it is
easy to tell whether the checksums concern the current state of the cache.

Integrity errors are fatal in these files, terminating the program,
and are not automatically corrected at this time.


HardLinkManager and the hlid concept
------------------------------------

Dealing with hard links needs some extra care, implemented in borg within the HardLinkManager
class:

- At archive creation time, fs items with st_nlink > 1 indicate that they are a member of
  a group of hardlinks all pointing to the same inode. For such fs items, the archived item
  includes a hlid attribute (hardlink id), which is computed like H(st_dev, st_ino). Thus,
  if archived items have the same hlid value, they pointed to the same inode and form a
  group of hardlinks. Besides that, nothing special is done for any member of the group
  of hardlinks, meaning that e.g. for regular files, each archived item will have a
  chunks list.
- At extraction time, the presence of a hlid attribute indicates that there might be more
  hardlinks coming, pointing to the same content (inode), thus borg will remember the "hlid
  to extracted path" mapping, so it will know the correct path for extracting (hardlinking)
  the next hardlink of that group / with the same hlid.
- This symmetric approach (each item has all the information, e.g. the chunks list)
  simplifies dealing with such items a lot, especially for partial extraction, for the
  FUSE filesystem, etc.
- This is different from the asymmetric approach of old borg versions (< 2.0) and also from
  tar which have the concept of a main item (first hardlink, has the content) and content-less
  secondary items with by-name back references for each subsequent hardlink, causing lots
  of complications when dealing with them.

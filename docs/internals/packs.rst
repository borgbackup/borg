.. include:: ../global.rst.inc
.. highlight:: none

.. _packs:

Pack files
==========

Without pack files, each repository chunk is stored as a separate borgstore object.
For large repositories this means millions of individual objects, each requiring its
own I/O round trip to read or write. On high-latency backends (SFTP, cloud object
storage) this overhead dominates backup and restore times.

Pack files address this by grouping multiple chunks into a single store object. A
reader that needs one chunk does a partial read (range request) at a known offset
instead of fetching a separate file. Store object count drops from one-per-chunk to
one-per-pack.


.. _pack-format:

Pack File Format
----------------

There is no separate file header. Each blob starts with the 8-byte ``OBJ_MAGIC``
(``BORG_OBJ``), so a forward scanner can locate blob boundaries and identify
each chunk using only the pack file bytes with no external index.

Per-blob layout
~~~~~~~~~~~~~~~

Each blob is a self-contained unit::

    Offset (relative to blob start)  Size              Type     Field
    --------------------------------  ----------------  -------  -----
    0                                 len(OBJ_MAGIC)    bytes    OBJ_MAGIC = ASCII b"BORG_OBJ"
    8                                 1                 uint8    Format version: 0x01
    9                                 32                bytes    chunk_id
    41                                4                 uint32le meta_size
    45                                4                 uint32le data_size
    49                                meta_size         bytes    encrypted_meta
    49 + meta_size                    data_size         bytes    encrypted_data

``chunk_id`` is the ID hash of the plaintext data (``id_hash(plaintext_data)``).
Storing it in the unencrypted header lets a scanner rebuild the
``chunk_id → location`` index without decrypting any blob.

``chunk_id`` is also written into ``encrypted_meta`` (the meta dict). The header
copy enables key-free scanning and recovery; the meta copy lets future code read
``chunk_id`` through the normal meta dict API without parsing the raw header layout.

The fixed part of each blob header is 49 bytes (``REPOOBJ_HEADER_SIZE``):
``len(OBJ_MAGIC)`` + 1 version + 32 chunk_id + 4 meta_size + 4 data_size.
``REPOOBJ_HEADER_SIZE = len(OBJ_MAGIC) + 1 + 32 + 4 + 4 = 49``

A reader locates the next blob by advancing::

    next_blob_offset = current_blob_offset + REPOOBJ_HEADER_SIZE + meta_size + data_size

The per-blob magic limits the blast radius of corrupted length fields: if
``meta_size`` or ``data_size`` is damaged, the scanner loses at most one blob.
Once it finds the next ``OBJ_MAGIC`` sequence it resumes. Other corruption
(payload bit flips) is caught by AEAD on that blob without losing position.

Blobs follow one another contiguously with no padding::

    OBJ_MAGIC | version=0x01 | chunk_id_0 | meta_size_0 | data_size_0 | encrypted_meta_0 | encrypted_data_0
    OBJ_MAGIC | version=0x01 | chunk_id_1 | meta_size_1 | data_size_1 | encrypted_meta_1 | encrypted_data_1
    ...

Pack ID
~~~~~~~

The pack ID equals the ``chunk_id`` of the blob it contains::

    pack_id = chunk_id

Since ``chunk_id`` is the ID hash of the plaintext, the filename commits to the
content. ``borg check`` can detect silent corruption without decrypting any blob.

Namespace
~~~~~~~~~

Pack files are stored under the ``packs/`` namespace in borgstore, using a
single directory level keyed on the first byte of the pack ID (hex-encoded)::

    packs/
      00/ .. ff/
        <pack_id_hex>


.. _pack-index-entry:

Pack Index Entry
----------------

Each pack contains one blob. The pack for a given chunk is always at::

    packs/<hex(pack_id)>

A ChunkIndex entry maps a chunk to its pack::

    chunk_id  →  pack_id

Since each pack holds exactly one blob, the blob is always at offset 0 and
its length is the full file size. No offset or length field is stored in the
index for this phase.

.. _pack-write-order:

Write Order and Crash Safety
-----------------------------

Pack data must be stored before any archive pointer references it.
The required write order is:

1. Store the pack file to ``packs/<pack_id>`` via borgstore.
2. Store the partial index file to ``index/<index_id>`` (see :ref:`pack-index-namespace`).
3. Write the archive and archive pointer. This is the sole commit point.

A crash between steps 1 and 2 leaves orphan pack files in ``packs/``. No archive
references these chunks; ``borg compact`` removes them on the next run.

A crash between steps 2 and 3 leaves a partial index file covering packs not yet
committed to any archive. The extra index entries point to valid, fully-written pack
data; they are harmless and will be cleaned up by the next ``borg compact``.

A crash after step 3 cannot leave the repository in an inconsistent state. The
archive pointer write is the commit point: data not referenced by any archive pointer
is unreachable and treated as garbage by ``borg compact``.

Only ``borg compact`` and ``borg check --repair`` delete pack files. When compact
determines via mark-and-sweep that none of a pack's blobs are referenced by any
archive, it removes the whole file. Individual blobs cannot be removed without
rewriting the entire pack, so deletion always operates at pack granularity.


.. _pack-index-namespace:

Index Namespace
---------------

Chunk-to-location mappings are stored as a separate set of encrypted partial index
files under the ``index/`` namespace.

Each partial index file covers the packs written in one backup session. Its name is
the SHA-256 digest of its own content. A first backup of a large dataset may produce
a large partial index file; using the same medium-sized file writer as compact for
``borg create`` would bound that. That is the intended direction.

::

    index/
      <sha256_of_content_hex>

Content-addressed naming makes each partial index file self-verifying and idempotent:
writing the same index data twice produces the same filename, so a repeated write is
a no-op.

Partial index files are write-once. A session stores new partial index files via
borgstore; existing files are never modified. On repository open all files under
``index/`` are loaded via borgstore, decrypted, and merged into the in-memory ChunkIndex
(a ``borghash`` ``HashTableNT`` keyed on ``chunk_id``). The merge is commutative and
idempotent; order does not matter.

``borg compact`` rewrites the ``index/`` namespace: it identifies live chunks via
mark-and-sweep, consolidates the surviving mappings into medium-sized replacement
files (targeting roughly 10–100 packs per file), and removes the files it supersedes.
Medium-sized files keep the open-time merge cost bounded while avoiding the
cache-invalidation traffic on other clients that a single all-in-one index would
cause.

If the entire ``index/`` namespace is lost or corrupt, the ChunkIndex can be rebuilt
by scanning pack files directly; see :ref:`pack-recovery`.


.. _pack-recovery:

Recovery Path
-------------

When ``borg check --repair`` detects a missing or incomplete ChunkIndex it rebuilds
it by forward-scanning all pack files in ``packs/``.

Each blob's unencrypted header supplies the ``OBJ_MAGIC`` (for re-sync after
corruption), the ``chunk_id``, and the size fields needed to locate the next blob.
The scan produces a complete ``chunk_id → (pack_id, offset, length)`` mapping
without decrypting any blob and without the repository key.


.. _pack-repo-version:

Repository Version and Feature Flags
--------------------------------------

Repositories using pack files require repository version **4**. Clients that only
accept version 3 refuse to open a version 4 repository with an unsupported-version
error before any data is read.

In addition, the repository ``config.feature_flags`` must include ``pack_files`` in
the mandatory set for all access modes:

.. code-block:: python

    config = {
        "feature_flags": {
            "read":  {"mandatory": ["pack_files"]},
            "write": {"mandatory": ["pack_files"]},
            "check": {"mandatory": ["pack_files"]},
        }
    }

A client that does not recognise the ``pack_files`` feature flag will refuse to open
the repository with a ``MandatoryFeatureUnsupported`` error regardless of the version
number. The two guards cover different failure modes: the version bump stops clients
that predate feature-flag support entirely; the feature flag gives a clearer error
message to clients that understand feature flags but don't know about packs yet.

There is no migration path from version 3 repositories to version 4. Users of the
version 3 beta format must create a new repository with ``borg repo-create``.

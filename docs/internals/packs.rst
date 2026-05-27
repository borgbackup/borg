.. include:: ../global.rst.inc
.. highlight:: none

.. _packs:

Pack files
==========

Borg currently stores each repository object (chunk) as a separate object in the
borgstore.  For large repositories this means millions of individual objects, each
requiring its own I/O round trip to read or write.  On high-latency backends (SFTP,
cloud object storage) this overhead dominates backup and restore times.

Pack files fix this by grouping multiple repo objects into a single store
object.  A reader that needs one chunk does a partial read (range request) at
a known offset instead of fetching a separate file.  Store object count drops
from one-per-chunk to one-per-pack.


.. _pack-format:

Pack File Format
----------------

Every pack file begins with a fixed 9-byte file header, followed by one or more
length-prefixed repo object blobs.  The format is designed for forward scanning:
given only the file bytes and no external index, a reader can locate every blob
boundary by reading the 4-byte length prefix before each blob.

File header
~~~~~~~~~~~

::

    Offset  Size  Type    Field
    ------  ----  ------  -----
    0       8     bytes   Magic: ASCII b"BORGPACK"
    8       1     uint8   Format version: 0x01

Any reader can check the magic bytes to confirm a file in the ``packs/``
namespace is a valid Borg pack file and reject misplaced or truncated files
before parsing further.  The version byte lets future incompatible layout changes
be detected without bumping the repository version.

Per-blob layout
~~~~~~~~~~~~~~~

Each blob is stored as a 4-byte length prefix followed by the full repo object::

    Offset (relative to blob start)  Size        Type     Field
    --------------------------------  ----------  -------  -----
    0                                 4           uint32le blob_len
    4                                 24          bytes    ObjHeader
    4 + 24                            meta_size   bytes    encrypted_meta
    4 + 24 + meta_size                data_size   bytes    encrypted_data

``blob_len`` is the total byte count of the repo object that follows: ObjHeader
(always 24 bytes) plus ``encrypted_meta`` plus ``encrypted_data``.  It satisfies::

    blob_len == 24 + meta_size + data_size

The ObjHeader is the existing 24-byte structure shared by all Borg repo objects::

    Offset  Size  Type     Field
    ------  ----  -------  -----
    0       4     uint32le meta_size
    4       4     uint32le data_size
    8       8     bytes    xxh64(encrypted_meta)
    16      8     bytes    xxh64(encrypted_data)

The ObjHeader is stored unmodified inside the pack blob; the pack layer treats blobs
as opaque bytes and does not rewrite the header.  The SHA256 content-addressed
``pack_id`` handles pack-level integrity; the xxh64 fields come from the existing
RepoObj wire format and are left as-is.  They remain useful for the keyless recovery
scan (see :ref:`pack-recovery`) where AEAD decryption is not available.

.. figure:: pack-objheader.png
    :figwidth: 100%
    :width: 100%
    :figclass: figure-padded

    ObjHeader structure: 24 bytes encoding the sizes and xxh64 integrity hashes for
    the encrypted meta and data sections of each blob.

Blobs follow one another contiguously with no padding between them::

    [file header: 9 B]
    [blob_len_0: 4 B][ObjHeader_0: 24 B][encrypted_meta_0][encrypted_data_0]
    [blob_len_1: 4 B][ObjHeader_1: 24 B][encrypted_meta_1][encrypted_data_1]
    ...
    [blob_len_N-1: 4 B][ObjHeader_N-1: 24 B][encrypted_meta_N-1][encrypted_data_N-1]

.. figure:: pack-layout.png
    :figwidth: 100%
    :width: 100%
    :figclass: figure-padded

    Pack file binary layout: 9-byte file header followed by contiguous
    length-prefixed blobs, each containing an ObjHeader and the encrypted payload.

There is no trailing table of contents.  The ``index/`` namespace (see
:ref:`pack-index-namespace`) is the sole authoritative source of chunk-to-location
mappings for normal operation.

Pack ID
~~~~~~~

For packs containing more than one blob, the pack ID is the SHA-256 digest of the
entire pack file content (file header plus all blobs)::

    pack_id = SHA256(pack_file_bytes)

This makes pack files content-addressed: the stored filename is a commitment to the
content.  ``borg check`` can detect silent corruption by recomputing the digest and
comparing it to the filename without decrypting any blob.

Namespace
~~~~~~~~~

Pack files are stored under the ``packs/`` namespace in borgstore, using a two-level
directory nesting on the first two bytes of the pack ID (hex-encoded)::

    packs/
      00/ .. ff/
        00/ .. ff/
          <pack_id_hex>

The nesting depth is controlled by the ``packs/`` entry in the repository's
``levels_config``, the same mechanism used by the ``data/`` namespace.


.. _pack-phase1:

Phase 1 Implementation (N=1)
-----------------------------

The initial implementation puts one blob per pack file.  Assembly is simpler: no
multi-chunk buffering, and the PackIndex lookup follows directly from the chunk ID.

Under this phase the pack ID is set equal to the chunk ID of the single blob it
contains::

    pack_id = chunk_id   # Phase 1 only

Computing SHA-256 over the pack content is therefore unnecessary.  The pack for a
given chunk is always at::

    packs/<hex(chunk_id)>

where the chunk ID is the same keyed MAC (``id_hash(plaintext_data)``) used today
for objects in ``data/``.

The ``BORGPACK`` header and the 4-byte ``blob_len`` prefix are written regardless.
Phase 1 packs are structurally identical to multi-blob packs; readers require no
special case for N=1.

A PackIndex entry for Phase 1 packs is::

    chunk_id  →  (pack_id = chunk_id,
                  offset  = 13,        # 9-byte file header + 4-byte blob_len
                  length  = blob_len)  # value read from bytes 9-12 of the pack file

.. note::

    The N value is configurable at ``borg repo-create`` time.  Expanding to N>1 in
    a follow-on change requires no modification to the pack file format: the file
    header and per-blob layout are identical.  Only the pack assembly, PackIndex
    update, and pack ID computation logic changes.


.. _pack-write-order:

Write Order and Crash Safety
-----------------------------

Pack data must reach stable storage before any index or manifest entry references
it.  The required write order is:

1. Write the pack file to ``packs/<pack_id>``.
2. ``fsync`` the pack file and its containing directory.
3. Write the index piece file to ``index/<index_id>`` (see :ref:`pack-index-namespace`).
4. ``fsync`` the index piece file.
5. Update and write the manifest.  This is the sole commit point.

.. figure:: pack-write-order.png
    :figwidth: 40%
    :width: 100%
    :align: center

    Write order and crash safety: the manifest write at step 5 is the sole commit
    point; partial failures at earlier steps leave only harmless orphan data.

A crash between steps 1 and 3 leaves orphan pack files in ``packs/``.  No archive
references these chunks; ``borg compact`` removes them on the next run.

A crash between steps 3 and 5 leaves an index piece covering packs not yet committed
to any archive.  The extra index entries point to valid, fully-written pack data; they
are harmless and will be cleaned up by the next ``borg compact``.

A crash after step 5 cannot leave the repository in an inconsistent state.  The
manifest is the commit point: data that the manifest does not reference is unreachable
and treated as garbage by ``borg compact``.

Deletion is soft: ``repository.delete()`` does not remove the pack file.  The pack
stays on disk until ``borg compact`` confirms via mark-and-sweep that none of its
blobs appear in any archive, then removes the whole file.  The same approach carries to N>1: there is no way to remove one blob from a pack
without rewriting the whole file, so soft-delete is the only option.


.. _pack-index-namespace:

Index Namespace
---------------

Borg does not embed a table of contents inside each pack file.  Chunk-to-location
mappings are stored as a separate set of encrypted piece files under the ``index/``
namespace.

Each piece file covers the packs written in one backup session.  Its name is the
SHA-256 digest of its own content::

    index/
      <sha256_of_content_hex>

Content-addressed naming makes each piece file self-verifying and idempotent: writing
the same index data twice produces the same filename, so a repeated write is a no-op.

Piece files are write-once.  A session appends new piece files; existing files are
never modified.  On repository open, the client downloads all files under ``index/``,
decrypts them, and merges the results into the in-memory PackIndex (a ``borghash``
``HashTableNT`` keyed on ``chunk_id``).  The merge is commutative and idempotent;
piece file order does not matter.

``borg compact`` consolidates all existing piece files into a single replacement file
that covers only live chunks, writes it to ``index/``, and removes the files it
supersedes.  This keeps the namespace small and open-time merge cost bounded.

If the entire ``index/`` namespace is lost or corrupt, the PackIndex can be rebuilt
by scanning pack files directly; see :ref:`pack-recovery`.


.. _pack-recovery:

Recovery Path
-------------

When ``borg check --repair`` detects a missing or incomplete PackIndex it rebuilds
it by forward-scanning all pack files in ``packs/``.

The 4-byte ``blob_len`` prefix before each blob makes the scan self-contained: no
prior knowledge of blob sizes or count is required.  The algorithm for one pack file::

    verify magic   = first 8 bytes are b"BORGPACK"
    verify version = byte 8 is 0x01

    pos = 9
    while pos < file_size:
        if pos + 4 > file_size:
            raise CorruptPackError(pack_id, pos)
        blob_len = uint32le(file[pos : pos + 4])
        if blob_len == 0 or pos + 4 + blob_len > file_size:
            raise CorruptPackError(pack_id, pos)

        obj_header          = file[pos + 4 : pos + 4 + 24]
        meta_size, data_size = uint32le(obj_header[0:4]), uint32le(obj_header[4:8])

        # Verify ObjHeader integrity without the key.
        assert xxh64(file[pos+28 : pos+28+meta_size])            == obj_header[8:16]
        assert xxh64(file[pos+28+meta_size : pos+4+blob_len])    == obj_header[16:24]

        # Reconstruct the chunk_id for this blob (requires the repository key).
        chunk_id = derive_chunk_id(pack_id, pos + 4, blob_len)

        record_index_entry(chunk_id,
                           pack_id = pack_id,
                           offset  = pos + 4,
                           length  = blob_len)
        pos += 4 + blob_len

The ``offset`` recorded in the rebuilt index points past the ``blob_len`` prefix,
directly at the ObjHeader, consistent with normal PackIndex entries.

Reconstructing ``chunk_id`` values requires the repository key because the chunk ID
is a keyed MAC of the plaintext data (``id_hash(plaintext_data)``).  Without the key,
a structural scan can still verify magic bytes, version, blob boundaries, and
ObjHeader xxh64 hashes, but cannot produce a usable ``chunk_id → location`` mapping.


.. _pack-repo-version:

Repository Version and Feature Flags
--------------------------------------

Repositories using pack files require repository version **4**.  Clients that only
accept version 3 refuse to open a version 4 repository with an unsupported-version
error before any data is read.

In addition, the manifest's ``config.feature_flags`` must include ``pack_files`` in
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
number.  The two guards cover different failure modes: the version bump stops clients
that predate feature-flag support entirely; the feature flag gives a clearer error
message to clients that understand feature flags but don't know about packs yet.

There is no migration path from version 3 repositories to version 4.  Users of the
version 3 beta format must create a new repository with ``borg repo-create``.

.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_check:

borg check
----------
.. code-block:: none

    borg [common options] check [options] REPOSITORY_OR_ARCHIVE

positional arguments
    REPOSITORY_OR_ARCHIVE
        repository or archive to check consistency of

optional arguments
    ``--repository-only``
        | only perform repository checks
    ``--archives-only``
        | only perform archives checks
    ``--verify-data``
        | perform cryptographic archive data integrity verification (conflicts with ``--repository-only``)
    ``--repair``
        | attempt to repair any inconsistencies found
    ``--save-space``
        | work slower, but using less space

:ref:`common_options`
    |

filters
    ``-P``, ``--prefix``
        | only consider archive names starting with this prefix.
    ``-a``, ``--glob-archives``
        | only consider archive names matching the glob. sh: rules apply, see "borg help patterns". ``--prefix`` and ``--glob-archives`` are mutually exclusive.
    ``--sort-by``
        | Comma-separated list of sorting keys; valid keys are: timestamp, name, id; default is: timestamp
    ``--first N``
        | consider first N archives after other filters were applied
    ``--last N``
        | consider last N archives after other filters were applied

Description
~~~~~~~~~~~

The check command verifies the consistency of a repository and the corresponding archives.

First, the underlying repository data files are checked:

- For all segments the segment magic (header) is checked
- For all objects stored in the segments, all metadata (e.g. crc and size) and
  all data is read. The read data is checked by size and CRC. Bit rot and other
  types of accidental damage can be detected this way.
- If we are in repair mode and a integrity error is detected for a segment,
  we try to recover as many objects from the segment as possible.
- In repair mode, it makes sure that the index is consistent with the data
  stored in the segments.
- If you use a remote repo server via ssh:, the repo check is executed on the
  repo server without causing significant network traffic.
- The repository check can be skipped using the ``--archives-only`` option.

Second, the consistency and correctness of the archive metadata is verified:

- Is the repo manifest present? If not, it is rebuilt from archive metadata
  chunks (this requires reading and decrypting of all metadata and data).
- Check if archive metadata chunk is present. if not, remove archive from
  manifest.
- For all files (items) in the archive, for all chunks referenced by these
  files, check if chunk is present.
  If a chunk is not present and we are in repair mode, replace it with a same-size
  replacement chunk of zeros.
  If a previously lost chunk reappears (e.g. via a later backup) and we are in
  repair mode, the all-zero replacement chunk will be replaced by the correct chunk.
  This requires reading of archive and file metadata, but not data.
- If we are in repair mode and we checked all the archives: delete orphaned
  chunks from the repo.
- if you use a remote repo server via ssh:, the archive check is executed on
  the client machine (because if encryption is enabled, the checks will require
  decryption and this is always done client-side, because key access will be
  required).
- The archive checks can be time consuming, they can be skipped using the
  ``--repository-only`` option.

The ``--verify-data`` option will perform a full integrity verification (as opposed to
checking the CRC32 of the segment) of data, which means reading the data from the
repository, decrypting and decompressing it. This is a cryptographic verification,
which will detect (accidental) corruption. For encrypted repositories it is
tamper-resistant as well, unless the attacker has access to the keys.

It is also very slow.
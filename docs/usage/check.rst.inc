.. _borg_check:

borg check
----------
::

    borg check <options> REPOSITORY_OR_ARCHIVE

positional arguments
    REPOSITORY_OR_ARCHIVE
        repository or archive to check consistency of

optional arguments
    ``--repository-only``
        | only perform repository checks
    ``--archives-only``
        | only perform archives checks
    ``--repair``
        | attempt to repair any inconsistencies found
    ``--save-space``
        | work slower, but using less space
    ``--last N``
        | only check last N archives (Default: all)
    ``-P``, ``--prefix``
        | only consider archive names starting with this prefix

`Common options`_
    |

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
- The repository check can be skipped using the --archives-only option.

Second, the consistency and correctness of the archive metadata is verified:

- Is the repo manifest present? If not, it is rebuilt from archive metadata
  chunks (this requires reading and decrypting of all metadata and data).
- Check if archive metadata chunk is present. if not, remove archive from
  manifest.
- For all files (items) in the archive, for all chunks referenced by these
  files, check if chunk is present (if not and we are in repair mode, replace
  it with a same-size chunk of zeros). This requires reading of archive and
  file metadata, but not data.
- If we are in repair mode and we checked all the archives: delete orphaned
  chunks from the repo.
- if you use a remote repo server via ssh:, the archive check is executed on
  the client machine (because if encryption is enabled, the checks will require
  decryption and this is always done client-side, because key access will be
  required).
- The archive checks can be time consuming, they can be skipped using the
  --repository-only option.

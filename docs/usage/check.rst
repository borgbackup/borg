.. _borg_check:

borg check
----------

Check repository consistency

Synopsis
~~~~~~~~

::

    borg check [-h] [-v] [--show-rc] [--no-files-cache] [--umask M]
                      [--remote-path PATH] [--repository-only] [--archives-only]
                      [--repair] [--last N]
                      [REPOSITORY_OR_ARCHIVE]
    
positional arguments
~~~~~~~~~~~~~~~~~~~~

::
      
    
      REPOSITORY_OR_ARCHIVE
                            repository or archive to check consistency of
    
optional arguments
~~~~~~~~~~~~~~~~~~

::
      
    
      -h, --help            show this help message and exit
      -v, --verbose         verbose output
      --show-rc             show/log the return code (rc)
      --no-files-cache      do not load/update the file metadata cache used to
                            detect unchanged files
      --umask M             set umask to M (local and remote, default: 63)
      --remote-path PATH    set remote path to executable (default: "borg")
      --repository-only     only perform repository checks
      --archives-only       only perform archives checks
      --repair              attempt to repair any inconsistencies found
      --last N              only check last N archives (Default: all)
    
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

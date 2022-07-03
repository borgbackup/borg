.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_check:

borg check
----------
.. code-block:: none

    borg [common options] check [options]

.. only:: html

    .. class:: borg-options-table

    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------+
    | **optional arguments**                                                                                                                                                                                                 |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``--repository-only``                 | only perform repository checks                                                                   |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``--archives-only``                   | only perform archives checks                                                                     |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``--verify-data``                     | perform cryptographic archive data integrity verification (conflicts with ``--repository-only``) |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``--repair``                          | attempt to repair any inconsistencies found                                                      |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``--save-space``                      | work slower, but using less space                                                                |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``--max-duration SECONDS``            | do only a partial repo check for max. SECONDS seconds (Default: unlimited)                       |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                         |
    |                                                                                                                                                                                                                        |
    | :ref:`common_options`                                                                                                                                                                                                  |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------+
    | **Archive filters** — Archive filters can be applied to repository targets.                                                                                                                                            |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``-a GLOB``, ``--glob-archives GLOB`` | only consider archive names matching the glob. sh: rules apply, see "borg help patterns".        |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``--sort-by KEYS``                    | Comma-separated list of sorting keys; valid keys are: timestamp, name, id; default is: timestamp |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``--first N``                         | consider first N archives after other filters were applied                                       |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``--last N``                          | consider last N archives after other filters were applied                                        |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    optional arguments
        --repository-only    only perform repository checks
        --archives-only    only perform archives checks
        --verify-data     perform cryptographic archive data integrity verification (conflicts with ``--repository-only``)
        --repair          attempt to repair any inconsistencies found
        --save-space      work slower, but using less space
        --max-duration SECONDS    do only a partial repo check for max. SECONDS seconds (Default: unlimited)


    :ref:`common_options`
        |

    Archive filters
        -a GLOB, --glob-archives GLOB     only consider archive names matching the glob. sh: rules apply, see "borg help patterns".
        --sort-by KEYS                    Comma-separated list of sorting keys; valid keys are: timestamp, name, id; default is: timestamp
        --first N                         consider first N archives after other filters were applied
        --last N                          consider last N archives after other filters were applied


Description
~~~~~~~~~~~

The check command verifies the consistency of a repository and the corresponding archives.

check --repair is a potentially dangerous function and might lead to data loss
(for kinds of corruption it is not capable of dealing with). BE VERY CAREFUL!

Pursuant to the previous warning it is also highly recommended to test the
reliability of the hardware running this software with stress testing software
such as memory testers. Unreliable hardware can also lead to data loss especially
when this command is run in repair mode.

First, the underlying repository data files are checked:

- For all segments, the segment magic header is checked.
- For all objects stored in the segments, all metadata (e.g. CRC and size) and
  all data is read. The read data is checked by size and CRC. Bit rot and other
  types of accidental damage can be detected this way.
- In repair mode, if an integrity error is detected in a segment, try to recover
  as many objects from the segment as possible.
- In repair mode, make sure that the index is consistent with the data stored in
  the segments.
- If checking a remote repo via ``ssh:``, the repo check is executed on the server
  without causing significant network traffic.
- The repository check can be skipped using the ``--archives-only`` option.
- A repository check can be time consuming. Partial checks are possible with the
  ``--max-duration`` option.

Second, the consistency and correctness of the archive metadata is verified:

- Is the repo manifest present? If not, it is rebuilt from archive metadata
  chunks (this requires reading and decrypting of all metadata and data).
- Check if archive metadata chunk is present; if not, remove archive from manifest.
- For all files (items) in the archive, for all chunks referenced by these
  files, check if chunk is present. In repair mode, if a chunk is not present,
  replace it with a same-size replacement chunk of zeroes. If a previously lost
  chunk reappears (e.g. via a later backup), in repair mode the all-zero replacement
  chunk will be replaced by the correct chunk. This requires reading of archive and
  file metadata, but not data.
- In repair mode, when all the archives were checked, orphaned chunks are deleted
  from the repo. One cause of orphaned chunks are input file related errors (like
  read errors) in the archive creation process.
- In verify-data mode, a complete cryptographic verification of the archive data
  integrity is performed. This conflicts with ``--repository-only`` as this mode
  only makes sense if the archive checks are enabled. The full details of this mode
  are documented below.
- If checking a remote repo via ``ssh:``, the archive check is executed on the
  client machine because it requires decryption, and this is always done client-side
  as key access is needed.
- The archive checks can be time consuming; they can be skipped using the
  ``--repository-only`` option.

The ``--max-duration`` option can be used to split a long-running repository check
into multiple partial checks. After the given number of seconds the check is
interrupted. The next partial check will continue where the previous one stopped,
until the complete repository has been checked. Example: Assuming a complete check took 7
hours, then running a daily check with --max-duration=3600 (1 hour) resulted in one
completed check per week.

Attention: A partial --repository-only check can only do way less checking than a full
--repository-only check: only the non-cryptographic checksum checks on segment file
entries are done, while a full --repository-only check would also do a repo index check.
A partial check cannot be combined with the ``--repair`` option. Partial checks
may therefore be useful only with very large repositories where a full check would take
too long.
Doing a full repository check aborts a partial check; the next partial check will restart
from the beginning.

The ``--verify-data`` option will perform a full integrity verification (as opposed to
checking the CRC32 of the segment) of data, which means reading the data from the
repository, decrypting and decompressing it. This is a cryptographic verification,
which will detect (accidental) corruption. For encrypted repositories it is
tamper-resistant as well, unless the attacker has access to the keys. It is also very
slow.
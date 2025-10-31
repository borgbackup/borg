.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_check:

borg check
----------
.. code-block:: none

    borg [common options] check [options] [REPOSITORY_OR_ARCHIVE]

.. only:: html

    .. class:: borg-options-table

    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    | **positional arguments**                                                                                                                                                                                                                                |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``REPOSITORY_OR_ARCHIVE``             | repository or archive to check consistency of                                                                                     |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                                                                                             |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--repository-only``                 | only perform repository checks                                                                                                    |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--archives-only``                   | only perform archives checks                                                                                                      |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--verify-data``                     | perform cryptographic archive data integrity verification (conflicts with ``--repository-only``)                                  |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--repair``                          | attempt to repair any inconsistencies found                                                                                       |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--save-space``                      | work slower, but using less space                                                                                                 |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--max-duration SECONDS``            | do only a partial repo check for max. SECONDS seconds (Default: unlimited)                                                        |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                                          |
    |                                                                                                                                                                                                                                                         |
    | :ref:`common_options`                                                                                                                                                                                                                                   |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    | **Archive filters** — Archive filters can be applied to repository targets.                                                                                                                                                                             |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-P PREFIX``, ``--prefix PREFIX``    | only consider archive names starting with this prefix. (deprecated)                                                               |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-a GLOB``, ``--glob-archives GLOB`` | only consider archive names matching the glob. sh: rules apply (without actually using the sh: prefix), see "borg help patterns". |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--sort-by KEYS``                    | Comma-separated list of sorting keys; valid keys are: timestamp, archive, name, id; default is: timestamp                         |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--first N``                         | consider first N archives after other filters were applied                                                                        |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--last N``                          | consider last N archives after other filters were applied                                                                         |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    REPOSITORY_OR_ARCHIVE
        repository or archive to check consistency of


    options
        --repository-only    only perform repository checks
        --archives-only    only perform archives checks
        --verify-data     perform cryptographic archive data integrity verification (conflicts with ``--repository-only``)
        --repair          attempt to repair any inconsistencies found
        --save-space      work slower, but using less space
        --max-duration SECONDS    do only a partial repo check for max. SECONDS seconds (Default: unlimited)


    :ref:`common_options`
        |

    Archive filters
        -P PREFIX, --prefix PREFIX        only consider archive names starting with this prefix. (deprecated)
        -a GLOB, --glob-archives GLOB     only consider archive names matching the glob. sh: rules apply (without actually using the sh: prefix), see "borg help patterns".
        --sort-by KEYS                    Comma-separated list of sorting keys; valid keys are: timestamp, archive, name, id; default is: timestamp
        --first N                         consider first N archives after other filters were applied
        --last N                          consider last N archives after other filters were applied


Description
~~~~~~~~~~~

The check command verifies the consistency of a repository and its archives.
It consists of two major steps:

1. Checking the consistency of the repository itself. This includes checking
   the segment magic headers, and both the metadata and data of all objects in
   the segments. The read data is checked by size and CRC. Bit rot and other
   types of accidental damage can be detected this way. Running the repository
   check can be split into multiple partial checks using ``--max-duration``.
   When checking a remote repository, please note that the checks run on the
   server and do not cause significant network traffic.

2. Checking consistency and correctness of the archive metadata and optionally
   archive data (requires ``--verify-data``). This includes ensuring that the
   repository manifest exists, the archive metadata chunk is present, and that
   all chunks referencing files (items) in the archive exist. This requires
   reading archive and file metadata, but not data. To cryptographically verify
   the file (content) data integrity pass ``--verify-data``, but keep in mind
   that this requires reading all data and is hence very time consuming. When
   checking archives of a remote repository, archive checks run on the client
   machine because they require decrypting data and therefore the encryption
   key.

Both steps can also be run independently. Pass ``--repository-only`` to run the
repository checks only, or pass ``--archives-only`` to run the archive checks
only.

The ``--max-duration`` option can be used to split a long-running repository
check into multiple partial checks. After the given number of seconds the check
is interrupted. The next partial check will continue where the previous one
stopped, until the full repository has been checked. Assuming a complete check
would take 7 hours, then running a daily check with ``--max-duration=3600``
(1 hour) would result in one full repository check per week. Doing a full
repository check aborts any previous partial check; the next partial check will
restart from the beginning. With partial repository checks you can run neither
archive checks, nor enable repair mode. Consequently, if you want to use
``--max-duration`` you must also pass ``--repository-only``, and must not pass
``--archives-only``, nor ``--repair``.

**Warning:** Please note that partial repository checks (i.e. running it with
``--max-duration``) can only perform non-cryptographic checksum checks on the
segment files. A full repository check (i.e. without ``--max-duration``) can
also do a repository index check. Enabling partial repository checks excludes
archive checks for the same reason. Therefore partial checks may be useful with
very large repositories only where a full check would take too long.

The ``--verify-data`` option will perform a full integrity verification (as
opposed to checking the CRC32 of the segment) of data, which means reading the
data from the repository, decrypting and decompressing it. It is a complete
cryptographic verification and hence very time consuming, but will detect any
accidental and malicious corruption. Tamper-resistance is only guaranteed for
encrypted repositories against attackers without access to the keys. You cannot
use ``--verify-data`` with ``--repository-only``.

About repair mode
+++++++++++++++++

The check command is a read-only task by default. If any corruption is found,
Borg will report the issue and proceed with checking. To actually repair the
issues found, pass ``--repair``.

.. note::

    ``--repair`` is a **POTENTIALLY DANGEROUS FEATURE** and might lead to data
    loss! This does not just include data that was previously lost anyway, but
    might include more data for kinds of corruption it is not capable of
    dealing with. **BE VERY CAREFUL!**

Pursuant to the previous warning it is also highly recommended to test the
reliability of the hardware running Borg with stress testing software. This
especially includes storage and memory testers. Unreliable hardware might lead
to additional data loss.

It is highly recommended to create a backup of your repository before running
in repair mode (i.e. running it with ``--repair``).

Repair mode will attempt to fix any corruptions found. Fixing corruptions does
not mean recovering lost data: Borg can not magically restore data lost due to
e.g. a hardware failure. Repairing a repository means sacrificing some data
for the sake of the repository as a whole and the remaining data. Hence it is,
by definition, a potentially lossy task.

In practice, repair mode hooks into both the repository and archive checks:

1. When checking the repository's consistency, repair mode will try to recover
   as many objects from segments with integrity errors as possible, and ensure
   that the index is consistent with the data stored in the segments.

2. When checking the consistency and correctness of archives, repair mode might
   remove whole archives from the manifest if their archive metadata chunk is
   corrupt or lost. On a chunk level (i.e. the contents of files), repair mode
   will replace corrupt or lost chunks with a same-size replacement chunk of
   zeroes. If a previously zeroed chunk reappears, repair mode will restore
   this lost chunk using the new chunk. Lastly, repair mode will also delete
   orphaned chunks (e.g. caused by read errors while creating the archive).

Most steps taken by repair mode have a one-time effect on the repository, like
removing a lost archive from the repository. However, replacing a corrupt or
lost chunk with an all-zero replacement will have an ongoing effect on the
repository: When attempting to extract a file referencing an all-zero chunk,
the ``extract`` command will distinctly warn about it. The FUSE filesystem
created by the ``mount`` command will reject reading such a "zero-patched"
file unless a special mount option is given.

As mentioned earlier, Borg might be able to "heal" a "zero-patched" file in
repair mode, if all its previously lost chunks reappear (e.g. via a later
backup). This is achieved by Borg not only keeping track of the all-zero
replacement chunks, but also by keeping metadata about the lost chunks. In
repair mode Borg will check whether a previously lost chunk reappeared and will
replace the all-zero replacement chunk by the reappeared chunk. If all lost
chunks of a "zero-patched" file reappear, this effectively "heals" the file.
Consequently, if lost chunks were repaired earlier, it is advised to run
``--repair`` a second time after creating some new backups.
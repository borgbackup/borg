.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_check:

borg check
----------
.. code-block:: none

    borg [common options] check [options]

.. only:: html

    .. class:: borg-options-table

    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                                                                                              |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--repository-only``                        | only perform repository checks                                                                                              |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--archives-only``                          | only perform archives checks                                                                                                |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--verify-data``                            | perform cryptographic archive data integrity verification (conflicts with ``--repository-only``)                            |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--repair``                                 | attempt to repair any inconsistencies found                                                                                 |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--find-lost-archives``                     | attempt to find lost archives                                                                                               |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--max-duration SECONDS``                   | do only a partial repo check for max. SECONDS seconds (Default: unlimited)                                                  |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                                           |
    |                                                                                                                                                                                                                                                          |
    | :ref:`common_options`                                                                                                                                                                                                                                    |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    | **Archive filters** — Archive filters can be applied to repository targets.                                                                                                                                                                              |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-a PATTERN``, ``--match-archives PATTERN`` | only consider archives matching all patterns. see "borg help match-archives".                                               |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--sort-by KEYS``                           | Comma-separated list of sorting keys; valid keys are: timestamp, archive, name, id, tags, host, user; default is: timestamp |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--first N``                                | consider first N archives after other filters were applied                                                                  |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--last N``                                 | consider last N archives after other filters were applied                                                                   |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--oldest TIMESPAN``                        | consider archives between the oldest archive's timestamp and (oldest + TIMESPAN), e.g. 7d or 12m.                           |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--newest TIMESPAN``                        | consider archives between the newest archive's timestamp and (newest - TIMESPAN), e.g. 7d or 12m.                           |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--older TIMESPAN``                         | consider archives older than (now - TIMESPAN), e.g. 7d or 12m.                                                              |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--newer TIMESPAN``                         | consider archives newer than (now - TIMESPAN), e.g. 7d or 12m.                                                              |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    options
        --repository-only    only perform repository checks
        --archives-only    only perform archives checks
        --verify-data     perform cryptographic archive data integrity verification (conflicts with ``--repository-only``)
        --repair          attempt to repair any inconsistencies found
        --find-lost-archives    attempt to find lost archives
        --max-duration SECONDS    do only a partial repo check for max. SECONDS seconds (Default: unlimited)


    :ref:`common_options`
        |

    Archive filters
        -a PATTERN, --match-archives PATTERN     only consider archives matching all patterns. see "borg help match-archives".
        --sort-by KEYS                           Comma-separated list of sorting keys; valid keys are: timestamp, archive, name, id, tags, host, user; default is: timestamp
        --first N                                consider first N archives after other filters were applied
        --last N                                 consider last N archives after other filters were applied
        --oldest TIMESPAN                        consider archives between the oldest archive's timestamp and (oldest + TIMESPAN), e.g. 7d or 12m.
        --newest TIMESPAN                        consider archives between the newest archive's timestamp and (newest - TIMESPAN), e.g. 7d or 12m.
        --older TIMESPAN                         consider archives older than (now - TIMESPAN), e.g. 7d or 12m.
        --newer TIMESPAN                         consider archives newer than (now - TIMESPAN), e.g. 7d or 12m.


Description
~~~~~~~~~~~

The check command verifies the consistency of a repository and its archives.
It consists of two major steps:

1. Checking the consistency of the repository itself. This includes checking
   the file magic headers, and both the metadata and data of all objects in
   the repository. The read data is checked by size and hash. Bit rot and other
   types of accidental damage can be detected this way. Running the repository
   check can be split into multiple partial checks using ``--max-duration``.
   When checking a ssh:// remote repository, please note that the checks run on
   the server and do not cause significant network traffic.

2. Checking consistency and correctness of the archive metadata and optionally
   archive data (requires ``--verify-data``). This includes ensuring that the
   repository manifest exists, the archive metadata chunk is present, and that
   all chunks referencing files (items) in the archive exist. This requires
   reading archive and file metadata, but not data. To scan for archives whose
   entries were lost from the archive directory, pass ``--find-lost-archives``.
   It requires reading all data and is hence very time consuming.
   To additionally cryptographically verify the file (content) data integrity,
   pass ``--verify-data``, which is even more time consuming.

   When checking archives of a remote repository, archive checks run on the client
   machine because they require decrypting data and therefore the encryption key.

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
repository files. Enabling partial repository checks excepts archive checks
for the same reason. Therefore partial checks may be useful with very large
repositories only where a full check would take too long.

The ``--verify-data`` option will perform a full integrity verification (as
opposed to checking just the xxh64) of data, which means reading the
data from the repository, decrypting and decompressing it. It is a complete
cryptographic verification and hence very time consuming, but will detect any
accidental and malicious corruption. Tamper-resistance is only guaranteed for
encrypted repositories against attackers without access to the keys. You can
not use ``--verify-data`` with ``--repository-only``.

The ``--find-lost-archives`` option will also scan the whole repository, but
tells Borg to search for lost archive metadata. If Borg encounters any archive
metadata that doesn't match with an archive directory entry (including
soft-deleted archives), it means that an entry was lost.
Unless ``borg compact`` is called, these archives can be fully restored with
``--repair``. Please note that ``--find-lost-archives`` must read a lot of
data from the repository and is thus very time consuming. You can not use
``--find-lost-archives`` with ``--repository-only``.

About repair mode
+++++++++++++++++

The check command is a readonly task by default. If any corruption is found,
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

1. When checking the repository's consistency, repair mode removes corrupted
   objects from the repository after it did a 2nd try to read them correctly.

2. When checking the consistency and correctness of archives, repair mode might
   remove whole archives from the manifest if their archive metadata chunk is
   corrupt or lost. Borg will also report files that reference missing chunks.

If ``--repair --find-lost-archives`` is given, previously lost entries will
be recreated in the archive directory. This is only possible before
``borg compact`` would remove the archives' data completely.
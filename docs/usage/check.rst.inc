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
    |                                                                             | ``--archives-only``                          | only perform archive checks                                                                                                 |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--verify-data``                            | perform cryptographic archive data integrity verification (conflicts with ``--repository-only``)                            |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--repair``                                 | attempt to repair any inconsistencies found                                                                                 |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--find-lost-archives``                     | attempt to find lost archives                                                                                               |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--max-age TIMESPAN``                       | reuse intact-pack check results younger than TIMESPAN, e.g. 4w or 12m                                                       |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--max-duration SECONDS``                   | perform only a partial repository check for at most SECONDS seconds (default: unlimited)                                    |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--format FORMAT``                          | specify format for the archive part (default: "{archive} {time} {id}")                                                      |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                                           |
    |                                                                                                                                                                                                                                                          |
    | :ref:`common_options`                                                                                                                                                                                                                                    |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    | **Archive filters** — Archive filters can be applied to repository targets.                                                                                                                                                                              |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-a PATTERN``, ``--match-archives PATTERN`` | only consider archives matching all patterns. See "borg help match-archives".                                               |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--sort-by KEYS``                           | Comma-separated list of sorting keys; valid keys are: timestamp, archive, name, id, tags, host, user; default is: timestamp |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--first N``                                | consider the first N archives after other filters are applied                                                               |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--last N``                                 | consider the last N archives after other filters are applied                                                                |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--oldest TIMESPAN``                        | consider archives between the oldest archive's timestamp and (oldest + TIMESPAN), e.g., 7d or 12m.                          |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--newest TIMESPAN``                        | consider archives between the newest archive's timestamp and (newest - TIMESPAN), e.g., 7d or 12m.                          |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--older TIMESPAN``                         | consider archives older than (now - TIMESPAN), e.g., 7d or 12m.                                                             |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--newer TIMESPAN``                         | consider archives newer than (now - TIMESPAN), e.g., 7d or 12m.                                                             |
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
        --archives-only    only perform archive checks
        --verify-data     perform cryptographic archive data integrity verification (conflicts with ``--repository-only``)
        --repair          attempt to repair any inconsistencies found
        --find-lost-archives    attempt to find lost archives
        --max-age TIMESPAN    reuse intact-pack check results younger than TIMESPAN, e.g. 4w or 12m
        --max-duration SECONDS    perform only a partial repository check for at most SECONDS seconds (default: unlimited)
        --format FORMAT    specify format for the archive part (default: "{archive} {time} {id}")


    :ref:`common_options`
        |

    Archive filters
        -a PATTERN, --match-archives PATTERN     only consider archives matching all patterns. See "borg help match-archives".
        --sort-by KEYS                           Comma-separated list of sorting keys; valid keys are: timestamp, archive, name, id, tags, host, user; default is: timestamp
        --first N                                consider the first N archives after other filters are applied
        --last N                                 consider the last N archives after other filters are applied
        --oldest TIMESPAN                        consider archives between the oldest archive's timestamp and (oldest + TIMESPAN), e.g., 7d or 12m.
        --newest TIMESPAN                        consider archives between the newest archive's timestamp and (newest - TIMESPAN), e.g., 7d or 12m.
        --older TIMESPAN                         consider archives older than (now - TIMESPAN), e.g., 7d or 12m.
        --newer TIMESPAN                         consider archives newer than (now - TIMESPAN), e.g., 7d or 12m.


Description
~~~~~~~~~~~

The check command verifies the consistency of a repository and its archives.
It consists of two major steps:

1. Checking the consistency of the repository itself. This includes checking
   the file magic headers, and both the metadata and data of all objects in
   the repository. The read data is checked by size and hash. Bit rot and other
   types of accidental damage can be detected this way. Running the repository
   check can be split into multiple partial checks using ``--max-duration``.
   When checking an ssh:// remote repository, please note that the checks run on
   the server and do not cause significant network traffic.

2. Checking consistency and correctness of the archive metadata and optionally
   archive data (requires ``--verify-data``). This includes ensuring that the
   repository manifest exists, the archive metadata chunk is present, and that
   all chunks referencing files (items) in the archive exist. This requires
   reading archive and file metadata, but not data. To scan for archives whose
   entries were lost from the archive directory, pass ``--find-lost-archives``.
   It requires reading all data and is hence very time-consuming.
   To additionally cryptographically verify the file (content) data integrity,
   pass ``--verify-data``, which is even more time-consuming.

   When checking archives of a remote repository, archive checks run on the client
   machine because they require decrypting data and therefore the encryption key.

Both steps can also be run independently. Pass ``--repository-only`` to run the
repository checks only, or pass ``--archives-only`` to run the archive checks
only.

The ``--max-age`` option makes the check reuse the results of previous
repository checks: packs whose intact result is younger than the given
timespan (e.g. ``--max-age=4w`` or ``--max-age=12m``) are skipped, spreading
the verification cost over repeated checks. The timespan uses the same markers
as ``--older``/``--newer``: ``d``, ``w``, ``H``, ``M``, ``S`` are exact spans,
while ``m`` and ``y`` are calendar units counted from now (so ``12m`` equals
``1y``). Check results are recorded in any case; ``--max-age`` only controls
their reuse. Packs recorded corrupt are always re-verified. ``--max-age``
affects only the repository check and cannot be combined with
``--archives-only`` or ``--repair``.

The ``--max-duration`` option splits a long-running repository check into
several partial checks. After the given number of seconds, the check is
interrupted. A partial check verifies the least-recently-checked packs first,
so repeated runs cover the whole repository. Add ``--max-age`` to also skip
packs whose result is still younger than the given age: once every pack has a
recent result, further runs re-check each pack at most once per ``--max-age``,
and no faster than the per-run budget allows.
Assuming a complete check would take 7 hours, running a daily check with
``--max-duration=3600 --max-age=1w`` (1 hour) results in one full repository
verification per week. Partial repository checks run neither archive checks
nor repair mode, so ``--max-duration`` requires ``--repository-only`` and
cannot be combined with ``--archives-only`` or ``--repair``.

**Warning:** Please note that partial repository checks (i.e., running with
``--max-duration``) can only perform non-cryptographic checksum checks on the
repository files. Enabling partial repository checks excludes archive checks
for the same reason. Therefore, partial checks may be useful only with very large
repositories where a full check would take too long.

The ``--verify-data`` option will perform a full integrity verification of data,
which means reading the data from the repository, decrypting and decompressing it.
It is a complete cryptographic verification and hence very time-consuming, but
will detect any accidental and malicious corruption. Tamper-resistance is only
guaranteed for encrypted repositories against attackers without access to the keys.
You cannot use ``--verify-data`` with ``--repository-only``.

``--verify-data`` also always verifies that each chunk's content matches its chunk id,
which normal reads do not do by default (see ``BORG_ASSERT_ID``). Running it periodically
is therefore recommended.

The ``--find-lost-archives`` option will also scan the whole repository, but
tells Borg to search for lost archive metadata. If Borg encounters any archive
metadata that does not match an archive directory entry (including
soft-deleted archives), it means that an entry was lost.
Unless ``borg compact`` is called, these archives can be fully restored with
``--repair``. Please note that ``--find-lost-archives`` must read a lot of
data from the repository and is thus very time-consuming. You cannot use
``--find-lost-archives`` with ``--repository-only``.

You can influence how the archive part of the ``Analyzing archive ...`` output is
formatted by giving a custom format using ``--format`` (see the ``borg repo-list``
description for more details about the format string).

If the ``borg check`` process receives a SIGINT signal (Ctrl-C), it stops at the
next safe boundary, leaving the repository and its chunk index in a consistent state.
The repository check stops after the current pack; ``--verify-data`` and
``--find-lost-archives`` stop after the current chunk; a ``--repair`` archive check
stops between whole archives. Results recorded before the interrupt are kept, so a later
check does not re-verify those packs until they are due again. With ``--repair``, an
interrupted archive check may leave some archives already repaired and others not yet
processed, so run ``borg check --repair`` again to finish.

During a ``--repair`` run, the archive check first rebuilds the chunk index from the
packs, and, if the key must be recovered, scans chunks for it. These phases do not yet
respond to SIGINT, so on a large repository a Ctrl-C during them may appear to have no
effect until they finish.

Unreadable repository objects
+++++++++++++++++++++++++++++

A repository object that cannot be read at all (an I/O error from a failing disk, a
flaky network filesystem, ...) is different from a corrupt one: Borg never saw its
content, so it cannot tell whether the object is fine. Such an object is reported and
the check continues, so one run lists everything that is affected; the check then
fails. The object is not remembered as corrupt, so a later check verifies it again.

Because the data may well be readable again once the underlying problem is fixed,
``--repair`` refuses to repair while there are unreadable objects, and
``--verify-data`` leaves chunks it could not read in place instead of deleting them.
Fix the storage hardware, filesystem or network first, then run the check again.

Only ``borg check`` goes on like this. Other commands stop with the read error rather
than work with a partially readable repository - e.g. ``borg prune`` would otherwise
see an archive whose metadata it could not read as undated and thus as the oldest one.

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
not mean recovering lost data: Borg cannot magically restore data lost due to
e.g. a hardware failure. Repairing a repository means sacrificing some data
for the sake of the repository as a whole and the remaining data. Hence it is,
by definition, a potentially lossy task.

In practice, repair mode hooks into both the repository and archive checks:

1. When checking the repository's consistency, repair mode rebuilds the repository
   index from the packs if the index is corrupt, provided every pack is intact. If
   any pack is corrupt, the repository check leaves the index and the packs untouched
   and reports the corruption; salvaging a corrupt pack's still-intact objects is not
   implemented yet (refs #8572).

2. When checking the consistency and correctness of archives, repair mode might
   remove whole archives from the manifest if their archive metadata chunk is
   corrupt or lost. Borg will also report files that reference missing chunks.

If ``--repair --find-lost-archives`` is given, previously lost entries will
be recreated in the archive directory. This is only possible before
``borg compact`` would remove the archives' data completely.
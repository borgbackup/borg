.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_analyze:

borg analyze
------------
.. code-block:: none

    borg [common options] analyze [options]

.. only:: html

    .. class:: borg-options-table

    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                                                                                              |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--by-name``                                | decompose the whole repository by archive name (not combinable with archive filters)                                        |
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
        --by-name     decompose the whole repository by archive name (not combinable with archive filters)


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

Analyze the archives matching the usual archive selection options (e.g. ``-a series_name``).

**Deduplicated size of a set of archives**

For the considered (matching) set of archives, ``borg analyze`` reports the *source*
(uncompressed source data) and *stored* (compressed, as stored in the repository) size,
plus the *compression* factor relating the two (stored / source):

- the *deduplicated size of the set*: the summed size of the union of chunks the
  considered archives reference (chunks shared *within* the set are counted once);
- the *exclusive size of the set*: the summed size of chunks referenced *only* by the
  considered set and by no other archive - i.e. the space that deleting the whole set
  would free (assuming the other archives stay).

Additionally, the *unreferenced chunks* are reported: chunks in the repository that no
non-deleted archive references, i.e. what ``borg compact`` could free in the current
state of the repository. Only their stored size is known - a chunk's source size is
only recorded in the archives that reference it. Note that chunks belonging to
soft-deleted archives count as unreferenced here, although ``borg compact`` keeps them
when the repository is damaged (so ``borg undelete`` stays possible).

If no archive filter is given, all archives are considered - every referenced chunk is
then trivially exclusive to them, so only the repository-wide deduplicated size is shown.

The stored sizes come from the repository's chunk index; the chunk membership and the
source sizes come from the per-archive references cache that ``borg compact``
maintains, so unchanged archives usually do not need to be opened.

**Decomposition by archive name (--by-name)**

With ``--by-name``, the whole repository is decomposed by archive name instead. Archives
sharing a name form a series, so a name usually groups all backups of one source; for
old-style archives that do not form a series, each name is just one archive.

Every chunk is counted in exactly one row, so the rows add up to the repository's
deduplicated size:

- one row per archive name, showing what is *exclusive* to it: no archive of another name
  references these chunks, so deleting all archives of that name would free them;
- one row for the chunks shared by two or more names;
- one row for the unreferenced chunks (see above).

This answers "which name costs how much, and what would I get back by dropping it" for
all names at once, in a single pass over the archives. As the shared and unreferenced
rows can only be determined by looking at every archive, ``--by-name`` always covers the
whole repository and cannot be combined with archive filters.

**Hot spots**

If at least two archives match, ``borg analyze`` additionally iterates over all matching
archives, over all contained files, and collects information about chunks stored in all
directories it encounters. It considers chunk IDs and their plaintext sizes and adds up
the sizes of added and removed chunks per direct parent directory, and outputs a list of
"directory: size".

You can use that list to find directories with a lot of "activity" — maybe some of these
are temporary or cache directories you forgot to exclude. To avoid including these unwanted
directories in your backups, you can carefully exclude them in ``borg create`` (for future
backups) or use ``borg recreate`` to recreate existing archives without them.
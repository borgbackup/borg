.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_recreate:

borg recreate
-------------
.. code-block:: none

    borg [common options] recreate [options] [PATH...]

.. only:: html

    .. class:: borg-options-table

    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **positional arguments**                                                                                                                                                                                                                                                                                                            |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``PATH``                                          | paths to recreate; patterns are supported                                                                                                                                                         |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                                                                                                                                                                         |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--list``                                        | output verbose list of items (files, dirs, ...)                                                                                                                                                   |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--filter STATUSCHARS``                          | only display items with the given status characters (listed in borg create --help)                                                                                                                |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-n``, ``--dry-run``                             | do not change anything                                                                                                                                                                            |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-s``, ``--stats``                               | print statistics at end                                                                                                                                                                           |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                                                                                                                      |
    |                                                                                                                                                                                                                                                                                                                                     |
    | :ref:`common_options`                                                                                                                                                                                                                                                                                                               |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **Include/Exclude options**                                                                                                                                                                                                                                                                                                         |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-e PATTERN``, ``--exclude PATTERN``             | exclude paths matching PATTERN                                                                                                                                                                    |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--exclude-from EXCLUDEFILE``                    | read exclude patterns from EXCLUDEFILE, one per line                                                                                                                                              |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--pattern PATTERN``                             | include/exclude paths matching PATTERN                                                                                                                                                            |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--patterns-from PATTERNFILE``                   | read include/exclude patterns from PATTERNFILE, one per line                                                                                                                                      |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--exclude-caches``                              | exclude directories that contain a CACHEDIR.TAG file (http://www.bford.info/cachedir/spec.html)                                                                                                   |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--exclude-if-present NAME``                     | exclude directories that are tagged by containing a filesystem object with the given NAME                                                                                                         |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--keep-exclude-tags``                           | if tag objects are specified with ``--exclude-if-present``, don't omit the tag objects themselves from the backup archive                                                                         |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **Archive filters** — Archive filters can be applied to repository targets.                                                                                                                                                                                                                                                         |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-a PATTERN``, ``--match-archives PATTERN``      | only consider archives matching all patterns. see "borg help match-archives".                                                                                                                     |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--sort-by KEYS``                                | Comma-separated list of sorting keys; valid keys are: timestamp, archive, name, id, tags, host, user; default is: timestamp                                                                       |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--first N``                                     | consider first N archives after other filters were applied                                                                                                                                        |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--last N``                                      | consider last N archives after other filters were applied                                                                                                                                         |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--oldest TIMESPAN``                             | consider archives between the oldest archive's timestamp and (oldest + TIMESPAN), e.g. 7d or 12m.                                                                                                 |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--newest TIMESPAN``                             | consider archives between the newest archive's timestamp and (newest - TIMESPAN), e.g. 7d or 12m.                                                                                                 |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--older TIMESPAN``                              | consider archives older than (now - TIMESPAN), e.g. 7d or 12m.                                                                                                                                    |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--newer TIMESPAN``                              | consider archives newer than (now - TIMESPAN), e.g. 7d or 12m.                                                                                                                                    |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--target TARGET``                               | create a new archive with the name ARCHIVE, do not replace existing archive                                                                                                                       |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--comment COMMENT``                             | add a comment text to the archive                                                                                                                                                                 |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--timestamp TIMESTAMP``                         | manually specify the archive creation date/time (yyyy-mm-ddThh:mm:ss[(+|-)HH:MM] format, (+|-)HH:MM is the UTC offset, default: local time zone). Alternatively, give a reference file/directory. |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-C COMPRESSION``, ``--compression COMPRESSION`` | select compression algorithm, see the output of the "borg help compression" command for details.                                                                                                  |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--chunker-params PARAMS``                       | rechunk using given chunker parameters (ALGO, CHUNK_MIN_EXP, CHUNK_MAX_EXP, HASH_MASK_BITS, HASH_WINDOW_SIZE) or `default` to use the chunker defaults. default: do not rechunk                   |
    +-----------------------------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    PATH
        paths to recreate; patterns are supported


    options
        --list          output verbose list of items (files, dirs, ...)
        --filter STATUSCHARS    only display items with the given status characters (listed in borg create --help)
        -n, --dry-run    do not change anything
        -s, --stats     print statistics at end


    :ref:`common_options`
        |

    Include/Exclude options
        -e PATTERN, --exclude PATTERN     exclude paths matching PATTERN
        --exclude-from EXCLUDEFILE        read exclude patterns from EXCLUDEFILE, one per line
        --pattern PATTERN                 include/exclude paths matching PATTERN
        --patterns-from PATTERNFILE       read include/exclude patterns from PATTERNFILE, one per line
        --exclude-caches                  exclude directories that contain a CACHEDIR.TAG file (http://www.bford.info/cachedir/spec.html)
        --exclude-if-present NAME         exclude directories that are tagged by containing a filesystem object with the given NAME
        --keep-exclude-tags               if tag objects are specified with ``--exclude-if-present``, don't omit the tag objects themselves from the backup archive


    Archive filters
        -a PATTERN, --match-archives PATTERN     only consider archives matching all patterns. see "borg help match-archives".
        --sort-by KEYS                           Comma-separated list of sorting keys; valid keys are: timestamp, archive, name, id, tags, host, user; default is: timestamp
        --first N                                consider first N archives after other filters were applied
        --last N                                 consider last N archives after other filters were applied
        --oldest TIMESPAN                        consider archives between the oldest archive's timestamp and (oldest + TIMESPAN), e.g. 7d or 12m.
        --newest TIMESPAN                        consider archives between the newest archive's timestamp and (newest - TIMESPAN), e.g. 7d or 12m.
        --older TIMESPAN                         consider archives older than (now - TIMESPAN), e.g. 7d or 12m.
        --newer TIMESPAN                         consider archives newer than (now - TIMESPAN), e.g. 7d or 12m.
        --target TARGET                          create a new archive with the name ARCHIVE, do not replace existing archive
        --comment COMMENT                        add a comment text to the archive
        --timestamp TIMESTAMP                    manually specify the archive creation date/time (yyyy-mm-ddThh:mm:ss[(+|-)HH:MM] format, (+|-)HH:MM is the UTC offset, default: local time zone). Alternatively, give a reference file/directory.
        -C COMPRESSION, --compression COMPRESSION    select compression algorithm, see the output of the "borg help compression" command for details.
        --chunker-params PARAMS                  rechunk using given chunker parameters (ALGO, CHUNK_MIN_EXP, CHUNK_MAX_EXP, HASH_MASK_BITS, HASH_WINDOW_SIZE) or `default` to use the chunker defaults. default: do not rechunk


Description
~~~~~~~~~~~

Recreate the contents of existing archives.

recreate is a potentially dangerous function and might lead to data loss
(if used wrongly). BE VERY CAREFUL!

Important: Repository disk space is **not** freed until you run ``borg compact``.

``--exclude``, ``--exclude-from``, ``--exclude-if-present``, ``--keep-exclude-tags``
and PATH have the exact same semantics as in "borg create", but they only check
for files in the archives and not in the local file system. If PATHs are specified,
the resulting archives will only contain files from these PATHs.

Note that all paths in an archive are relative, therefore absolute patterns/paths
will *not* match (``--exclude``, ``--exclude-from``, PATHs).

``--chunker-params`` will re-chunk all files in the archive, this can be
used to have upgraded Borg 0.xx archives deduplicate with Borg 1.x archives.

**USE WITH CAUTION.**
Depending on the PATHs and patterns given, recreate can be used to
delete files from archives permanently.
When in doubt, use ``--dry-run --verbose --list`` to see how patterns/PATHS are
interpreted. See :ref:`list_item_flags` in ``borg create`` for details.

The archive being recreated is only removed after the operation completes. The
archive that is built during the operation exists at the same time at
"<ARCHIVE>.recreate". The new archive will have a different archive ID.

With ``--target`` the original archive is not replaced, instead a new archive is created.

When rechunking, space usage can be substantial - expect
at least the entire deduplicated size of the archives using the previous
chunker params.

If your most recent borg check found missing chunks, please first run another
backup for the same data, before doing any rechunking. If you are lucky, that
will re-create the missing chunks. Optionally, do another borg check, to see
if the chunks are still missing).
.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_diff:

borg diff
---------
.. code-block:: none

    borg [common options] diff [options] REPO::ARCHIVE1 ARCHIVE2 [PATH...]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------+
    | **positional arguments**                                                                                                                                                                                                                  |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``REPO::ARCHIVE1``                    | repository location and ARCHIVE1 name                                                                                                     |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``ARCHIVE2``                          | ARCHIVE2 name (no repository location allowed)                                                                                            |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``PATH``                              | paths of items inside the archives to compare; patterns are supported                                                                     |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                                                                               |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--numeric-owner``                   | deprecated, use ``--numeric-ids`` instead                                                                                                 |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--numeric-ids``                     | only consider numeric user and group identifiers                                                                                          |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--same-chunker-params``             | Override check of chunker parameters.                                                                                                     |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--sort``                            | Sort the output by path (deprecated, use --sort-by=path).                                                                                 |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--sort-by FIELD[,FIELD...]``        | Advanced sorting: specify field(s) to sort by. Accepts a comma-separated list. Prefix with > for descending or < for ascending (default). |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--content-only``                    | Only compare differences in content (exclude metadata differences)                                                                        |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--json-lines``                      | Format output as JSON Lines.                                                                                                              |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                            |
    |                                                                                                                                                                                                                                           |
    | :ref:`common_options`                                                                                                                                                                                                                     |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------+
    | **Include/Exclude options**                                                                                                                                                                                                               |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``-e PATTERN``, ``--exclude PATTERN`` | exclude paths matching PATTERN                                                                                                            |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--exclude-from EXCLUDEFILE``        | read exclude patterns from EXCLUDEFILE, one per line                                                                                      |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--pattern PATTERN``                 | include/exclude paths matching PATTERN                                                                                                    |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--patterns-from PATTERNFILE``       | read include/exclude patterns from PATTERNFILE, one per line                                                                              |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    REPO::ARCHIVE1
        repository location and ARCHIVE1 name
    ARCHIVE2
        ARCHIVE2 name (no repository location allowed)
    PATH
        paths of items inside the archives to compare; patterns are supported


    options
        --numeric-owner                deprecated, use ``--numeric-ids`` instead
        --numeric-ids                  only consider numeric user and group identifiers
        --same-chunker-params          Override check of chunker parameters.
        --sort                         Sort the output by path (deprecated, use --sort-by=path).
        --sort-by FIELD[,FIELD...]     Advanced sorting: specify field(s) to sort by. Accepts a comma-separated list. Prefix with > for descending or < for ascending (default).
        --content-only                 Only compare differences in content (exclude metadata differences)
        --json-lines                   Format output as JSON Lines. 


    :ref:`common_options`
        |

    Include/Exclude options
        -e PATTERN, --exclude PATTERN     exclude paths matching PATTERN
        --exclude-from EXCLUDEFILE        read exclude patterns from EXCLUDEFILE, one per line
        --pattern PATTERN                 include/exclude paths matching PATTERN
        --patterns-from PATTERNFILE       read include/exclude patterns from PATTERNFILE, one per line


Description
~~~~~~~~~~~

This command finds differences (file contents, user/group/mode) between archives.

A repository location and an archive name must be specified for REPO::ARCHIVE1.
ARCHIVE2 is just another archive name in the same repository (no repository location
allowed).

What is compared
+++++++++++++++++
For each matching item in both archives, Borg reports:

- Content changes: total added/removed bytes within files. If chunker parameters are comparable,
  Borg compares chunk IDs quickly; otherwise, it compares the content.
- Metadata changes: user, group, mode, and other metadata shown inline like
  "[old_mode -> new_mode]" for mode changes. Use ``--content-only`` to suppress metadata changes.
- Added/removed items: printed as "added SIZE path" or "removed SIZE path".

Output formats
++++++++++++++
The default (text) output shows one line per changed path, e.g.::

    +135 B    -252 B [ -rw-r--r-- -> -rwxr-xr-x ] path/to/file

JSON Lines output (``--json-lines``) prints one JSON object per changed path, e.g.::

    {"path": "PATH", "changes": [
        {"type": "modified", "added": BYTES, "removed": BYTES},
        {"type": "mode", "old_mode": "-rw-r--r--", "new_mode": "-rwxr-xr-x"},
        {"type": "added", "size": SIZE},
        {"type": "removed", "size": SIZE}
    ]}

Only actual changes are included in the "changes" list. For example, a modified entry with
added=0 and removed=0 is omitted.

Sorting
++++++++
Use ``--sort-by FIELDS`` where FIELDS is a comma-separated list of fields.
Sorts are applied stably from last to first in the given list. Prepend ">" for
descending, "<" (or no prefix) for ascending, for example ``--sort-by=">size_added,path"``.
Supported fields include:

- path: the item path
- size_added: total bytes added for the item content
- size_removed: total bytes removed for the item content
- size_diff: size_added - size_removed (net content change)
- size: size of the item as stored in ARCHIVE2 (0 for removed items)
- user, group, uid, gid, ctime, mtime: taken from the item state in ARCHIVE2 when present
- ctime_diff, mtime_diff: timestamp difference (archive2 - archive1)

The ``--sort`` option is deprecated and only sorts by path.

Performance considerations
++++++++++++++++++++++++++
For archives created with Borg 1.1 or newer, diff automatically detects whether
the archives were created with the same chunker parameters. If so, only chunk IDs
are compared, which is very fast.

For archives prior to Borg 1.1, chunk contents are compared by default.
If you did not create the archives with different chunker parameters,
pass ``--same-chunker-params``.
Note that the chunker parameters changed from Borg 0.xx to 1.0.

For more help on include/exclude patterns, see the :ref:`borg_patterns` command output.
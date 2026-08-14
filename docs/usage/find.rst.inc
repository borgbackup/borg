.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_find:

borg find
---------
.. code-block:: none

    borg [common options] find [options] [PATH...]

.. only:: html

    .. class:: borg-options-table

    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **positional arguments**                                                                                                                                                                                                                                                                                           |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``PATH``                                     | paths to find; patterns are supported                                                                                                                                                 |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                                                                                                                                                        |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--format FORMAT``                          | specify format for file listing (default: "{archiveid:.8} {archivename} {mode} {user:6} {group:6} {size:8} {mtime} {path}{extra}{NL}")                                                |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--json-lines``                             | Format output as JSON Lines. The form of ``--format`` is ignored, but keys used in it are added to the JSON output. Some keys are always present. Note: JSON can only represent text. |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                                                                                                     |
    |                                                                                                                                                                                                                                                                                                                    |
    | :ref:`common_options`                                                                                                                                                                                                                                                                                              |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **Archive filters** — Archive filters can be applied to repository targets.                                                                                                                                                                                                                                        |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-a PATTERN``, ``--match-archives PATTERN`` | only consider archives matching all patterns. See "borg help match-archives".                                                                                                         |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--sort-by KEYS``                           | Comma-separated list of sorting keys; valid keys are: timestamp, archive, name, id, tags, host, user; default is: timestamp                                                           |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--first N``                                | consider the first N archives after other filters are applied                                                                                                                         |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--last N``                                 | consider the last N archives after other filters are applied                                                                                                                          |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--oldest TIMESPAN``                        | consider archives between the oldest archive's timestamp and (oldest + TIMESPAN), e.g., 7d or 12m.                                                                                    |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--newest TIMESPAN``                        | consider archives between the newest archive's timestamp and (newest - TIMESPAN), e.g., 7d or 12m.                                                                                    |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--older TIMESPAN``                         | consider archives older than (now - TIMESPAN), e.g., 7d or 12m.                                                                                                                       |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--newer TIMESPAN``                         | consider archives newer than (now - TIMESPAN), e.g., 7d or 12m.                                                                                                                       |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **Include/Exclude options**                                                                                                                                                                                                                                                                                        |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-e PATTERN``, ``--exclude PATTERN``        | exclude paths matching PATTERN                                                                                                                                                        |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--exclude-from EXCLUDEFILE``               | read exclude patterns from EXCLUDEFILE, one per line                                                                                                                                  |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--pattern PATTERN``                        | include/exclude paths matching PATTERN                                                                                                                                                |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--patterns-from PATTERNFILE``              | read include/exclude patterns from PATTERNFILE, one per line                                                                                                                          |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    PATH
        paths to find; patterns are supported


    options
        --format FORMAT    specify format for file listing (default: "{archiveid:.8} {archivename} {mode} {user:6} {group:6} {size:8} {mtime} {path}{extra}{NL}")
        --json-lines     Format output as JSON Lines. The form of ``--format`` is ignored, but keys used in it are added to the JSON output. Some keys are always present. Note: JSON can only represent text.


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


    Include/Exclude options
        -e PATTERN, --exclude PATTERN     exclude paths matching PATTERN
        --exclude-from EXCLUDEFILE        read exclude patterns from EXCLUDEFILE, one per line
        --pattern PATTERN                 include/exclude paths matching PATTERN
        --patterns-from PATTERNFILE       read include/exclude patterns from PATTERNFILE, one per line


Description
~~~~~~~~~~~

This command finds files matching the given paths or patterns in the archives
selected by the usual archive filter options (all archives, if no filters are
given). It iterates over the matching archives from newest to oldest, over all
items of each archive, and outputs one line per match, like ``borg list``, but
prefixed with a short archive ID and the archive name. As the archives of a
series all share the same name, only the archive ID uniquely identifies the
archive.

This makes it easy to answer questions like "which archives contain this file?"
or "where did that file end up?"::

    $ borg find home/user/file.txt          # in which archives is this file?
    $ borg find 'sh:**/*.jpg' --last 3      # all jpg files in the last 3 archives

The given PATHs match like in ``borg list`` or ``borg extract``: a plain path
matches the item with that path as well as everything below it, and the pattern
styles (``fm:``, ``sh:``, ``re:``, ``pp:``, ``pf:``) are supported as well.
For more help on include/exclude patterns, see the output of :ref:`borg_patterns`.

Note: there is no extra index for the file paths, so this command reads the
metadata of all selected archives, which may take a while for many/big archives.

.. man NOTES

The FORMAT specifier syntax
+++++++++++++++++++++++++++

The ``--format`` option uses Python's `format string syntax
<https://docs.python.org/3.11/library/string.html#formatstrings>`_.

Examples:
::

    # only print the archive and the path, nothing else
    $ borg find --format '{archiveid:.8} {archivename} {path}{NL}' 'sh:**/*.jpg'
    20e70e3a photos photos/paris/eiffel.jpg
    ...

{archiveid:.8} prints a short archive ID (use {archiveid} for the full ID),
{archivename} the archive name (the archives of a series all share the name).

The following keys are always available:
- NEWLINE: OS dependent line separator
- NL: alias of NEWLINE
- NUL: NUL character for creating print0 / xargs -0 like output
- SPACE: space character
- TAB: tab character
- CR: carriage return character
- LF: line feed character


Keys available only when finding files in an archive:

- type: file type (file, dir, symlink, ...)
- mode: file mode (as in stat)
- uid: user id of file owner
- gid: group id of file owner
- user: user name of file owner
- group: group name of file owner
- path: file path
- target: link target for symlinks
- hlid: hard link identity (same if hardlinking same fs object)
- inode: inode number
- flags: file flags

- size: file size
- num_chunks: number of chunks in this file

- mtime: file modification time
- ctime: file change time
- atime: file access time
- isomtime: file modification time (ISO 8601 format)
- isoctime: file change time (ISO 8601 format)
- isoatime: file access time (ISO 8601 format)

- fingerprint: Fingerprint of the file content (may have false negatives), format: H(conditions)-H(chunk_ids)
- blake2b
- blake2s
- blake3
- md5
- sha1
- sha224
- sha256
- sha384
- sha3_224
- sha3_256
- sha3_384
- sha3_512
- sha512

- archiveid: internal ID of the archive
- archivename: name of the archive
- extra: prepends {target} with " -> " for soft links and " link to " for hard links

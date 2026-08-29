.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_diff:

borg diff
---------
.. code-block:: none

    borg [common options] diff [options] ARCHIVE1 ARCHIVE2 [PATH...]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+---------------------------------------+----------------------------------------------------------------------------------+
    | **positional arguments**                                                                                                                                                         |
    +-------------------------------------------------------+---------------------------------------+----------------------------------------------------------------------------------+
    |                                                       | ``ARCHIVE1``                          | ARCHIVE1 name                                                                    |
    +-------------------------------------------------------+---------------------------------------+----------------------------------------------------------------------------------+
    |                                                       | ``ARCHIVE2``                          | ARCHIVE2 name                                                                    |
    +-------------------------------------------------------+---------------------------------------+----------------------------------------------------------------------------------+
    |                                                       | ``PATH``                              | paths of items inside the archives to compare; patterns are supported.           |
    +-------------------------------------------------------+---------------------------------------+----------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                      |
    +-------------------------------------------------------+---------------------------------------+----------------------------------------------------------------------------------+
    |                                                       | ``--numeric-ids``                     | only consider numeric user and group identifiers                                 |
    +-------------------------------------------------------+---------------------------------------+----------------------------------------------------------------------------------+
    |                                                       | ``--same-chunker-params``             | override the check of chunker parameters                                         |
    +-------------------------------------------------------+---------------------------------------+----------------------------------------------------------------------------------+
    |                                                       | ``--format FORMAT``                   | specify format for differences between archives (default: "{change} {path}{NL}") |
    +-------------------------------------------------------+---------------------------------------+----------------------------------------------------------------------------------+
    |                                                       | ``--json-lines``                      | Format output as JSON Lines.                                                     |
    +-------------------------------------------------------+---------------------------------------+----------------------------------------------------------------------------------+
    |                                                       | ``--sort-by``                         | Sort output by comma-separated fields (e.g., '>size_added,path').                |
    +-------------------------------------------------------+---------------------------------------+----------------------------------------------------------------------------------+
    |                                                       | ``--content-only``                    | Only compare differences in content (exclude metadata differences)               |
    +-------------------------------------------------------+---------------------------------------+----------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                   |
    |                                                                                                                                                                                  |
    | :ref:`common_options`                                                                                                                                                            |
    +-------------------------------------------------------+---------------------------------------+----------------------------------------------------------------------------------+
    | **Include/Exclude options**                                                                                                                                                      |
    +-------------------------------------------------------+---------------------------------------+----------------------------------------------------------------------------------+
    |                                                       | ``-e PATTERN``, ``--exclude PATTERN`` | exclude paths matching PATTERN                                                   |
    +-------------------------------------------------------+---------------------------------------+----------------------------------------------------------------------------------+
    |                                                       | ``--exclude-from EXCLUDEFILE``        | read exclude patterns from EXCLUDEFILE, one per line                             |
    +-------------------------------------------------------+---------------------------------------+----------------------------------------------------------------------------------+
    |                                                       | ``--pattern PATTERN``                 | include/exclude paths matching PATTERN                                           |
    +-------------------------------------------------------+---------------------------------------+----------------------------------------------------------------------------------+
    |                                                       | ``--patterns-from PATTERNFILE``       | read include/exclude patterns from PATTERNFILE, one per line                     |
    +-------------------------------------------------------+---------------------------------------+----------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    ARCHIVE1
        ARCHIVE1 name
    ARCHIVE2
        ARCHIVE2 name
    PATH
        paths of items inside the archives to compare; patterns are supported.


    options
        --numeric-ids    only consider numeric user and group identifiers
        --same-chunker-params    override the check of chunker parameters
        --format FORMAT    specify format for differences between archives (default: "{change} {path}{NL}")
        --json-lines    Format output as JSON Lines.
        --sort-by     Sort output by comma-separated fields (e.g., '>size_added,path').
        --content-only    Only compare differences in content (exclude metadata differences)


    :ref:`common_options`
        |

    Include/Exclude options
        -e PATTERN, --exclude PATTERN     exclude paths matching PATTERN
        --exclude-from EXCLUDEFILE        read exclude patterns from EXCLUDEFILE, one per line
        --pattern PATTERN                 include/exclude paths matching PATTERN
        --patterns-from PATTERNFILE       read include/exclude patterns from PATTERNFILE, one per line


Description
~~~~~~~~~~~

This command finds differences (file contents, metadata) between ARCHIVE1 and ARCHIVE2.

For more help on include/exclude patterns, see the output of the :ref:`borg_patterns` command.

.. man NOTES

The FORMAT specifier syntax
+++++++++++++++++++++++++++

The ``--format`` option uses Python's `format string syntax
<https://docs.python.org/3.11/library/string.html#formatstrings>`_.

Examples:
::

    $ borg diff --format '{content:30} {path}{NL}' ArchiveFoo ArchiveBar
    modified:  +4.1 kB  -1.0 kB    file-diff
    ...

    # {VAR:<NUMBER} - pad to NUMBER columns left-aligned.
    # {VAR:>NUMBER} - pad to NUMBER columns right-aligned.
    $ borg diff --format '{content:>30} {path}{NL}' ArchiveFoo ArchiveBar
       modified:  +4.1 kB  -1.0 kB file-diff
    ...

The following keys are always available:

- NEWLINE: OS dependent line separator
- NL: alias of NEWLINE
- NUL: NUL character for creating print0 / xargs -0 like output
- SPACE: space character
- TAB: tab character
- CR: carriage return character
- LF: line feed character


Keys available only when showing differences between archives:

- path: archived file path
- change: all available changes

- content: file content change
- mode: file mode change
- type: file type change
- owner: file owner (user/group) change
- group: file group change
- user: file user change

- link: file link change
- directory: file directory change
- blkdev: file block device change
- chrdev: file character device change
- fifo: file fifo change

- mtime: file modification time change
- ctime: file change time change
- isomtime: file modification time change (ISO 8601)
- isoctime: file creation time change (ISO 8601)


What is compared
+++++++++++++++++
For each matching item in both archives, Borg reports:

- Content changes: total added/removed bytes within files. If chunker parameters are comparable,
  Borg compares chunk IDs quickly; otherwise, it compares the content. In the latter case, borg
  can only tell that a file was modified, not by how much: no byte counts are given for it, the
  text output shows "modified:  (can't get size)" instead.
- Metadata changes: user, group, mode, and other metadata shown inline as "[old -> new]", like
  "[-rw-r--r-- -> -rwxr-xr-x]" for a mode change. Use ``--content-only`` to suppress metadata changes.
- Added/removed items: printed as "added: SIZE path" or "removed: SIZE path".

Output formats
++++++++++++++
The default (text) output shows one line per changed path, e.g.::

    modified:    +23 B     -5 B [-rwxr-xr-x -> -rw-r--r--] path/to/file
    added:                  4 B path/to/added-file
    removed:                5 B path/to/removed-file

JSON Lines output (``--json-lines``) prints one JSON object per changed path, with a list of
change objects. Each change object has a "type" plus type-specific data: content changes
("added", "removed", "modified") carry "added"/"removed" byte counts - except for a
"modified" that was determined by comparing the content, which carries no counts at all;
metadata changes ("changed mode", "changed owner", "mtime", ...) carry the old and new
values as "item1" and "item2". Example::

    {"changes": [{"added": 23, "removed": 5, "type": "modified"}], "path": "path/to/file"}
    {"changes": [{"type": "modified"}], "path": "path/to/other-file"}
    {"changes": [{"item1": "-rw-r--r--", "item2": "-rwxr-xr-x", "type": "changed mode"}], "path": "some/file"}
    {"changes": [{"added": 4, "removed": 0, "type": "added"}], "path": "path/to/added-file"}
    {"changes": [{"added": 0, "removed": 5, "type": "removed"}], "path": "path/to/removed-file"}

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
- ctime_diff, mtime_diff: timestamp difference (ARCHIVE2 - ARCHIVE1)

Performance considerations
++++++++++++++++++++++++++
diff automatically detects whether the archives were created with the same chunker
parameters. If so, only chunk IDs are compared, which is very fast.
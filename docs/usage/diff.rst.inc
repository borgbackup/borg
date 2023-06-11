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
    |                                                       | ``PATH``                              | paths of items inside the archives to compare; patterns are supported            |
    +-------------------------------------------------------+---------------------------------------+----------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                      |
    +-------------------------------------------------------+---------------------------------------+----------------------------------------------------------------------------------+
    |                                                       | ``--numeric-ids``                     | only consider numeric user and group identifiers                                 |
    +-------------------------------------------------------+---------------------------------------+----------------------------------------------------------------------------------+
    |                                                       | ``--same-chunker-params``             | Override check of chunker parameters.                                            |
    +-------------------------------------------------------+---------------------------------------+----------------------------------------------------------------------------------+
    |                                                       | ``--sort``                            | Sort the output lines by file path.                                              |
    +-------------------------------------------------------+---------------------------------------+----------------------------------------------------------------------------------+
    |                                                       | ``--format FORMAT``                   | specify format for differences between archives (default: "{change} {path}{NL}") |
    +-------------------------------------------------------+---------------------------------------+----------------------------------------------------------------------------------+
    |                                                       | ``--json-lines``                      | Format output as JSON Lines.                                                     |
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
        paths of items inside the archives to compare; patterns are supported


    options
        --numeric-ids    only consider numeric user and group identifiers
        --same-chunker-params    Override check of chunker parameters.
        --sort     Sort the output lines by file path.
        --format FORMAT    specify format for differences between archives (default: "{change} {path}{NL}")
        --json-lines    Format output as JSON Lines. 
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

For more help on include/exclude patterns, see the :ref:`borg_patterns` command output.

.. man NOTES

The FORMAT specifier syntax
+++++++++++++++++++++++++++

The ``--format`` option uses python's `format string syntax
<https://docs.python.org/3.9/library/string.html#formatstrings>`_.

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

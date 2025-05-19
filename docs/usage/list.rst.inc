.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_list:

borg list
---------
.. code-block:: none

    borg [common options] list [options] NAME [PATH...]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **positional arguments**                                                                                                                                                                                                                                                              |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``NAME``                              | specify the archive name                                                                                                                                                              |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``PATH``                              | paths to list; patterns are supported                                                                                                                                                 |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                                                                                                                           |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--short``                           | only print file/directory names, nothing else                                                                                                                                         |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--format FORMAT``                   | specify format for file listing (default: "{mode} {user:6} {group:6} {size:8} {mtime} {path}{extra}{NL}")                                                                             |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--json-lines``                      | Format output as JSON Lines. The form of ``--format`` is ignored, but keys used in it are added to the JSON output. Some keys are always present. Note: JSON can only represent text. |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--depth N``                         | only list files up to the specified directory level depth                                                                                                                             |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                                                                        |
    |                                                                                                                                                                                                                                                                                       |
    | :ref:`common_options`                                                                                                                                                                                                                                                                 |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **Include/Exclude options**                                                                                                                                                                                                                                                           |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``-e PATTERN``, ``--exclude PATTERN`` | exclude paths matching PATTERN                                                                                                                                                        |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--exclude-from EXCLUDEFILE``        | read exclude patterns from EXCLUDEFILE, one per line                                                                                                                                  |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--pattern PATTERN``                 | include/exclude paths matching PATTERN                                                                                                                                                |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--patterns-from PATTERNFILE``       | read include/exclude patterns from PATTERNFILE, one per line                                                                                                                          |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    NAME
        specify the archive name
    PATH
        paths to list; patterns are supported


    options
        --short     only print file/directory names, nothing else
        --format FORMAT    specify format for file listing (default: "{mode} {user:6} {group:6} {size:8} {mtime} {path}{extra}{NL}")
        --json-lines    Format output as JSON Lines. The form of ``--format`` is ignored, but keys used in it are added to the JSON output. Some keys are always present. Note: JSON can only represent text.
        --depth N    only list files up to the specified directory level depth


    :ref:`common_options`
        |

    Include/Exclude options
        -e PATTERN, --exclude PATTERN     exclude paths matching PATTERN
        --exclude-from EXCLUDEFILE        read exclude patterns from EXCLUDEFILE, one per line
        --pattern PATTERN                 include/exclude paths matching PATTERN
        --patterns-from PATTERNFILE       read include/exclude patterns from PATTERNFILE, one per line


Description
~~~~~~~~~~~

This command lists the contents of an archive.

For more help on include/exclude patterns, see the :ref:`borg_patterns` command output.

.. man NOTES

The FORMAT specifier syntax
+++++++++++++++++++++++++++

The ``--format`` option uses python's `format string syntax
<https://docs.python.org/3.9/library/string.html#formatstrings>`_.

Examples:
::

    $ borg list --format '{mode} {user:6} {group:6} {size:8} {mtime} {path}{extra}{NL}' ArchiveFoo
    -rw-rw-r-- user   user       1024 Thu, 2021-12-09 10:22:17 file-foo
    ...

    # {VAR:<NUMBER} - pad to NUMBER columns left-aligned.
    # {VAR:>NUMBER} - pad to NUMBER columns right-aligned.
    $ borg list --format '{mode} {user:>6} {group:>6} {size:<8} {mtime} {path}{extra}{NL}' ArchiveFoo
    -rw-rw-r--   user   user 1024     Thu, 2021-12-09 10:22:17 file-foo
    ...

The following keys are always available:

- NEWLINE: OS dependent line separator
- NL: alias of NEWLINE
- NUL: NUL character for creating print0 / xargs -0 like output
- SPACE: space character
- TAB: tab character
- CR: carriage return character
- LF: line feed character


Keys available only when listing files in an archive:

- type: file type (file, dir, symlink, ...)
- mode: file mode (as in stat)
- uid: user id of file owner
- gid: group id of file owner
- user: user name of file owner
- group: group name of file owner
- path: file path
- target: link target for symlinks
- hlid: hard link identity (same if hardlinking same fs object)
- flags: file flags

- size: file size
- num_chunks: number of chunks in this file

- mtime: file modification time
- ctime: file change time
- atime: file access time
- isomtime: file modification time (ISO 8601 format)
- isoctime: file change time (ISO 8601 format)
- isoatime: file access time (ISO 8601 format)

- blake2b
- blake2s
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
- xxh64: XXH64 checksum of this file (note: this is NOT a cryptographic hash!)

- archiveid: internal ID of the archive
- archivename: name of the archive
- extra: prepends {target} with " -> " for soft links and " link to " for hard links

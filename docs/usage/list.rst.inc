.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_list:

borg list
---------
.. code-block:: none

    borg [common options] list [options] NAME [PATH...]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **positional arguments**                                                                                                                                                                                                                                                                                                        |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``NAME``                              | specify the archive name                                                                                                                                                                                                        |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``PATH``                              | paths to list; patterns are supported                                                                                                                                                                                           |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **optional arguments**                                                                                                                                                                                                                                                                                                          |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--short``                           | only print file/directory names, nothing else                                                                                                                                                                                   |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--format FORMAT``                   | specify format for file listing (default: "{mode} {user:6} {group:6} {size:8} {mtime} {path}{extra}{NL}")                                                                                                                       |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--json-lines``                      | Format output as JSON Lines. The form of ``--format`` is ignored, but keys used in it are added to the JSON output. Some keys are always present. Note: JSON can only represent text. A "bpath" key is therefore not available. |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                                                                                                                  |
    |                                                                                                                                                                                                                                                                                                                                 |
    | :ref:`common_options`                                                                                                                                                                                                                                                                                                           |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **Exclusion options**                                                                                                                                                                                                                                                                                                           |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``-e PATTERN``, ``--exclude PATTERN`` | exclude paths matching PATTERN                                                                                                                                                                                                  |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--exclude-from EXCLUDEFILE``        | read exclude patterns from EXCLUDEFILE, one per line                                                                                                                                                                            |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--pattern PATTERN``                 | include/exclude paths matching PATTERN                                                                                                                                                                                          |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--patterns-from PATTERNFILE``       | read include/exclude patterns from PATTERNFILE, one per line                                                                                                                                                                    |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

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


    optional arguments
        --short     only print file/directory names, nothing else
        --format FORMAT    specify format for file listing (default: "{mode} {user:6} {group:6} {size:8} {mtime} {path}{extra}{NL}")
        --json-lines    Format output as JSON Lines. The form of ``--format`` is ignored, but keys used in it are added to the JSON output. Some keys are always present. Note: JSON can only represent text. A "bpath" key is therefore not available.


    :ref:`common_options`
        |

    Exclusion options
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
- NUL: NUL character for creating print0 / xargs -0 like output, see barchive and bpath keys below
- SPACE
- TAB
- CR
- LF

Keys available only when listing files in an archive:

- type
- mode
- uid
- gid
- user
- group
- path: path interpreted as text (might be missing non-text characters, see bpath)
- bpath: verbatim POSIX path, can contain any character except NUL
- source: link target for symlinks (identical to linktarget)
- linktarget
- hlid: hard link identity (same if hardlinking same fs object)
- flags

- size
- dsize: deduplicated size
- num_chunks: number of chunks in this file
- unique_chunks: number of unique chunks in this file

- mtime
- ctime
- atime
- isomtime
- isoctime
- isoatime

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

- archiveid
- archivename
- extra: prepends {source} with " -> " for soft links and " link to " for hard links

- health: either "healthy" (file ok) or "broken" (if file has all-zero replacement chunks)

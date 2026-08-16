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
    |                                                       | ``--depth N``                         | only list files up to the specified directory depth                                                                                                                                   |
    +-------------------------------------------------------+---------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--sort-by SPEC``                    | sort output by comma-separated fields (e.g. '>size,path'), see Sorting below                                                                                                          |
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
        --short            only print file/directory names, nothing else
        --format FORMAT    specify format for file listing (default: "{mode} {user:6} {group:6} {size:8} {mtime} {path}{extra}{NL}")
        --json-lines       Format output as JSON Lines. The form of ``--format`` is ignored, but keys used in it are added to the JSON output. Some keys are always present. Note: JSON can only represent text.
        --depth N          only list files up to the specified directory depth
        --sort-by SPEC     sort output by comma-separated fields (e.g. '>size,path'), see Sorting below


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

For more help on include/exclude patterns, see the output of :ref:`borg_patterns`.

.. man NOTES

The FORMAT specifier syntax
+++++++++++++++++++++++++++

The ``--format`` option uses Python's `format string syntax
<https://docs.python.org/3.11/library/string.html#formatstrings>`_.

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


Sorting
+++++++
Use ``--sort-by SPEC`` where SPEC is a comma-separated list of fields.
Sorts are applied stably from last to first in the given list, thus the first
field is the primary sort criterion. Prepend ">" for descending, "<" (or no
prefix) for ascending order, e.g. ``--sort-by='>size,path'`` (quote it, ">" is
a shell redirection).

Supported fields, sorting by the same value that ``--format`` would print:

- path: the item path
- type, mode: the file type character resp. the full file mode string
- user, group: the owner/group name, or the numeric id if the name is not known
- uid, gid: the numeric owner/group id
- size: the file size (same as {size}, 0 for items without content)
- mtime, ctime, atime: the timestamps (atime/ctime fall back to mtime if not stored)

There is no ``birthtime`` field, as there is no {birthtime} format key either.

The sort fields are independent of ``--format``, you may sort by a field you do
not print.

Note: ``--sort-by`` needs to read all (matching) items into memory before it can
print anything, so listing a huge archive this way needs a lot of memory and
delays the first output line. Without ``--sort-by``, items are streamed and their
order is undefined. If memory usage is a problem, consider
``borg list --format ... | sort`` instead.

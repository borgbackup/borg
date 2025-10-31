.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_list:

borg list
---------
.. code-block:: none

    borg [common options] list [options] [REPOSITORY_OR_ARCHIVE] [PATH...]

.. only:: html

    .. class:: borg-options-table

    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **positional arguments**                                                                                                                                                                                                                                                                                                                                                                       |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``REPOSITORY_OR_ARCHIVE``             | repository or archive to list contents of                                                                                                                                                                                                                                |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``PATH``                              | paths to list; patterns are supported                                                                                                                                                                                                                                    |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                                                                                                                                                                                                                                    |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--consider-checkpoints``            | Show checkpoint archives in the repository contents list (default: hidden).                                                                                                                                                                                              |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--short``                           | only print file/directory names, nothing else                                                                                                                                                                                                                            |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--format FORMAT``                   | specify format for file or archive listing (default for files: "{mode} {user:6} {group:6} {size:8} {mtime} {path}{extra}{NL}"; for archives: "{archive:<36} {time} [{id}]{NL}")                                                                                          |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--json``                            | Only valid for listing repository contents. Format output as JSON. The form of ``--format`` is ignored, but keys used in it are added to the JSON output. Some keys are always present. Note: JSON can only represent text. A "barchive" key is therefore not available. |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--json-lines``                      | Only valid for listing archive contents. Format output as JSON Lines. The form of ``--format`` is ignored, but keys used in it are added to the JSON output. Some keys are always present. Note: JSON can only represent text. A "bpath" key is therefore not available. |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                                                                                                                                                                                 |
    |                                                                                                                                                                                                                                                                                                                                                                                                |
    | :ref:`common_options`                                                                                                                                                                                                                                                                                                                                                                          |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **Archive filters** — Archive filters can be applied to repository targets.                                                                                                                                                                                                                                                                                                                    |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-P PREFIX``, ``--prefix PREFIX``    | only consider archive names starting with this prefix. (deprecated)                                                                                                                                                                                                      |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-a GLOB``, ``--glob-archives GLOB`` | only consider archive names matching the glob. sh: rules apply (without actually using the sh: prefix), see "borg help patterns".                                                                                                                                        |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--sort-by KEYS``                    | Comma-separated list of sorting keys; valid keys are: timestamp, archive, name, id; default is: timestamp                                                                                                                                                                |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--first N``                         | consider first N archives after other filters were applied                                                                                                                                                                                                               |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--last N``                          | consider last N archives after other filters were applied                                                                                                                                                                                                                |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **Include/Exclude options**                                                                                                                                                                                                                                                                                                                                                                    |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-e PATTERN``, ``--exclude PATTERN`` | exclude paths matching PATTERN                                                                                                                                                                                                                                           |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--exclude-from EXCLUDEFILE``        | read exclude patterns from EXCLUDEFILE, one per line                                                                                                                                                                                                                     |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--pattern PATTERN``                 | include/exclude paths matching PATTERN                                                                                                                                                                                                                                   |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--patterns-from PATTERNFILE``       | read include/exclude patterns from PATTERNFILE, one per line                                                                                                                                                                                                             |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    REPOSITORY_OR_ARCHIVE
        repository or archive to list contents of
    PATH
        paths to list; patterns are supported


    options
        --consider-checkpoints    Show checkpoint archives in the repository contents list (default: hidden).
        --short     only print file/directory names, nothing else
        --format FORMAT    specify format for file or archive listing (default for files: "{mode} {user:6} {group:6} {size:8} {mtime} {path}{extra}{NL}"; for archives: "{archive:<36} {time} [{id}]{NL}")
        --json      Only valid for listing repository contents. Format output as JSON. The form of ``--format`` is ignored, but keys used in it are added to the JSON output. Some keys are always present. Note: JSON can only represent text. A "barchive" key is therefore not available.
        --json-lines    Only valid for listing archive contents. Format output as JSON Lines. The form of ``--format`` is ignored, but keys used in it are added to the JSON output. Some keys are always present. Note: JSON can only represent text. A "bpath" key is therefore not available.


    :ref:`common_options`
        |

    Archive filters
        -P PREFIX, --prefix PREFIX        only consider archive names starting with this prefix. (deprecated)
        -a GLOB, --glob-archives GLOB     only consider archive names matching the glob. sh: rules apply (without actually using the sh: prefix), see "borg help patterns".
        --sort-by KEYS                    Comma-separated list of sorting keys; valid keys are: timestamp, archive, name, id; default is: timestamp
        --first N                         consider first N archives after other filters were applied
        --last N                          consider last N archives after other filters were applied


    Include/Exclude options
        -e PATTERN, --exclude PATTERN     exclude paths matching PATTERN
        --exclude-from EXCLUDEFILE        read exclude patterns from EXCLUDEFILE, one per line
        --pattern PATTERN                 include/exclude paths matching PATTERN
        --patterns-from PATTERNFILE       read include/exclude patterns from PATTERNFILE, one per line


Description
~~~~~~~~~~~

This command lists the contents of a repository or an archive.

For more help on include/exclude patterns, see the :ref:`borg_patterns` command output.

.. man NOTES

The FORMAT specifier syntax
+++++++++++++++++++++++++++

The ``--format`` option uses Python's `format string syntax
<https://docs.python.org/3.9/library/string.html#formatstrings>`_.

Examples:
::

    $ borg list --format '{archive}{NL}' /path/to/repo
    ArchiveFoo
    ArchiveBar
    ...

    # {VAR:NUMBER} - pad to NUMBER columns.
    # Strings are left-aligned, numbers are right-aligned.
    # Note: time columns except ``isomtime``, ``isoctime`` and ``isoatime`` cannot be padded.
    $ borg list --format '{archive:36} {time} [{id}]{NL}' /path/to/repo
    ArchiveFoo                           Thu, 2021-12-09 10:22:28 [0b8e9a312bef3f2f6e2d0fc110c196827786c15eba0188738e81697a7fa3b274]
    $ borg list --format '{mode} {user:6} {group:6} {size:8} {mtime} {path}{extra}{NL}' /path/to/repo::ArchiveFoo
    -rw-rw-r-- user   user       1024 Thu, 2021-12-09 10:22:17 file-foo
    ...

    # {VAR:<NUMBER} - pad to NUMBER columns left-aligned.
    # {VAR:>NUMBER} - pad to NUMBER columns right-aligned.
    $ borg list --format '{mode} {user:>6} {group:>6} {size:<8} {mtime} {path}{extra}{NL}' /path/to/repo::ArchiveFoo
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

Keys available only when listing archives in a repository:

- archive: archive name interpreted as text (might be missing non-text characters, see barchive)
- name: alias of "archive"
- barchive: verbatim archive name, can contain any character except NUL
- comment: archive comment interpreted as text (might be missing non-text characters, see bcomment)
- bcomment: verbatim archive comment, can contain any character except NUL
- id: internal ID of the archive
- tam: TAM authentication state of this archive

- start: time (start) of creation of the archive
- time: alias of "start"
- end: time (end) of creation of the archive
- command_line: command line which was used to create the archive

- hostname: hostname of host on which this archive was created
- username: username of user who created this archive


Keys available only when listing files in an archive:

- type
- mode
- uid
- gid
- user
- group
- path: path interpreted as text (might be missing non-text characters, see bpath)
- bpath: verbatim POSIX path, can contain any character except NUL
- source: link target for links (identical to linktarget)
- linktarget
- flags

- size
- csize: compressed size
- dsize: deduplicated size
- dcsize: deduplicated compressed size
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

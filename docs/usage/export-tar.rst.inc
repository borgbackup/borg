.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_export-tar:

borg export-tar
---------------
.. code-block:: none

    borg [common options] export-tar [options] NAME FILE [PATH...]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
    | **positional arguments**                                                                                                                                                                                          |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``NAME``                              | specify the archive name                                                                                          |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``FILE``                              | output tar file. "-" to write to stdout instead.                                                                  |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``PATH``                              | paths to extract; patterns are supported                                                                          |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                                                       |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--tar-filter``                      | filter program to pipe data through                                                                               |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--list``                            | output verbose list of items (files, dirs, ...)                                                                   |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--tar-format FMT``                  | select tar format: BORG, PAX or GNU                                                                               |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--sparse``                          | write sparse tar members (GNU sparse format 1.0) for files containing all-zero chunks (BORG and PAX formats only) |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                    |
    |                                                                                                                                                                                                                   |
    | :ref:`common_options`                                                                                                                                                                                             |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
    | **Include/Exclude options**                                                                                                                                                                                       |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``-e PATTERN``, ``--exclude PATTERN`` | exclude paths matching PATTERN                                                                                    |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--exclude-from EXCLUDEFILE``        | read exclude patterns from EXCLUDEFILE, one per line                                                              |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--pattern PATTERN``                 | include/exclude paths matching PATTERN                                                                            |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--patterns-from PATTERNFILE``       | read include/exclude patterns from PATTERNFILE, one per line                                                      |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--strip-components NUMBER``         | Remove the specified number of leading path elements. Paths with fewer elements will be silently skipped.         |
    +-------------------------------------------------------+---------------------------------------+-------------------------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    NAME
        specify the archive name
    FILE
        output tar file. "-" to write to stdout instead.
    PATH
        paths to extract; patterns are supported


    options
        --tar-filter         filter program to pipe data through
        --list               output verbose list of items (files, dirs, ...)
        --tar-format FMT     select tar format: BORG, PAX or GNU
        --sparse             write sparse tar members (GNU sparse format 1.0) for files containing all-zero chunks (BORG and PAX formats only)


    :ref:`common_options`
        |

    Include/Exclude options
        -e PATTERN, --exclude PATTERN     exclude paths matching PATTERN
        --exclude-from EXCLUDEFILE        read exclude patterns from EXCLUDEFILE, one per line
        --pattern PATTERN                 include/exclude paths matching PATTERN
        --patterns-from PATTERNFILE       read include/exclude patterns from PATTERNFILE, one per line
        --strip-components NUMBER         Remove the specified number of leading path elements. Paths with fewer elements will be silently skipped.


Description
~~~~~~~~~~~

This command creates a tarball from an archive.

When giving '-' as the output FILE, Borg will write a tar stream to standard output.

By default (``--tar-filter=auto``) Borg will detect whether the FILE should be compressed
based on its file extension and pipe the tarball through an appropriate filter
before writing it to FILE:

- .tar.gz or .tgz: gzip
- .tar.bz2 or .tbz: bzip2
- .tar.xz or .txz: xz
- .tar.zstd, .tar.zst or .tzst: zstd (in-process, level 3)
- .tar.lz4: lz4

For zstd, Borg compresses in-process using libzstd instead of piping through an
external program (set BORG_ZSTD_MT_WORKERS to use multiple compression threads).
The other formats are piped through the respective external filter program.

Alternatively, a ``--tar-filter`` program may be explicitly specified. It should
read the uncompressed tar stream from stdin and write a compressed/filtered
tar stream to stdout.

Depending on the ``--tar-format`` option, these formats are created:

+--------------+---------------------------+----------------------------+
| --tar-format | Specification             | Metadata                   |
+--------------+---------------------------+----------------------------+
| BORG         | BORG specific, like PAX   | all as supported by borg   |
+--------------+---------------------------+----------------------------+
| PAX          | POSIX.1-2001 (pax) format | GNU + atime/ctime/mtime ns |
|              |                           | + xattrs                   |
+--------------+---------------------------+----------------------------+
| GNU          | GNU tar format            | mtime s, no atime/ctime,   |
|              |                           | no ACLs/xattrs/bsdflags    |
+--------------+---------------------------+----------------------------+

With ``--sparse``, files whose content contains runs of all-zero chunks are written
as sparse tar members (GNU sparse format 1.0, as GNU tar creates it in POSIX mode),
storing only a hole map and the non-zero data. This requires ``--tar-format BORG``
or ``PAX``. Such tarballs can be much smaller for sparse files (e.g. disk images)
and extract to sparse files again with GNU tar's or bsdtar's sparse support
(as well as with ``borg import-tar`` / ``borg extract --sparse``).
Notes: hole detection works at the granularity of borg's content chunks (it does not
depend on the original file having been a sparse file - but some short or unaligned
zero runs may be stored literally); sparse-unaware tar implementations will extract
a member as ``GNUSparseFile.0/<name>`` containing the raw hole map and data (the
same caveat applies to tarballs created by GNU tar); for members needing >= 8 GiB
of stored (non-hole) data, the stored size is base-256 encoded in the tar header
(the GNU/star encoding of big numbers, understood by GNU tar, libarchive/bsdtar
and python) - logical file sizes are unlimited anyway.

By default the entire archive is extracted but a subset of files and directories
can be selected by passing a list of ``PATHs`` as arguments.
The file selection can further be restricted by using the ``--exclude`` option.

For more help on include/exclude patterns, see the :ref:`borg_patterns` command output.

``--progress`` can be slower than no progress display, since it makes one additional
pass over the archive metadata.
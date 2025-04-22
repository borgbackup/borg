.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_import-tar:

borg import-tar
---------------
.. code-block:: none

    borg [common options] import-tar [options] NAME TARFILE

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **positional arguments**                                                                                                                                                                                                                                                                                      |
    +-------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``NAME``                                          | specify the archive name                                                                                                                                                                          |
    +-------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``TARFILE``                                       | input tar file. "-" to read from stdin instead.                                                                                                                                                   |
    +-------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                                                                                                                                                   |
    +-------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--tar-filter``                                  | filter program to pipe data through                                                                                                                                                               |
    +-------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``-s``, ``--stats``                               | print statistics for the created archive                                                                                                                                                          |
    +-------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--list``                                        | output verbose list of items (files, dirs, ...)                                                                                                                                                   |
    +-------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--filter STATUSCHARS``                          | only display items with the given status characters                                                                                                                                               |
    +-------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--json``                                        | output stats as JSON (implies --stats)                                                                                                                                                            |
    +-------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--ignore-zeros``                                | ignore zero-filled blocks in the input tarball                                                                                                                                                    |
    +-------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                                                                                                |
    |                                                                                                                                                                                                                                                                                                               |
    | :ref:`common_options`                                                                                                                                                                                                                                                                                         |
    +-------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **Archive options**                                                                                                                                                                                                                                                                                           |
    +-------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--comment COMMENT``                             | add a comment text to the archive                                                                                                                                                                 |
    +-------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--timestamp TIMESTAMP``                         | manually specify the archive creation date/time (yyyy-mm-ddThh:mm:ss[(+|-)HH:MM] format, (+|-)HH:MM is the UTC offset, default: local time zone). Alternatively, give a reference file/directory. |
    +-------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--chunker-params PARAMS``                       | specify the chunker parameters (ALGO, CHUNK_MIN_EXP, CHUNK_MAX_EXP, HASH_MASK_BITS, HASH_WINDOW_SIZE). default: buzhash,19,23,21,4095                                                             |
    +-------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``-C COMPRESSION``, ``--compression COMPRESSION`` | select compression algorithm, see the output of the "borg help compression" command for details.                                                                                                  |
    +-------------------------------------------------------+---------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    NAME
        specify the archive name
    TARFILE
        input tar file. "-" to read from stdin instead.


    options
        --tar-filter    filter program to pipe data through
        -s, --stats     print statistics for the created archive
        --list          output verbose list of items (files, dirs, ...)
        --filter STATUSCHARS    only display items with the given status characters
        --json          output stats as JSON (implies --stats)
        --ignore-zeros    ignore zero-filled blocks in the input tarball


    :ref:`common_options`
        |

    Archive options
        --comment COMMENT                             add a comment text to the archive
        --timestamp TIMESTAMP                         manually specify the archive creation date/time (yyyy-mm-ddThh:mm:ss[(+|-)HH:MM] format, (+|-)HH:MM is the UTC offset, default: local time zone). Alternatively, give a reference file/directory.
        --chunker-params PARAMS                       specify the chunker parameters (ALGO, CHUNK_MIN_EXP, CHUNK_MAX_EXP, HASH_MASK_BITS, HASH_WINDOW_SIZE). default: buzhash,19,23,21,4095
        -C COMPRESSION, --compression COMPRESSION     select compression algorithm, see the output of the "borg help compression" command for details.


Description
~~~~~~~~~~~

This command creates a backup archive from a tarball.

When giving '-' as path, Borg will read a tar stream from standard input.

By default (--tar-filter=auto) Borg will detect whether the file is compressed
based on its file extension and pipe the file through an appropriate filter:

- .tar.gz or .tgz: gzip -d
- .tar.bz2 or .tbz: bzip2 -d
- .tar.xz or .txz: xz -d
- .tar.zstd or .tar.zst: zstd -d
- .tar.lz4: lz4 -d

Alternatively, a --tar-filter program may be explicitly specified. It should
read compressed data from stdin and output an uncompressed tar stream on
stdout.

Most documentation of borg create applies. Note that this command does not
support excluding files.

A ``--sparse`` option (as found in borg create) is not supported.

About tar formats and metadata conservation or loss, please see ``borg export-tar``.

import-tar reads these tar formats:

- BORG: borg specific (PAX-based)
- PAX: POSIX.1-2001
- GNU: GNU tar
- POSIX.1-1988 (ustar)
- UNIX V7 tar
- SunOS tar with extended attributes

To import multiple tarballs into a single archive, they can be simply
concatenated (e.g. using "cat") into a single file, and imported with an
``--ignore-zeros`` option to skip through the stop markers between them.
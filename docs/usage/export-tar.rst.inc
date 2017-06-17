.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_export-tar:

borg export-tar
---------------
.. code-block:: none

    borg [common options] export-tar [options] ARCHIVE FILE PATH

positional arguments
    ARCHIVE
        archive to export
    FILE
        output tar file. "-" to write to stdout instead.
    PATH
        paths to extract; patterns are supported

optional arguments
    ``--tar-filter``
        | filter program to pipe data through
    ``--list``
        | output verbose list of items (files, dirs, ...)
    ``-e PATTERN``, ``--exclude PATTERN``
        | exclude paths matching PATTERN
    ``--exclude-from EXCLUDEFILE``
        | read exclude patterns from EXCLUDEFILE, one per line
    ``--pattern PATTERN``
        | experimental: include/exclude paths matching PATTERN
    ``--patterns-from PATTERNFILE``
        | experimental: read include/exclude patterns from PATTERNFILE, one per line
    ``--strip-components NUMBER``
        | Remove the specified number of leading path elements. Pathnames with fewer elements will be silently skipped.

:ref:`common_options`
    |

Description
~~~~~~~~~~~

This command creates a tarball from an archive.

When giving '-' as the output FILE, Borg will write a tar stream to standard output.

By default (``--tar-filter=auto``) Borg will detect whether the FILE should be compressed
based on its file extension and pipe the tarball through an appropriate filter
before writing it to FILE:

- .tar.gz: gzip
- .tar.bz2: bzip2
- .tar.xz: xz

Alternatively a ``--tar-filter`` program may be explicitly specified. It should
read the uncompressed tar stream from stdin and write a compressed/filtered
tar stream to stdout.

The generated tarball uses the GNU tar format.

export-tar is a lossy conversion:
BSD flags, ACLs, extended attributes (xattrs), atime and ctime are not exported.
Timestamp resolution is limited to whole seconds, not the nanosecond resolution
otherwise supported by Borg.

A ``--sparse`` option (as found in borg extract) is not supported.

By default the entire archive is extracted but a subset of files and directories
can be selected by passing a list of ``PATHs`` as arguments.
The file selection can further be restricted by using the ``--exclude`` option.

See the output of the "borg help patterns" command for more help on exclude patterns.

``--progress`` can be slower than no progress display, since it makes one additional
pass over the archive metadata.
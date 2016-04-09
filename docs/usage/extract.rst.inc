.. _borg_extract:

borg extract
------------
::

    borg extract <options> ARCHIVE PATH

positional arguments
    ARCHIVE
        archive to extract
    PATH
        paths to extract; patterns are supported

optional arguments
    ``--list``
        | output verbose list of items (files, dirs, ...)
    ``-n``, ``--dry-run``
        | do not actually change any files
    ``-e PATTERN``, ``--exclude PATTERN``
        | exclude paths matching PATTERN
    ``--exclude-from EXCLUDEFILE``
        | read exclude patterns from EXCLUDEFILE, one per line
    ``--numeric-owner``
        | only obey numeric user and group identifiers
    ``--strip-components NUMBER``
        | Remove the specified number of leading path elements. Pathnames with fewer elements will be silently skipped.
    ``--stdout``
        | write all extracted data to stdout
    ``--sparse``
        | create holes in output sparse file from all-zero chunks

`Common options`_
    |

Description
~~~~~~~~~~~

This command extracts the contents of an archive. By default the entire
archive is extracted but a subset of files and directories can be selected
by passing a list of ``PATHs`` as arguments. The file selection can further
be restricted by using the ``--exclude`` option.

See the output of the "borg help patterns" command for more help on exclude patterns.

.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_extract:

borg extract
------------
.. code-block:: none

    borg [common options] extract [options] NAME [PATH...]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **positional arguments**                                                                                                                                                                                                                                                                |
    +-------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``NAME``                              | specify the archive name                                                                                                                                                                |
    +-------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``PATH``                              | paths to extract; patterns are supported                                                                                                                                                |
    +-------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                                                                                                                             |
    +-------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--list``                            | output a verbose list of items (files, dirs, ...)                                                                                                                                       |
    +-------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``-s``, ``--stats``                   | print store statistics for the extraction                                                                                                                                               |
    +-------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``-n``, ``--dry-run``                 | do not actually change any files                                                                                                                                                        |
    +-------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--numeric-ids``                     | only use numeric user and group identifiers                                                                                                                                             |
    +-------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--noflags``                         | do not extract/set flags (e.g. NODUMP, IMMUTABLE)                                                                                                                                       |
    +-------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--noacls``                          | do not extract/set ACLs                                                                                                                                                                 |
    +-------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--noxattrs``                        | do not extract/set xattrs                                                                                                                                                               |
    +-------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--stdout``                          | write all extracted data to stdout                                                                                                                                                      |
    +-------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--sparse``                          | create holes in the output sparse file from all-zero chunks                                                                                                                             |
    +-------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--continue``                        | extract into a non-empty directory, e.g. to continue a previously interrupted extraction of the same archive: skip files that are fully extracted already, replace other existing files |
    +-------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                                                                          |
    |                                                                                                                                                                                                                                                                                         |
    | :ref:`common_options`                                                                                                                                                                                                                                                                   |
    +-------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **Include/Exclude options**                                                                                                                                                                                                                                                             |
    +-------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``-e PATTERN``, ``--exclude PATTERN`` | exclude paths matching PATTERN                                                                                                                                                          |
    +-------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--exclude-from EXCLUDEFILE``        | read exclude patterns from EXCLUDEFILE, one per line                                                                                                                                    |
    +-------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--pattern PATTERN``                 | include/exclude paths matching PATTERN                                                                                                                                                  |
    +-------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--patterns-from PATTERNFILE``       | read include/exclude patterns from PATTERNFILE, one per line                                                                                                                            |
    +-------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--strip-components NUMBER``         | Remove the specified number of leading path elements. Paths with fewer elements will be silently skipped.                                                                               |
    +-------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

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
        paths to extract; patterns are supported


    options
        --list          output a verbose list of items (files, dirs, ...)
        -s, --stats     print store statistics for the extraction
        -n, --dry-run    do not actually change any files
        --numeric-ids    only use numeric user and group identifiers
        --noflags       do not extract/set flags (e.g. NODUMP, IMMUTABLE)
        --noacls        do not extract/set ACLs
        --noxattrs      do not extract/set xattrs
        --stdout        write all extracted data to stdout
        --sparse        create holes in the output sparse file from all-zero chunks
        --continue      extract into a non-empty directory, e.g. to continue a previously interrupted extraction of the same archive: skip files that are fully extracted already, replace other existing files


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

This command extracts the contents of an archive.

By default, the entire archive is extracted, but a subset of files and directories
can be selected by passing a list of ``PATH`` arguments. The default interpretation
for the paths to extract is `pp:` which is a literal path-prefix match. If you want
to use e.g. a wildcard, you must select a different pattern style such as `sh:` or
`fm:`. See :ref:`borg_patterns` for more information.

The file selection can be further restricted by using the ``--exclude`` option.
For more help on include/exclude patterns, see the :ref:`borg_patterns` command output.

By using ``--dry-run``, you can do all extraction steps except actually writing the
output data: reading metadata and data chunks from the repository, checking the hash/HMAC,
decrypting, and decompressing.

``--progress`` can be slower than no progress display, since it makes one additional
pass over the archive metadata.

Extracting into a non-empty directory replaces existing files that are in the way and
leaves all other existing files as they are. The result is a mix of the files that were
there before and the extracted files, which might not be what you want - especially not
by accident in a directory that is in use (e.g. your home directory). Thus, borg refuses
to extract into a non-empty directory unless ``--continue`` is given (``--dry-run`` and
``--stdout`` do not write into the directory, so they always work). The usual way to
restore is to extract into a new, empty directory: after that, the directory has exactly
the contents of the extracted archive (or of the selected part of it).

``--continue`` extracts into a non-empty directory. It is made for continuing a previously
interrupted extraction of the same archive into the same directory: an existing regular
file that has the same type, permissions (mode), size and modification time as the
archived file is considered to be fully extracted already and is skipped. Everything else
is extracted, replacing existing files. Files that are in the directory, but not in the
archive, are left as they are. ``--continue`` is thus also needed to restore files into an
existing directory tree. Note that a file that was damaged without a change of its size
and modification time (e.g. by bit rot) is skipped, not replaced: remove it before
extracting it.

If a file's content chunks are missing from the repository or are corrupted (they fail
authentication, decryption or decompression), the extraction does not abort: each such
chunk is written as all-zero data of the correct size, an error naming the chunk is logged,
the file is reported with a warning and the exit code is a warning. The extracted file thus
has the correct size and metadata, but wrong (all-zero) content where the damaged chunks
were. Run ``borg check`` to find out which chunks and archives are affected. This also
applies to ``--dry-run`` (which thus can be used to find unreadable files) and ``--stdout``.

When using ``--stats``, borg reports the store statistics (lines prefixed with
"Store") for the extraction: per-operation call counts and timings, the load/store
data volumes and throughput, and cache hits/misses. This includes ``--dry-run``
extractions.

.. note::

    Currently, extract always writes into the current working directory ("."),
    so make sure you ``cd`` to the right place before calling ``borg extract``.

    When parent directories are not extracted (because of using file/directory selection
    or any other reason), Borg cannot restore parent directories' metadata, e.g., owner,
    group, permissions, etc.

.. note::

    Restoring some file metadata requires root privileges (or equivalent
    capabilities). This includes the owner and group of files, device nodes,
    privileged file flags (like immutable or append-only) and privileged
    extended attributes (like Linux capabilities or ``trusted.*`` xattrs).

    When running as a normal user, borg still extracts the file contents, but
    the extracted files are owned by the invoking user (the failure to restore
    ownership is silently ignored: no warning, exit code unaffected), privileged
    flags are skipped while the other flags are still set, and privileged xattrs
    and device nodes are skipped with a warning. ``--numeric-ids`` does not
    change this, it only selects whether the archived numeric IDs or the archived
    user/group names are used. To restore all metadata, run ``borg extract`` as root.
.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_borgfs:

borg borgfs
-----------
.. code-block:: none

    borg [common options] borgfs [options] REPOSITORY_OR_ARCHIVE MOUNTPOINT [PATH...]

.. only:: html

    .. class:: borg-options-table

    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **positional arguments**                                                                                                                                                                                                                                                     |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``REPOSITORY_OR_ARCHIVE``             | repository/archive to mount                                                                                                                            |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``MOUNTPOINT``                        | where to mount filesystem                                                                                                                              |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``PATH``                              | paths to extract; patterns are supported                                                                                                               |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **optional arguments**                                                                                                                                                                                                                                                       |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-V``, ``--version``                 | show version number and exit                                                                                                                           |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-f``, ``--foreground``              | stay in foreground, do not daemonize                                                                                                                   |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-o``                                | Extra mount options                                                                                                                                    |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                                                               |
    |                                                                                                                                                                                                                                                                              |
    | :ref:`common_options`                                                                                                                                                                                                                                                        |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **Archive filters** — Archive filters can be applied to repository targets.                                                                                                                                                                                                  |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-P PREFIX``, ``--prefix PREFIX``    | only consider archive names starting with this prefix.                                                                                                 |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-a GLOB``, ``--glob-archives GLOB`` | only consider archive names matching the glob. sh: rules apply, see "borg help patterns". ``--prefix`` and ``--glob-archives`` are mutually exclusive. |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--sort-by KEYS``                    | Comma-separated list of sorting keys; valid keys are: timestamp, name, id; default is: timestamp                                                       |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--first N``                         | consider first N archives after other filters were applied                                                                                             |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--last N``                          | consider last N archives after other filters were applied                                                                                              |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **Exclusion options**                                                                                                                                                                                                                                                        |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-e PATTERN``, ``--exclude PATTERN`` | exclude paths matching PATTERN                                                                                                                         |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--exclude-from EXCLUDEFILE``        | read exclude patterns from EXCLUDEFILE, one per line                                                                                                   |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--pattern PATTERN``                 | experimental: include/exclude paths matching PATTERN                                                                                                   |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--patterns-from PATTERNFILE``       | experimental: read include/exclude patterns from PATTERNFILE, one per line                                                                             |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--strip-components NUMBER``         | Remove the specified number of leading path elements. Paths with fewer elements will be silently skipped.                                              |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    REPOSITORY_OR_ARCHIVE
        repository/archive to mount
    MOUNTPOINT
        where to mount filesystem
    PATH
        paths to extract; patterns are supported


    optional arguments
        -V, --version    show version number and exit
        -f, --foreground    stay in foreground, do not daemonize
        -o     Extra mount options


    :ref:`common_options`
        |

    Archive filters
        -P PREFIX, --prefix PREFIX        only consider archive names starting with this prefix.
        -a GLOB, --glob-archives GLOB     only consider archive names matching the glob. sh: rules apply, see "borg help patterns". ``--prefix`` and ``--glob-archives`` are mutually exclusive.
        --sort-by KEYS                    Comma-separated list of sorting keys; valid keys are: timestamp, name, id; default is: timestamp
        --first N                         consider first N archives after other filters were applied
        --last N                          consider last N archives after other filters were applied


    Exclusion options
        -e PATTERN, --exclude PATTERN     exclude paths matching PATTERN
        --exclude-from EXCLUDEFILE        read exclude patterns from EXCLUDEFILE, one per line
        --pattern PATTERN                 experimental: include/exclude paths matching PATTERN
        --patterns-from PATTERNFILE       experimental: read include/exclude patterns from PATTERNFILE, one per line
        --strip-components NUMBER         Remove the specified number of leading path elements. Paths with fewer elements will be silently skipped.


Description
~~~~~~~~~~~

This command mounts an archive as a FUSE filesystem. This can be useful for
browsing an archive or restoring individual files. Unless the ``--foreground``
option is given the command will run in the background until the filesystem
is ``umounted``.

The command ``borgfs`` provides a wrapper for ``borg mount``. This can also be
used in fstab entries:
``/path/to/repo /mnt/point fuse.borgfs defaults,noauto 0 0``

To allow a regular user to use fstab entries, add the ``user`` option:
``/path/to/repo /mnt/point fuse.borgfs defaults,noauto,user 0 0``

For mount options, see the fuse(8) manual page. Additional mount options
supported by borg:

- versions: when used with a repository mount, this gives a merged, versioned
  view of the files in the archives. EXPERIMENTAL, layout may change in future.
- allow_damaged_files: by default damaged files (where missing chunks were
  replaced with runs of zeros by borg check ``--repair``) are not readable and
  return EIO (I/O error). Set this option to read such files.

The BORG_MOUNT_DATA_CACHE_ENTRIES environment variable is meant for advanced users
to tweak the performance. It sets the number of cached data chunks; additional
memory usage can be up to ~8 MiB times this number. The default is the number
of CPU cores.

When the daemonized process receives a signal or crashes, it does not unmount.
Unmounting in these cases could cause an active rsync or similar process
to unintentionally delete data.

When running in the foreground ^C/SIGINT unmounts cleanly, but other
signals or crashes do not.
.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_mount:

borg mount
----------
.. code-block:: none

    borg [common options] mount [options] REPOSITORY_OR_ARCHIVE MOUNTPOINT [PATH...]

.. only:: html

    .. class:: borg-options-table

    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    | **positional arguments**                                                                                                                                                                                                                                |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``REPOSITORY_OR_ARCHIVE``             | repository or archive to mount                                                                                                    |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``MOUNTPOINT``                        | where to mount filesystem                                                                                                         |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``PATH``                              | paths to extract; patterns are supported                                                                                          |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                                                                                             |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--consider-checkpoints``            | Show checkpoint archives in the repository contents list (default: hidden).                                                       |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-f``, ``--foreground``              | stay in foreground, do not daemonize                                                                                              |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-o``                                | Extra mount options                                                                                                               |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--numeric-owner``                   | deprecated, use ``--numeric-ids`` instead                                                                                         |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--numeric-ids``                     | use numeric user and group identifiers from archive(s)                                                                            |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                                          |
    |                                                                                                                                                                                                                                                         |
    | :ref:`common_options`                                                                                                                                                                                                                                   |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    | **Archive filters** — Archive filters can be applied to repository targets.                                                                                                                                                                             |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-P PREFIX``, ``--prefix PREFIX``    | only consider archive names starting with this prefix. (deprecated)                                                               |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-a GLOB``, ``--glob-archives GLOB`` | only consider archive names matching the glob. sh: rules apply (without actually using the sh: prefix), see "borg help patterns". |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--sort-by KEYS``                    | Comma-separated list of sorting keys; valid keys are: timestamp, archive, name, id; default is: timestamp                         |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--first N``                         | consider first N archives after other filters were applied                                                                        |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--last N``                          | consider last N archives after other filters were applied                                                                         |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    | **Include/Exclude options**                                                                                                                                                                                                                             |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-e PATTERN``, ``--exclude PATTERN`` | exclude paths matching PATTERN                                                                                                    |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--exclude-from EXCLUDEFILE``        | read exclude patterns from EXCLUDEFILE, one per line                                                                              |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--pattern PATTERN``                 | include/exclude paths matching PATTERN                                                                                            |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--patterns-from PATTERNFILE``       | read include/exclude patterns from PATTERNFILE, one per line                                                                      |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--strip-components NUMBER``         | Remove the specified number of leading path elements. Paths with fewer elements will be silently skipped.                         |
    +-----------------------------------------------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    REPOSITORY_OR_ARCHIVE
        repository or archive to mount
    MOUNTPOINT
        where to mount filesystem
    PATH
        paths to extract; patterns are supported


    options
        --consider-checkpoints    Show checkpoint archives in the repository contents list (default: hidden).
        -f, --foreground    stay in foreground, do not daemonize
        -o     Extra mount options
        --numeric-owner    deprecated, use ``--numeric-ids`` instead
        --numeric-ids    use numeric user and group identifiers from archive(s)


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
        --strip-components NUMBER         Remove the specified number of leading path elements. Paths with fewer elements will be silently skipped.


Description
~~~~~~~~~~~

This command mounts a repository or an archive as a FUSE filesystem.
This can be useful for browsing or restoring individual files.

When restoring, take into account that the current FUSE implementation does
not support special filesystem flags and ACLs.

When mounting a repository, the top directories will be named like the
archives and the directory structure below these will be loaded on-demand from
the repository when entering these directories, so expect some delay.

Unless the ``--foreground`` option is given the command will run in the
background until the filesystem is ``unmounted``.

Performance tips:

- when doing a "whole repository" mount:
  do not enter archive directories if not needed; this avoids on-demand loading.
- only mount a specific archive, not the whole repository.
- only mount specific paths in a specific archive, not the complete archive.

The command ``borgfs`` provides a wrapper for ``borg mount``. This can also be
used in fstab entries:
``/path/to/repo /mnt/point fuse.borgfs defaults,noauto 0 0``

To allow a regular user to use fstab entries, add the ``user`` option:
``/path/to/repo /mnt/point fuse.borgfs defaults,noauto,user 0 0``

For FUSE configuration and mount options, see the mount.fuse(8) manual page.

Borg's default behavior is to use the archived user and group names of each
file and map them to the system's respective user and group ids.
Alternatively, using ``numeric-ids`` will instead use the archived user and
group ids without any mapping.

The ``uid`` and ``gid`` mount options (implemented by Borg) can be used to
override the user and group ids of all files (i.e., ``borg mount -o
uid=1000,gid=1000``).

The man page references ``user_id`` and ``group_id`` mount options
(implemented by FUSE) which specify the user and group id of the mount owner
(aka, the user who does the mounting). It is set automatically by libfuse (or
the filesystem if libfuse is not used). However, you should not specify these
manually. Unlike the ``uid`` and ``gid`` mount options which affect all files,
``user_id`` and ``group_id`` affect the user and group id of the mounted
(base) directory.

Additional mount options supported by borg:

- ``versions``: when used with a repository mount, this gives a merged, versioned
  view of the files in the archives. EXPERIMENTAL; the layout may change in the future.
- ``allow_damaged_files``: by default damaged files (where missing chunks were
  replaced with runs of zeros by ``borg check --repair``) are not readable and
  return EIO (I/O error). Set this option to read such files.
- ``ignore_permissions``: for security reasons the ``default_permissions`` mount
  option is internally enforced by borg. ``ignore_permissions`` can be given to
  not enforce ``default_permissions``.

The BORG_MOUNT_DATA_CACHE_ENTRIES environment variable is meant for advanced users
to tweak the performance. It sets the number of cached data chunks; additional
memory usage can be up to ~8 MiB times this number. The default is the number
of CPU cores.

When the daemonized process receives a signal or crashes, it does not unmount.
Unmounting in these cases could cause an active rsync or similar process
to unintentionally delete data.

When running in the foreground, ^C/SIGINT cleanly unmounts the filesystem,
but other signals or crashes do not.

Debugging:

``borg mount`` usually daemonizes and the daemon process sends stdout/stderr
to /dev/null. Thus, you need to either use ``-f / --foreground`` to make it stay
in the foreground and not daemonize, or use ``BORG_LOGGING_CONF`` to reconfigure
the logger to output to a file.
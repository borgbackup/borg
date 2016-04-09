.. _borg_mount:

borg mount
----------
::

    borg mount <options> REPOSITORY_OR_ARCHIVE MOUNTPOINT

positional arguments
    REPOSITORY_OR_ARCHIVE
        repository/archive to mount
    MOUNTPOINT
        where to mount filesystem

optional arguments
    ``-f``, ``--foreground``
        | stay in foreground, do not daemonize
    ``-o``
        | Extra mount options

`Common options`_
    |

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

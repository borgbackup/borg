.. _borg_mount:

borg mount
----------

Mount archive or an entire repository as a FUSE fileystem

Synopsis
--------

::

    borg mount [-h] [-v] [--show-rc] [--no-files-cache] [--umask M]
                      [--remote-path PATH] [-f] [-o OPTIONS]
                      REPOSITORY_OR_ARCHIVE MOUNTPOINT
    
positional arguments
~~~~~~~~~~~~~~~~~~~~
::
      REPOSITORY_OR_ARCHIVE
                            repository/archive to mount
      MOUNTPOINT            where to mount filesystem
    
optional arguments
~~~~~~~~~~~~~~~~~~
::
      -h, --help            show this help message and exit
      -v, --verbose         verbose output
      --show-rc             show/log the return code (rc)
      --no-files-cache      do not load/update the file metadata cache used to
                            detect unchanged files
      --umask M             set umask to M (local and remote, default: 63)
      --remote-path PATH    set remote path to executable (default: "borg")
      -f, --foreground      stay in foreground, do not daemonize
      -o OPTIONS            Extra mount options
    
Description
~~~~~~~~~~~

This command mounts an archive as a FUSE filesystem. This can be useful for
browsing an archive or restoring individual files. Unless the ``--foreground``
option is given the command will run in the background until the filesystem
is ``umounted``.

Examples
~~~~~~~~

::

    $ borg mount /mnt/backup::root-2013-08-02 /tmp/mymountpoint
    $ ls /tmp/mymountpoint
    bin  boot  etc  lib  lib64  mnt  opt  root  sbin  srv  usr  var
    $ fusermount -u /tmp/mymountpoint

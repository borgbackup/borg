.. _borg_mount:

borg mount
----------
::

    usage: borg mount [-h] [--critical] [--error] [--warning] [--info] [--debug]
                      [--lock-wait N] [--show-rc] [--no-files-cache] [--umask M]
                      [--remote-path PATH] [-f] [-o OPTIONS]
                      REPOSITORY_OR_ARCHIVE MOUNTPOINT
    
    Mount archive or an entire repository as a FUSE fileystem
    
    positional arguments:
      REPOSITORY_OR_ARCHIVE
                            repository/archive to mount
      MOUNTPOINT            where to mount filesystem
    
    optional arguments:
      -h, --help            show this help message and exit
      --critical            work on log level CRITICAL
      --error               work on log level ERROR
      --warning             work on log level WARNING (default)
      --info, -v, --verbose
                            work on log level INFO
      --debug               work on log level DEBUG
      --lock-wait N         wait for the lock, but max. N seconds (default: 1).
      --show-rc             show/log the return code (rc)
      --no-files-cache      do not load/update the file metadata cache used to
                            detect unchanged files
      --umask M             set umask to M (local and remote, default: 0077)
      --remote-path PATH    set remote path to executable (default: "borg")
      -f, --foreground      stay in foreground, do not daemonize
      -o OPTIONS            Extra mount options
    
Description
~~~~~~~~~~~

This command mounts an archive as a FUSE filesystem. This can be useful for
browsing an archive or restoring individual files. Unless the ``--foreground``
option is given the command will run in the background until the filesystem
is ``umounted``.

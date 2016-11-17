.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_umount:

borg umount
-----------
::

    usage: borg umount [-h] [--critical] [--error] [--warning] [--info] [--debug]
                       [--lock-wait N] [--show-rc] [--no-files-cache] [--umask M]
                       [--remote-path PATH]
                       MOUNTPOINT
    
    un-mount the FUSE filesystem
    
    positional arguments:
      MOUNTPOINT            mountpoint of the filesystem to umount
    
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
    
Description
~~~~~~~~~~~

This command un-mounts a FUSE filesystem that was mounted with ``borg mount``.

This is a convenience wrapper that just calls the platform-specific shell
command - usually this is either umount or fusermount -u.

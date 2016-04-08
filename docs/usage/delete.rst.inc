.. _borg_delete:

borg delete
-----------
::

    usage: borg delete [-h] [--critical] [--error] [--warning] [--info] [--debug]
                       [--lock-wait N] [--show-rc] [--no-files-cache] [--umask M]
                       [--remote-path PATH] [-p] [-s] [-c] [--save-space]
                       [TARGET]
    
    Delete an existing repository or archive
    
    positional arguments:
      TARGET                archive or repository to delete
    
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
      -p, --progress        show progress display while deleting a single archive
      -s, --stats           print statistics for the deleted archive
      -c, --cache-only      delete only the local cache for the given repository
      --save-space          work slower, but using less space
    
Description
~~~~~~~~~~~

This command deletes an archive from the repository or the complete repository.
Disk space is reclaimed accordingly. If you delete the complete repository, the
local cache for it (if any) is also deleted.

.. _borg_debug-dump-archive-items:

borg debug-dump-archive-items
-----------------------------
::

    usage: borg debug-dump-archive-items [-h] [--critical] [--error] [--warning]
                                         [--info] [--debug] [--lock-wait N]
                                         [--show-rc] [--no-files-cache]
                                         [--umask M] [--remote-path PATH]
                                         ARCHIVE
    
    dump (decrypted, decompressed) archive items metadata (not: data)
    
    positional arguments:
      ARCHIVE               archive to dump
    
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

This command dumps raw (but decrypted and decompressed) archive items (only metadata) to files.

.. _borg_debug-dump-archive-items:

borg debug-dump-archive-items
-----------------------------

dump (decrypted, decompressed) archive items metadata (not: data)

Synopsis
~~~~~~~~

::

    borg debug-dump-archive-items [-h] [-v] [--show-rc] [--no-files-cache]
                                         [--umask M] [--remote-path PATH]
                                         ARCHIVE
    
positional arguments
~~~~~~~~~~~~~~~~~~~~
::
      ARCHIVE             archive to dump
    
optional arguments
~~~~~~~~~~~~~~~~~~
::
      -h, --help          show this help message and exit
      -v, --verbose       verbose output
      --show-rc           show/log the return code (rc)
      --no-files-cache    do not load/update the file metadata cache used to
                          detect unchanged files
      --umask M           set umask to M (local and remote, default: 63)
      --remote-path PATH  set remote path to executable (default: "borg")
    
Description
~~~~~~~~~~~

This command dumps raw (but decrypted and decompressed) archive items (only metadata) to files.

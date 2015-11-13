.. _borg_info:

borg info
---------
::

    usage: borg info [-h] [-v] [--show-rc] [--no-files-cache] [--umask M]
                     [--remote-path PATH]
                     ARCHIVE
    
    Show archive details such as disk space used
    
    positional arguments:
      ARCHIVE             archive to display information about
    
    optional arguments:
      -h, --help          show this help message and exit
      -v, --verbose       verbose output
      --show-rc           show/log the return code (rc)
      --no-files-cache    do not load/update the file metadata cache used to
                          detect unchanged files
      --umask M           set umask to M (local and remote, default: 63)
      --remote-path PATH  set remote path to executable (default: "borg")
    
Description
~~~~~~~~~~~

This command displays some detailed information about the specified archive.

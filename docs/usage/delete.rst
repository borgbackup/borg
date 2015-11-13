.. _borg_delete:

borg delete
-----------

Delete an existing repository or archive

Synopsis
~~~~~~~~

::

    borg delete [-h] [-v] [--show-rc] [--no-files-cache] [--umask M]
                       [--remote-path PATH] [-s] [-c]
                       [TARGET]
    
positional arguments
~~~~~~~~~~~~~~~~~~~~
::
      TARGET              archive or repository to delete
    
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
      -s, --stats         print statistics for the deleted archive
      -c, --cache-only    delete only the local cache for the given repository
    
Description
~~~~~~~~~~~

This command deletes an archive from the repository or the complete repository.
Disk space is reclaimed accordingly. If you delete the complete repository, the
local cache for it (if any) is also deleted.

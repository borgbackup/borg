.. _borg_debug-delete-obj:

borg debug-delete-obj
---------------------
::

    usage: borg debug-delete-obj [-h] [-v] [--show-rc] [--no-files-cache]
                                 [--umask M] [--remote-path PATH]
                                 [REPOSITORY] IDs [IDs ...]
    
    delete the objects with the given IDs from the repo
    
    positional arguments:
      REPOSITORY          repository to use
      IDs                 hex object ID(s) to delete from the repo
    
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

This command deletes objects from the repository.

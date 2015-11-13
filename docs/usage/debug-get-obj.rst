.. _borg_debug-get-obj:

borg debug-get-obj
------------------
::

    usage: borg debug-get-obj [-h] [-v] [--show-rc] [--no-files-cache] [--umask M]
                              [--remote-path PATH]
                              [REPOSITORY] ID PATH
    
    get object contents from the repository and write it into file
    
    positional arguments:
      REPOSITORY          repository to use
      ID                  hex object ID to get from the repo
      PATH                file to write object data into
    
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

This command gets an object from the repository.

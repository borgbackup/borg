.. _borg_debug-put-obj:

borg debug-put-obj
------------------

put file(s) contents into the repository

Synopsis
--------

::

    borg debug-put-obj [-h] [-v] [--show-rc] [--no-files-cache] [--umask M]
                              [--remote-path PATH]
                              [REPOSITORY] PATH [PATH ...]
    
positional arguments
~~~~~~~~~~~~~~~~~~~~
::
      REPOSITORY          repository to use
      PATH                file(s) to read and create object(s) from
    
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

This command puts objects into the repository.

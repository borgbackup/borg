.. _borg_rename:

borg rename
-----------
::

    usage: borg rename [-h] [-v] [--show-rc] [--no-files-cache] [--umask M]
                       [--remote-path PATH]
                       ARCHIVE NEWNAME
    
    Rename an existing archive
    
    positional arguments:
      ARCHIVE             archive to rename
      NEWNAME             the new archive name to use
    
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

This command renames an archive in the repository.

Examples
~~~~~~~~
::

    $ borg create /mnt/backup::archivename ~
    $ borg list /mnt/backup
    archivename                          Mon Nov  2 20:40:06 2015

    $ borg rename /mnt/backup::archivename newname
    $ borg list /mnt/backup
    newname                              Mon Nov  2 20:40:06 2015

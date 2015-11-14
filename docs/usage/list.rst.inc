.. _borg_list:

borg list
---------
::

    usage: borg list [-h] [-v] [--show-rc] [--no-files-cache] [--umask M]
                     [--remote-path PATH] [--short] [-p PREFIX]
                     [REPOSITORY_OR_ARCHIVE]
    
    List archive or repository contents
    
    positional arguments:
      REPOSITORY_OR_ARCHIVE
                            repository/archive to list contents of
    
    optional arguments:
      -h, --help            show this help message and exit
      -v, --verbose         verbose output
      --show-rc             show/log the return code (rc)
      --no-files-cache      do not load/update the file metadata cache used to
                            detect unchanged files
      --umask M             set umask to M (local and remote, default: 63)
      --remote-path PATH    set remote path to executable (default: "borg")
      --short               only print file/directory names, nothing else
      -p PREFIX, --prefix PREFIX
                            only consider archive names starting with this prefix
    
Description
~~~~~~~~~~~

This command lists the contents of a repository or an archive.

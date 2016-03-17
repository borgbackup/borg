.. _borg_list:

borg list
---------
::

    usage: borg list [-h] [-v] [--debug] [--lock-wait N] [--show-version]
                     [--show-rc] [--no-files-cache] [--umask M]
                     [--remote-path PATH] [--short] [--list-format LISTFORMAT]
                     [-P PREFIX]
                     [REPOSITORY_OR_ARCHIVE]
    
    List archive or repository contents
    
    positional arguments:
      REPOSITORY_OR_ARCHIVE
                            repository/archive to list contents of
    
    optional arguments:
      -h, --help            show this help message and exit
      -v, --verbose, --info
                            enable informative (verbose) output, work on log level
                            INFO
      --debug               enable debug output, work on log level DEBUG
      --lock-wait N         wait for the lock, but max. N seconds (default: 1).
      --show-version        show/log the borg version
      --show-rc             show/log the return code (rc)
      --no-files-cache      do not load/update the file metadata cache used to
                            detect unchanged files
      --umask M             set umask to M (local and remote, default: 0077)
      --remote-path PATH    set remote path to executable (default: "borg")
      --short               only print file/directory names, nothing else
      --list-format LISTFORMAT
                            specify format for archive file listing (default:
                            "{mode} {user:6} {group:6} {size:8d} {isomtime}
                            {path}{extra}{NEWLINE}") Special "{formatkeys}" exists
                            to list available keys
      -P PREFIX, --prefix PREFIX
                            only consider archive names starting with this prefix
    
Description
~~~~~~~~~~~

This command lists the contents of a repository or an archive.

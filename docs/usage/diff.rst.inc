.. _borg_diff:

borg diff
---------
::

    usage: borg diff [-h] [-v] [--debug] [--lock-wait N] [--show-version]
                     [--show-rc] [--no-files-cache] [--umask M]
                     [--remote-path PATH] [-e PATTERN]
                     [--exclude-from EXCLUDEFILE] [--numeric-owner]
                     [--same-chunker-params]
                     ARCHIVE1 ARCHIVE2 [PATH [PATH ...]]
    
    Diff contents of two archives
    
    positional arguments:
      ARCHIVE1              archive
      ARCHIVE2              archive to compare with ARCHIVE1 (no repository
                            location)
      PATH                  paths to compare; patterns are supported
    
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
      -e PATTERN, --exclude PATTERN
                            exclude paths matching PATTERN
      --exclude-from EXCLUDEFILE
                            read exclude patterns from EXCLUDEFILE, one per line
      --numeric-owner       only consider numeric user and group identifiers
      --same-chunker-params
                            Override check of chunker parameters.
    
Description
~~~~~~~~~~~

This command finds differences in files (contents, user, group, mode) between archives.

Both archives need to be in the same repository, and a repository location may only
be specified for ARCHIVE1.

See the output of the "borg help patterns" command for more help on exclude patterns.

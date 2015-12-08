.. _borg_extract:

borg extract
------------
::

    usage: borg extract [-h] [-v] [--debug] [--lock-wait N] [--show-rc]
                        [--no-files-cache] [--umask M] [--remote-path PATH] [-n]
                        [-e PATTERN] [--exclude-from EXCLUDEFILE]
                        [--numeric-owner] [--strip-components NUMBER] [--stdout]
                        [--sparse]
                        ARCHIVE [PATH [PATH ...]]
    
    Extract archive contents
    
    positional arguments:
      ARCHIVE               archive to extract
      PATH                  paths to extract
    
    optional arguments:
      -h, --help            show this help message and exit
      -v, --verbose, --info
                            enable informative (verbose) output, work on log level
                            INFO
      --debug               enable debug output, work on log level DEBUG
      --lock-wait N         wait for the lock, but max. N seconds (default: 1).
      --show-rc             show/log the return code (rc)
      --no-files-cache      do not load/update the file metadata cache used to
                            detect unchanged files
      --umask M             set umask to M (local and remote, default: 0077)
      --remote-path PATH    set remote path to executable (default: "borg")
      -n, --dry-run         do not actually change any files
      -e PATTERN, --exclude PATTERN
                            exclude paths matching PATTERN
      --exclude-from EXCLUDEFILE
                            read exclude patterns from EXCLUDEFILE, one per line
      --numeric-owner       only obey numeric user and group identifiers
      --strip-components NUMBER
                            Remove the specified number of leading path elements.
                            Pathnames with fewer elements will be silently
                            skipped.
      --stdout              write all extracted data to stdout
      --sparse              create holes in output sparse file from all-zero
                            chunks
    
Description
~~~~~~~~~~~

This command extracts the contents of an archive. By default the entire
archive is extracted but a subset of files and directories can be selected
by passing a list of ``PATHs`` as arguments. The file selection can further
be restricted by using the ``--exclude`` option.

See the output of the "borg help patterns" command for more help on exclude patterns.

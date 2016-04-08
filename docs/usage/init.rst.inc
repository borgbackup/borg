.. _borg_init:

borg init
---------
::

    usage: borg init [-h] [--critical] [--error] [--warning] [--info] [--debug]
                     [--lock-wait N] [--show-rc] [--no-files-cache] [--umask M]
                     [--remote-path PATH] [-e {none,keyfile,repokey}]
                     [REPOSITORY]
    
    Initialize an empty repository
    
    positional arguments:
      REPOSITORY            repository to create
    
    optional arguments:
      -h, --help            show this help message and exit
      --critical            work on log level CRITICAL
      --error               work on log level ERROR
      --warning             work on log level WARNING (default)
      --info, -v, --verbose
                            work on log level INFO
      --debug               work on log level DEBUG
      --lock-wait N         wait for the lock, but max. N seconds (default: 1).
      --show-rc             show/log the return code (rc)
      --no-files-cache      do not load/update the file metadata cache used to
                            detect unchanged files
      --umask M             set umask to M (local and remote, default: 0077)
      --remote-path PATH    set remote path to executable (default: "borg")
      -e {none,keyfile,repokey}, --encryption {none,keyfile,repokey}
                            select encryption key mode (default: "repokey")
    
Description
~~~~~~~~~~~

This command initializes an empty repository. A repository is a filesystem
directory containing the deduplicated data from zero or more archives.
Encryption can be enabled at repository init time.

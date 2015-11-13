.. _borg_init:

borg init
---------

Initialize an empty repository

Synopsis
--------

::

    borg init [-h] [-v] [--show-rc] [--no-files-cache] [--umask M]
                     [--remote-path PATH] [-e {none,keyfile,repokey,passphrase}]
                     [REPOSITORY]
    
positional arguments
~~~~~~~~~~~~~~~~~~~~
::
      REPOSITORY            repository to create
    
optional arguments
~~~~~~~~~~~~~~~~~~
::
      -h, --help            show this help message and exit
      -v, --verbose         verbose output
      --show-rc             show/log the return code (rc)
      --no-files-cache      do not load/update the file metadata cache used to
                            detect unchanged files
      --umask M             set umask to M (local and remote, default: 63)
      --remote-path PATH    set remote path to executable (default: "borg")
      -e {none,keyfile,repokey,passphrase}, --encryption {none,keyfile,repokey,passphrase}
                            select encryption key mode
    
Description
~~~~~~~~~~~

This command initializes an empty repository. A repository is a filesystem
directory containing the deduplicated data from zero or more archives.
Encryption can be enabled at repository init time.
Please note that the 'passphrase' encryption mode is DEPRECATED (instead of it,
consider using 'repokey').

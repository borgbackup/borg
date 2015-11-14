.. _borg_change-passphrase:

borg change-passphrase
----------------------
::

    usage: borg change-passphrase [-h] [-v] [--show-rc] [--no-files-cache]
                                  [--umask M] [--remote-path PATH]
                                  [REPOSITORY]
    
    Change repository key file passphrase
    
    positional arguments:
      REPOSITORY
    
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

The key files used for repository encryption are optionally passphrase
protected. This command can be used to change this passphrase.

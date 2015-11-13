.. _borg_serve:

borg serve
----------

Start in server mode. This command is usually not used manually.
        

Synopsis
--------

::

    borg serve [-h] [-v] [--show-rc] [--no-files-cache] [--umask M]
                      [--remote-path PATH] [--restrict-to-path PATH]
    
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
      --restrict-to-path PATH
                            restrict repository access to PATH
    
Description
~~~~~~~~~~~

This command starts a repository server process. This command is usually not used manually.

Examples
~~~~~~~~
::

    # Allow an SSH keypair to only run |project_name|, and only have access to /mnt/backup.
    # This will help to secure an automated remote backup system.
    $ cat ~/.ssh/authorized_keys
    command="borg serve --restrict-to-path /mnt/backup" ssh-rsa AAAAB3[...]

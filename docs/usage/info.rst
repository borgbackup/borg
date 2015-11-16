.. _borg_info:

borg info
---------

Show archive details such as disk space used

Synopsis
~~~~~~~~

::

    borg info [-h] [-v] [--show-rc] [--no-files-cache] [--umask M]
                     [--remote-path PATH]
                     ARCHIVE
    
positional arguments
~~~~~~~~~~~~~~~~~~~~

::
      
    
      ARCHIVE             archive to display information about
    
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

This command displays some detailed information about the specified archive.

Examples
~~~~~~~~

::

    $ borg info /mnt/backup::root-2013-08-02
    Name: root-2013-08-02
    Fingerprint: bc3902e2c79b6d25f5d769b335c5c49331e6537f324d8d3badcb9a0917536dbb
    Hostname: myhostname
    Username: root
    Time: Fri Aug  2 15:18:17 2013
    Command line: /usr/bin/borg create --stats -C zlib,6 /mnt/backup::root-2013-08-02 / --do-not-cross-mountpoints
    Number of files: 147429
    Original size: 5344169493 (4.98 GB)
    Compressed size: 1748189642 (1.63 GB)
    Unique data: 64805454 (61.80 MB)

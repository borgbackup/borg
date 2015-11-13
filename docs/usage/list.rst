.. _borg_list:

borg list
---------

List archive or repository contents

Synopsis
--------

::

    borg list [-h] [-v] [--show-rc] [--no-files-cache] [--umask M]
                     [--remote-path PATH] [--short] [-p PREFIX]
                     [REPOSITORY_OR_ARCHIVE]
    
positional arguments
~~~~~~~~~~~~~~~~~~~~
::
      REPOSITORY_OR_ARCHIVE
                            repository/archive to list contents of
    
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
      --short               only print file/directory names, nothing else
      -p PREFIX, --prefix PREFIX
                            only consider archive names starting with this prefix
    
Description
~~~~~~~~~~~

This command lists the contents of a repository or an archive.

Examples
~~~~~~~~

::

    $ borg list /mnt/backup
    my-files            Thu Aug  1 23:33:22 2013
    my-documents        Thu Aug  1 23:35:43 2013
    root-2013-08-01     Thu Aug  1 23:43:55 2013
    root-2013-08-02     Fri Aug  2 15:18:17 2013
    ...

    $ borg list /mnt/backup::root-2013-08-02
    drwxr-xr-x root   root          0 Jun 05 12:06 .
    lrwxrwxrwx root   root          0 May 31 20:40 bin -> usr/bin
    drwxr-xr-x root   root          0 Aug 01 22:08 etc
    drwxr-xr-x root   root          0 Jul 15 22:07 etc/ImageMagick-6
    -rw-r--r-- root   root       1383 May 22 22:25 etc/ImageMagick-6/colors.xml
    ...

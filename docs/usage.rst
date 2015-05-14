.. include:: global.rst.inc
.. _detailed_usage:

Usage
=====

|project_name| consists of a number of commands. Each command accepts
a number of arguments and options. The following sections will describe each
command in detail.

Quiet by default
----------------

Like most UNIX commands |project_name| is quiet by default but the ``-v`` or
``--verbose`` option can be used to get the program to output more status
messages as it is processing.

.. include:: usage/init.rst.inc

Examples
~~~~~~~~
::

    # Local repository
    $ attic init /data/mybackuprepo.attic

    # Remote repository
    $ attic init user@hostname:mybackuprepo.attic

    # Encrypted remote repository
    $ attic init --encryption=passphrase user@hostname:mybackuprepo.attic


.. include:: usage/create.rst.inc

Examples
~~~~~~~~
::

    # Backup ~/Documents into an archive named "my-documents"
    $ attic create /data/myrepo.attic::my-documents ~/Documents

    # Backup ~/Documents and ~/src but exclude pyc files
    $ attic create /data/myrepo.attic::my-files   \
        ~/Documents                               \
        ~/src                                     \
        --exclude '*.pyc'

    # Backup the root filesystem into an archive named "root-YYYY-MM-DD"
    NAME="root-`date +%Y-%m-%d`"
    $ attic create /data/myrepo.attic::$NAME / --do-not-cross-mountpoints


.. include:: usage/extract.rst.inc

Examples
~~~~~~~~
::

    # Extract entire archive
    $ attic extract /data/myrepo::my-files

    # Extract entire archive and list files while processing
    $ attic extract -v /data/myrepo::my-files

    # Extract the "src" directory
    $ attic extract /data/myrepo::my-files home/USERNAME/src

    # Extract the "src" directory but exclude object files
    $ attic extract /data/myrepo::my-files home/USERNAME/src --exclude '*.o'

.. include:: usage/check.rst.inc

.. include:: usage/delete.rst.inc

.. include:: usage/list.rst.inc

Examples
~~~~~~~~
::

    $ attic list /data/myrepo
    my-files            Thu Aug  1 23:33:22 2013
    my-documents        Thu Aug  1 23:35:43 2013
    root-2013-08-01     Thu Aug  1 23:43:55 2013
    root-2013-08-02     Fri Aug  2 15:18:17 2013
    ...

    $ attic list /data/myrepo::root-2013-08-02
    drwxr-xr-x root   root          0 Jun 05 12:06 .
    lrwxrwxrwx root   root          0 May 31 20:40 bin -> usr/bin
    drwxr-xr-x root   root          0 Aug 01 22:08 etc
    drwxr-xr-x root   root          0 Jul 15 22:07 etc/ImageMagick-6
    -rw-r--r-- root   root       1383 May 22 22:25 etc/ImageMagick-6/colors.xml
    ...


.. include:: usage/prune.rst.inc

Examples
~~~~~~~~
::

    # Keep 7 end of day and 4 additional end of week archives:
    $ attic prune /data/myrepo --keep-daily=7 --keep-weekly=4

    # Same as above but only apply to archive names starting with "foo":
    $ attic prune /data/myrepo --keep-daily=7 --keep-weekly=4 --prefix=foo

    # Keep 7 end of day, 4 additional end of week archives,
    # and an end of month archive for every month:
    $ attic prune /data/myrepo --keep-daily=7 --keep-weekly=4 --keep-monthly=-1

    # Keep all backups in the last 10 days, 4 additional end of week archives,
    # and an end of month archive for every month:
    $ attic prune /data/myrepo --keep-within=10d --keep-weekly=4 --keep-monthly=-1


.. include:: usage/info.rst.inc

Examples
~~~~~~~~
::

    $ attic info /data/myrepo::root-2013-08-02
    Name: root-2013-08-02
    Fingerprint: bc3902e2c79b6d25f5d769b335c5c49331e6537f324d8d3badcb9a0917536dbb
    Hostname: myhostname
    Username: root
    Time: Fri Aug  2 15:18:17 2013
    Command line: /usr/bin/attic create --stats /data/myrepo::root-2013-08-02 / --do-not-cross-mountpoints
    Number of files: 147429
    Original size: 5344169493 (4.98 GB)
    Compressed size: 1748189642 (1.63 GB)
    Unique data: 64805454 (61.80 MB)


.. include:: usage/mount.rst.inc

Examples
~~~~~~~~
::

    $ attic mount /data/myrepo::root-2013-08-02 /tmp/mymountpoint
    $ ls /tmp/mymountpoint
    bin  boot  etc  lib  lib64  mnt  opt  root  sbin  srv  usr  var
    $ fusermount -u /tmp/mymountpoint


.. include:: usage/change-passphrase.rst.inc

Examples
~~~~~~~~
::

    # Create a key file protected repository
    $ attic init --encryption=keyfile /tmp/encrypted-repo
    Initializing repository at "/tmp/encrypted-repo"
    Enter passphrase (empty for no passphrase):
    Enter same passphrase again: 
    Key file "/home/USER/.attic/keys/tmp_encrypted_repo" created.
    Keep this file safe. Your data will be inaccessible without it.

    # Change key file passphrase
    $ attic change-passphrase /tmp/encrypted-repo
    Enter passphrase for key file /home/USER/.attic/keys/tmp_encrypted_repo: 
    New passphrase: 
    Enter same passphrase again: 
    Key file "/home/USER/.attic/keys/tmp_encrypted_repo" updated

.. include:: mount.rst.inc

.. include:: umount.rst.inc

Examples
~~~~~~~~

::

    # Mounting the repository shows all archives.
    # Archives are loaded lazily, expect some delay when navigating to an archive
    # for the first time.
    $ borg mount /path/to/repo /tmp/mymountpoint
    $ ls /tmp/mymountpoint
    root-2016-02-14 root-2016-02-15
    $ borg umount /tmp/mymountpoint

    # Mounting a specific archive is possible as well.
    $ borg mount /path/to/repo::root-2016-02-15 /tmp/mymountpoint
    $ ls /tmp/mymountpoint
    bin  boot  etc	home  lib  lib64  lost+found  media  mnt  opt
    root  sbin  srv  tmp  usr  var
    $ borg umount /tmp/mymountpoint

    # The experimental "versions view" merges all archives in the repository
    # and provides a versioned view on files.
    $ borg mount -o versions /path/to/repo /tmp/mymountpoint
    $ ls -l /tmp/mymountpoint/home/user/doc.txt/
    total 24
    -rw-rw-r-- 1 user group 12357 Aug 26 21:19 doc.cda00bc9.txt
    -rw-rw-r-- 1 user group 12204 Aug 26 21:04 doc.fa760f28.txt
    $ borg umount /tmp/mymountpoint

    # Archive filters are supported.
    # These are especially handy for the "versions view",
    # which does not support lazy processing of archives.
    $ borg mount -o versions --glob-archives '*-my-home' --last 10 /path/to/repo /tmp/mymountpoint

    # Exclusion options are supported.
    # These can speed up mounting and lower memory needs significantly.
    $ borg mount /path/to/repo /tmp/mymountpoint only/that/path
    $ borg mount --exclude '...' /path/to/repo /tmp/mymountpoint


borgfs
++++++

::

    $ echo '/mnt/backup /tmp/myrepo fuse.borgfs defaults,noauto 0 0' >> /etc/fstab
    $ echo '/mnt/backup::root-2016-02-15 /tmp/myarchive fuse.borgfs defaults,noauto 0 0' >> /etc/fstab
    $ mount /tmp/myrepo
    $ mount /tmp/myarchive
    $ ls /tmp/myrepo
    root-2016-02-01 root-2016-02-2015
    $ ls /tmp/myarchive
    bin  boot  etc	home  lib  lib64  lost+found  media  mnt  opt  root  sbin  srv  tmp  usr  var

.. Note::

    ``borgfs`` will be automatically provided if you used a distribution
    package, ``pip`` or ``setup.py`` to install Borg. Users of the
    standalone binary will have to manually create a symlink (see
    :ref:`pyinstaller-binary`).

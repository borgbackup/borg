.. include:: mount.rst.inc

.. include:: umount.rst.inc

Examples
~~~~~~~~

borg mount
++++++++++
::

    $ borg mount /path/to/repo::root-2016-02-15 /tmp/mymountpoint
    $ ls /tmp/mymountpoint
    bin  boot  etc	home  lib  lib64  lost+found  media  mnt  opt  root  sbin  srv  tmp  usr  var
    $ borg umount /tmp/mymountpoint

::

    $ borg mount -o versions /path/to/repo /tmp/mymountpoint
    $ ls -l /tmp/mymountpoint/home/user/doc.txt/
    total 24
    -rw-rw-r-- 1 user group 12357 Aug 26 21:19 doc.txt.cda00bc9
    -rw-rw-r-- 1 user group 12204 Aug 26 21:04 doc.txt.fa760f28
    $ fusermount -u /tmp/mymountpoint

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

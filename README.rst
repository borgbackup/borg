What is Borg?
-------------
Borg is a deduplicating backup program.
Optionally, it also supports compression and authenticated encryption.

The main goal of Borg is to provide an efficient and secure way to backup data.
The data deduplication technique used makes Borg suitable for daily backups
since only changes are stored.
The authenticated encryption technique makes it suitable for backups to not
fully trusted targets.

Main features
~~~~~~~~~~~~~
Space efficient storage
  Variable block size deduplication is used to reduce the number of bytes
  stored by detecting redundant data. Each file is split into a number of
  variable length chunks and only chunks that have never been seen before are
  added to the repository.

  The content-defined chunking based deduplication is applied to remove
  duplicate chunks within:

  * the current backup data set (even inside single files / streams)
  * current and previous backups of same machine
  * all the chunks in the same repository, even if coming from other machines

  This advanced deduplication method does NOT depend on:

  * file/directory names staying the same (so you can move your stuff around
    without killing the deduplication, even between machines sharing a repo)
  * complete files or time stamps staying the same (if a big file changes a
    little, only a few new chunks will be stored - this is great for VMs or
    raw disks)
  * the absolute position of a data chunk inside a file (stuff may get shifted
    and will still be found by the deduplication algorithm)

Optional data encryption
    All data can be protected using 256-bit AES encryption and data integrity
    and authenticity is verified using HMAC-SHA256.

Optional compression
    All data can be compressed (by zlib, level 0-9).

Off-site backups
    Borg can store data on any remote host accessible over SSH.  This is
    most efficient if Borg is also installed on the remote host. If you can't
    install Borg there, you can also use some network filesystem (sshfs, nfs,
    ...), but it will be less efficient.

Backups mountable as filesystems
    Backup archives are mountable as userspace filesystems for easy backup
    verification and restores.

Platforms Borg works on
  * Linux
  * FreeBSD
  * Mac OS X
  * Cygwin (unsupported)


Easy to use
~~~~~~~~~~~
Initialize a new backup repository and create a backup archive::

    $ borg init /mnt/backup
    $ borg create /mnt/backup::Monday ~/Documents

Now doing another backup, just to show off the great deduplication::

    $ borg create --stats /mnt/backup::Tuesday ~/Documents

    Archive name: Tuesday
    Archive fingerprint: 387a5e3f9b0e792e91ce87134b0f4bfe17677d9248cb5337f3fbf3a8e157942a
    Start time: Tue Mar 25 12:00:10 2014
    End time:   Tue Mar 25 12:00:10 2014
    Duration: 0.08 seconds
    Number of files: 358
                           Original size      Compressed size    Deduplicated size
    This archive:               57.16 MB             46.78 MB            151.67 kB
    All archives:              114.02 MB             93.46 MB             44.81 MB

For a graphical frontend refer to our complementary project
`BorgWeb <https://github.com/borgbackup/borgweb>`_.


How to proceed from here
------------------------
Everything about requirements, installation, getting a quick start, usage
reference, FAQ, support info, internals and developer infos is in our
documentation:

See `our online documentation <https://borgbackup.github.io/>`_
or alternatively read it in raw text form in the `docs/*.rst` files.


Notes
-----

Build status:
|build|

Borg is a fork of `Attic <https://github.com/jborg/attic>`_ and maintained by
"`The Borg Collective <https://github.com/borgbackup/borg/blob/master/AUTHORS>`_".

BORG IS NOT COMPATIBLE WITH ORIGINAL ATTIC.
EXPECT THAT WE WILL BREAK COMPATIBILITY REPEATEDLY WHEN MAJOR RELEASE NUMBER
CHANGES (like when going from 0.x.y to 1.0.0). Please read CHANGES document.

NOT RELEASED DEVELOPMENT VERSIONS HAVE UNKNOWN COMPATIBILITY PROPERTIES.

THIS IS SOFTWARE IN DEVELOPMENT, DECIDE YOURSELF WHETHER IT FITS YOUR NEEDS.

Read `issue #1 <https://github.com/borgbackup/borg/issues/1>`_ on the issue
tracker, goals are being defined there.

For more information, please also see the
`LICENSE  <https://github.com/borgbackup/borg/blob/master/LICENSE>`_.


.. |build| image:: https://travis-ci.org/borgbackup/borg.svg
        :alt: Build Status
        :target: https://travis-ci.org/borgbackup/borg

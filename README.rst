|build|

What is Borg?
-------------
Borg is a deduplicating backup program. The main goal of Borg is to provide
an efficient and secure way to backup data. The data deduplication
technique used makes Borg suitable for daily backups since only changes
are stored.

Borg is a fork of `Attic <https://github.com/jborg/attic>`_ and maintained by "`The Borg Collective <https://github.com/borgbackup/borg/blob/master/AUTHORS>`_".

BORG IS NOT COMPATIBLE WITH ORIGINAL ATTIC.
EXPECT THAT WE WILL BREAK COMPATIBILITY REPEATEDLY WHEN MAJOR RELEASE NUMBER
CHANGES (like when going from 0.x.y to 1.0.0). Please read CHANGES document.

NOT RELEASED DEVELOPMENT VERSIONS HAVE UNKNOWN COMPATIBILITY PROPERTIES.

THIS IS SOFTWARE IN DEVELOPMENT, DECIDE YOURSELF WHETHER IT FITS YOUR NEEDS.

Read `issue #1 <https://github.com/borgbackup/borg/issues/1>`_ on the issue tracker, goals are being defined there.

Please also see the `LICENSE  <https://github.com/borgbackup/borg/blob/master/LICENSE>`_ for more informations.

Easy to use
~~~~~~~~~~~
Initialize backup repository and create a backup archive::

    $ borg init /mnt/backup
    $ borg create -v /mnt/backup::documents ~/Documents

For a graphical frontend refer to our complementary project `BorgWeb <https://github.com/borgbackup/borgweb>`_.

Main features
~~~~~~~~~~~~~
Space efficient storage
  Variable block size deduplication is used to reduce the number of bytes 
  stored by detecting redundant data. Each file is split into a number of
  variable length chunks and only chunks that have never been seen before are
  compressed and added to the repository.

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

Off-site backups
    Borg can store data on any remote host accessible over SSH.  This is
    most efficient if Borg is also installed on the remote host.

Backups mountable as filesystems
    Backup archives are mountable as userspace filesystems for easy backup
    verification and restores.

What do I need?
---------------
Borg requires Python 3.2 or above to work.
Borg also requires a sufficiently recent OpenSSL (>= 1.0.0).
In order to mount archives as filesystems, llfuse is required.

How do I install it?
--------------------
::

  $ pip3 install borgbackup

Where are the docs?
-------------------
Go to https://borgbackup.github.io/ for a prebuilt version of the documentation.
You can also build it yourself from the docs folder.

Where are the tests?
--------------------
The tests are in the borg/testsuite package. To run the test suite use the
following command::

  $ fakeroot -u tox  # you need to have tox and pytest installed

.. |build| image:: https://travis-ci.org/borgbackup/borg.svg
        :alt: Build Status
        :target: https://travis-ci.org/borgbackup/borg

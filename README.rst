|screencast|


What is BorgBackup?
-------------------

BorgBackup (short: Borg) is a deduplicating backup program.
Optionally, it supports compression and authenticated encryption.

The main goal of Borg is to provide an efficient and secure way to backup data.
The data deduplication technique used makes Borg suitable for daily backups
since only changes are stored.
The authenticated encryption technique makes it suitable for backups to not
fully trusted targets.

See the `installation manual`_ or, if you have already
downloaded Borg, ``docs/installation.rst`` to get started with Borg.

.. _installation manual: https://borgbackup.readthedocs.org/en/stable/installation.html

Main features
~~~~~~~~~~~~~

**Space efficient storage**
  Deduplication based on content-defined chunking is used to reduce the number
  of bytes stored: each file is split into a number of variable length chunks
  and only chunks that have never been seen before are added to the repository.

  A chunk is considered duplicate if its id_hash value is identical.
  A cryptographically strong hash or MAC function is used as id_hash, e.g.
  (hmac-)sha256.

  To deduplicate, all the chunks in the same repository are considered, no
  matter whether they come from different machines, from previous backups,
  from the same backup or even from the same single file.

  Compared to other deduplication approaches, this method does NOT depend on:

  * file/directory names staying the same: So you can move your stuff around
    without killing the deduplication, even between machines sharing a repo.

  * complete files or time stamps staying the same: If a big file changes a
    little, only a few new chunks need to be stored - this is great for VMs or
    raw disks.

  * The absolute position of a data chunk inside a file: Stuff may get shifted
    and will still be found by the deduplication algorithm.

**Speed**
  * performance critical code (chunking, compression, encryption) is
    implemented in C/Cython
  * local caching of files/chunks index data
  * quick detection of unmodified files

**Data encryption**
    All data can be protected using 256-bit AES encryption, data integrity and
    authenticity is verified using HMAC-SHA256. Data is encrypted clientside.

**Compression**
    All data can be compressed by lz4 (super fast, low compression), zlib
    (medium speed and compression) or lzma (low speed, high compression).

**Off-site backups**
    Borg can store data on any remote host accessible over SSH.  If Borg is
    installed on the remote host, big performance gains can be achieved
    compared to using a network filesystem (sshfs, nfs, ...).

**Backups mountable as filesystems**
    Backup archives are mountable as userspace filesystems for easy interactive
    backup examination and restores (e.g. by using a regular file manager).

**Easy installation on multiple platforms**
    We offer single-file binaries that do not require installing anything -
    you can just run them on these platforms:

    * Linux
    * Mac OS X
    * FreeBSD
    * OpenBSD and NetBSD (no xattrs/ACLs support or binaries yet)
    * Cygwin (not supported, no binaries yet)
    * Linux Subsystem of Windows 10 (not supported)

**Free and Open Source Software**
  * security and functionality can be audited independently
  * licensed under the BSD (3-clause) license, see `License`_ for the
    complete license

Easy to use
~~~~~~~~~~~

Initialize a new backup repository and create a backup archive::

    $ borg init /path/to/repo
    $ borg create /path/to/repo::Saturday1 ~/Documents

Now doing another backup, just to show off the great deduplication::

    $ borg create -v --stats /path/to/repo::Saturday2 ~/Documents
    -----------------------------------------------------------------------------
    Archive name: Saturday2
    Archive fingerprint: 622b7c53c...
    Time (start): Sat, 2016-02-27 14:48:13
    Time (end):   Sat, 2016-02-27 14:48:14
    Duration: 0.88 seconds
    Number of files: 163
    -----------------------------------------------------------------------------
                   Original size      Compressed size    Deduplicated size
    This archive:        6.85 MB              6.85 MB             30.79 kB  <-- !
    All archives:       13.69 MB             13.71 MB              6.88 MB

                   Unique chunks         Total chunks
    Chunk index:             167                  330
    -----------------------------------------------------------------------------


For a graphical frontend refer to our complementary project `BorgWeb <https://borgweb.readthedocs.io/>`_.

Helping, Donations and Bounties
-------------------------------

Your help is always welcome!
Spread the word, give feedback, help with documentation, testing or development.

You can also give monetary support to the project, see there for details:

https://borgbackup.readthedocs.io/en/stable/support.html#bounties-and-fundraisers

Links
-----

* `Main Web Site <https://borgbackup.readthedocs.org/>`_
* `Releases <https://github.com/borgbackup/borg/releases>`_,
  `PyPI packages <https://pypi.python.org/pypi/borgbackup>`_ and
  `ChangeLog <https://github.com/borgbackup/borg/blob/master/docs/changes.rst>`_
* `GitHub <https://github.com/borgbackup/borg>`_ and
  `Issue Tracker <https://github.com/borgbackup/borg/issues>`_.
* `Web-Chat (IRC) <http://webchat.freenode.net/?randomnick=1&channels=%23borgbackup&uio=MTY9dHJ1ZSY5PXRydWUa8>`_ and
  `Mailing List <https://mail.python.org/mailman/listinfo/borgbackup>`_
* `License <https://borgbackup.readthedocs.org/en/stable/authors.html#license>`_
* `Security contact <https://borgbackup.readthedocs.io/en/latest/support.html#security-contact>`_

Compatibility notes
-------------------

EXPECT THAT WE WILL BREAK COMPATIBILITY REPEATEDLY WHEN MAJOR RELEASE NUMBER
CHANGES (like when going from 0.x.y to 1.0.0 or from 1.x.y to 2.0.0).

NOT RELEASED DEVELOPMENT VERSIONS HAVE UNKNOWN COMPATIBILITY PROPERTIES.

THIS IS SOFTWARE IN DEVELOPMENT, DECIDE YOURSELF WHETHER IT FITS YOUR NEEDS.

Security issues should be reported to the `Security contact`_ (or
see ``docs/suppport.rst`` in the source distribution).

.. start-badges

|doc| |build| |coverage| |bestpractices| |bounties|

.. |bounties| image:: https://api.bountysource.com/badge/team?team_id=78284&style=bounties_posted
        :alt: Bounty Source
        :target: https://www.bountysource.com/teams/borgbackup

.. |doc| image:: https://readthedocs.org/projects/borgbackup/badge/?version=stable
        :alt: Documentation
        :target: https://borgbackup.readthedocs.org/en/stable/

.. |build| image:: https://api.travis-ci.org/borgbackup/borg.svg
        :alt: Build Status
        :target: https://travis-ci.org/borgbackup/borg

.. |coverage| image:: https://codecov.io/github/borgbackup/borg/coverage.svg?branch=master
        :alt: Test Coverage
        :target: https://codecov.io/github/borgbackup/borg?branch=master

.. |screencast| image:: https://asciinema.org/a/28691.png
        :alt: BorgBackup Installation and Basic Usage
        :target: https://asciinema.org/a/28691?autoplay=1&speed=2

.. |bestpractices| image:: https://bestpractices.coreinfrastructure.org/projects/271/badge
        :alt: Best Practices Score
        :target: https://bestpractices.coreinfrastructure.org/projects/271

.. end-badges

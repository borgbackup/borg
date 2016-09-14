|screencast|

.. highlight:: bash

What is BorgBackup?
===================

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
-------------

**Space efficient storage**
  Deduplication based on content-defined chunking is used to reduce the number
  of bytes stored: each file is split into a number of variable length chunks
  and only chunks that have never been seen before are added to the repository.

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

**Free and Open Source Software**
  * security and functionality can be audited independently
  * licensed under the BSD (3-clause) license


Easy to use
-----------

Initialize a new backup repository and create a backup archive::

    $ borg init /path/to/repo
    $ borg create /path/to/repo::Saturday1 ~/Documents

Now doing another backup, just to show off the great deduplication:

.. code-block:: none

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

Checking Release Authenticity and Security Contact
==================================================

`Releases <https://github.com/borgbackup/borg/releases>`_ are signed with this GPG key,
please use GPG to verify their authenticity.

In case you discover a security issue, please use this contact for reporting it privately
and please, if possible, use encrypted E-Mail:

Thomas Waldmann <tw@waldmann-edv.de>

GPG Key Fingerprint: 6D5B EF9A DD20 7580 5747  B70F 9F88 FB52 FAF7 B393

The public key can be fetched from any GPG keyserver, but be careful: you must
use the **full fingerprint** to check that you got the correct key.

Links
=====

* `Main Web Site <https://borgbackup.readthedocs.org/>`_
* `Releases <https://github.com/borgbackup/borg/releases>`_,
  `PyPI packages <https://pypi.python.org/pypi/borgbackup>`_ and
  `ChangeLog <https://github.com/borgbackup/borg/blob/master/docs/changes.rst>`_
* `GitHub <https://github.com/borgbackup/borg>`_,
  `Issue Tracker <https://github.com/borgbackup/borg/issues>`_ and
  `Bounties & Fundraisers <https://www.bountysource.com/teams/borgbackup>`_
* `Web-Chat (IRC) <http://webchat.freenode.net/?randomnick=1&channels=%23borgbackup&uio=MTY9dHJ1ZSY5PXRydWUa8>`_ and
  `Mailing List <https://mail.python.org/mailman/listinfo/borgbackup>`_
* `License <https://borgbackup.readthedocs.org/en/stable/authors.html#license>`_

Notes
-----

Borg is a fork of `Attic`_ and maintained by "`The Borg collective`_".

.. _Attic: https://github.com/jborg/attic
.. _The Borg collective: https://borgbackup.readthedocs.org/en/latest/authors.html

Differences between Attic and Borg
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Here's a (incomplete) list of some major changes:

* more open, faster paced development (see `issue #1 <https://github.com/borgbackup/borg/issues/1>`_)
* lots of attic issues fixed (see `issue #5 <https://github.com/borgbackup/borg/issues/5>`_)
* less chunk management overhead (less memory and disk usage for chunks index)
* faster remote cache resync (useful when backing up multiple machines into same repo)
* compression: no, lz4, zlib or lzma compression, adjustable compression levels
* repokey replaces problematic passphrase mode (you can't change the passphrase nor the pbkdf2 iteration count in "passphrase" mode)
* simple sparse file support, great for virtual machine disk files
* can read special files (e.g. block devices) or from stdin, write to stdout
* mkdir-based locking is more compatible than attic's posix locking
* uses fadvise to not spoil / blow up the fs cache
* better error messages / exception handling
* better logging, screen output, progress indication
* tested on misc. Linux systems, 32 and 64bit, FreeBSD, OpenBSD, NetBSD, Mac OS X

Please read the `ChangeLog`_ (or ``docs/changes.rst`` in the source distribution) for more
information.

BORG IS NOT COMPATIBLE WITH ORIGINAL ATTIC (but there is a one-way conversion).

EXPECT THAT WE WILL BREAK COMPATIBILITY REPEATEDLY WHEN MAJOR RELEASE NUMBER
CHANGES (like when going from 0.x.y to 1.0.0 or from 1.x.y to 2.0.0).

NOT RELEASED DEVELOPMENT VERSIONS HAVE UNKNOWN COMPATIBILITY PROPERTIES.

THIS IS SOFTWARE IN DEVELOPMENT, DECIDE YOURSELF WHETHER IT FITS YOUR NEEDS.

Borg is distributed under a 3-clause BSD license, see `License`_ for the complete license.

|doc| |build| |coverage| |bestpractices|

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

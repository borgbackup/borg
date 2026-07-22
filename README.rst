This is borg2!
--------------

Please note that this is the README for (unstable) Borg2 / master branch.

For general project infos, versioned docs, screen casts, please see there:

https://www.borgbackup.org/

Borg2 is currently in beta testing and might get major and/or
breaking changes between beta releases (and there is no beta to
next-beta upgrade code, so you will have to delete and re-create repos).

Thus, **DO NOT USE BORG2 FOR YOUR PRODUCTION BACKUPS!** Please help with
testing it, but set it up *additionally* to your production backups.


What is BorgBackup?
-------------------

BorgBackup (short: Borg) is a deduplicating backup program.
Optionally, it supports compression and authenticated encryption.

The main goal of Borg is to provide an efficient and secure way to back up data.
The data deduplication technique used makes Borg suitable for daily backups
since only changes are stored.
The authenticated encryption technique makes it suitable for backups to targets not
fully trusted.

See the `installation manual`_ or, if you have already
downloaded Borg, ``docs/installation.rst`` to get started with Borg.

.. _installation manual: https://borgbackup.readthedocs.io/en/master/installation.html

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

  Supported chunkers:

  * buzhash (as in borg 1.x) / buzhash64 (improved)
  * fastCDC
  * fixed

**Speed**
  * performance-critical code (chunking, compression, encryption) is
    implemented in C/Cython
  * local caching
  * quick detection of unmodified files

**Data encryption**
    All data can be protected client-side using 256-bit authenticated encryption
    (AES-OCB or chacha20-poly1305), ensuring data confidentiality, integrity and
    authenticity.

**Hashing**
    You can choose between HMAC-SHA256 and Blake3.

**Obfuscation**
    Optionally, Borg can actively obfuscate, e.g., the size of files/chunks to
    make fingerprinting attacks more difficult.

**Compression**
    All data can be optionally compressed:

    * lz4 (super fast, low compression)
    * zstd (wide range from high speed and low compression to high compression
      and lower speed)
    * zlib (medium speed and compression)
    * lzma (low speed, high compression)

**Off-site backups**
    Borg can store data on any remote host accessible via misc. protocols:

    * ssh (REST-http-over-stdio-over-ssh) and https (REST-http-over-tcp).
      Significant performance gains can be achieved with this by having a
      remote agent (borg must be installed on the repo server).
    * sftp
    * S3 / B2
    * lots of protocols / providers supported by rclone

**Backups mountable as file systems**
    Backup archives are mountable as user-space file systems for easy interactive
    backup examination and restores (e.g., by using a regular file manager).

**Easy installation on multiple platforms**
    We offer single-file binaries that do not require installing anything -
    you can just run them on these platforms:

    * Linux
    * macOS
    * FreeBSD
    * OpenBSD and NetBSD (no xattrs/ACLs support or binaries yet)
    * Cygwin (experimental, no binaries yet)
    * Windows (MSYS2/MINGW borg.exe, experimental)
    * Windows Subsystem for Linux (WSL) on Windows 10/11 (experimental)

**Free and Open Source Software**
  * security and functionality can be audited independently
  * licensed under the BSD (3-clause) license, see `License`_ for the
    complete license

Easy to use
~~~~~~~~~~~

For ease of use, set the BORG_REPO environment variable::

    $ export BORG_REPO=/path/to/repo

Create a new backup repository (see ``borg repo-create --help`` for encryption options)::

    $ borg repo-create --encryption=aes256-ocb --key-location=repokey

Create a new backup archive::

    $ borg create docs ~/Documents

Now do another backup, just to show off the great deduplication::

    $ borg create -v --stats docs ~/Documents
    Repository: /path/to/repo
    Archive name: docs
    Archive fingerprint: 7714aef97c1a24539cc3dc73f79b060f14af04e2541da33d54c7ee8e81a00089
    Time (start): Mon, 2022-10-03 19:57:35 +0200
    Time (end):   Mon, 2022-10-03 19:57:35 +0200
    Duration: 0.01 seconds
    Number of files: 24
    Original size: 29.73 MB
    Deduplicated size: 520 B


For demo videos, check out our homepage: https://www.borgbackup.org/#demo

Helping, donations and bounties, becoming a Patron
--------------------------------------------------

Your help is always welcome!

Spread the word, give feedback, help with documentation, testing or development.

You can also give monetary support to the project, see here for details:

https://www.borgbackup.org/#fund

Links
-----

* `Main website <https://www.borgbackup.org/>`_
* `Releases <https://github.com/borgbackup/borg/releases>`_,
  `PyPI packages <https://pypi.org/project/borgbackup/>`_ and
  `Changelog <https://github.com/borgbackup/borg/blob/master/docs/changes.rst>`_
* `GitHub <https://github.com/borgbackup/borg>`_ and
  `Issue tracker <https://github.com/borgbackup/borg/issues>`_.
* `Web chat (IRC) <https://web.libera.chat/#borgbackup>`_ and
  `Mailing list <https://mail.python.org/mailman/listinfo/borgbackup>`_
* `License <https://borgbackup.readthedocs.io/en/master/authors.html#license>`_
* `Security contact <https://borgbackup.readthedocs.io/en/master/support.html#security-contact>`_

Compatibility notes
-------------------

EXPECT THAT WE WILL BREAK COMPATIBILITY REPEATEDLY WHEN MAJOR RELEASE NUMBER
CHANGES (like when going from 0.x.y to 1.0.0 or from 1.x.y to 2.0.0).

NOT RELEASED DEVELOPMENT VERSIONS HAVE UNKNOWN COMPATIBILITY PROPERTIES.

THIS IS SOFTWARE IN DEVELOPMENT, DECIDE FOR YOURSELF WHETHER IT FITS YOUR NEEDS.

Security issues should be reported to the `Security contact`_ (or
see ``docs/support.rst`` in the source distribution).

.. start-badges

|doc| |build| |coverage| |bestpractices|

.. |doc| image:: https://readthedocs.org/projects/borgbackup/badge/?version=master
        :alt: Documentation
        :target: https://borgbackup.readthedocs.io/en/master/

.. |build| image:: https://github.com/borgbackup/borg/actions/workflows/ci.yml/badge.svg?branch=master
        :alt: Build Status (master)
        :target: https://github.com/borgbackup/borg/actions

.. |coverage| image:: https://codecov.io/github/borgbackup/borg/coverage.svg?branch=master
        :alt: Test Coverage
        :target: https://codecov.io/github/borgbackup/borg?branch=master

.. |bestpractices| image:: https://bestpractices.coreinfrastructure.org/projects/271/badge
        :alt: Best Practices Score
        :target: https://bestpractices.coreinfrastructure.org/projects/271

.. end-badges

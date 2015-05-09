.. include:: global.rst.inc
.. _foreword:

Foreword
========

|project_name| is a secure backup program for Linux, FreeBSD and Mac OS X. 
|project_name| is designed for efficient data storage where only new or
modified data is stored.

Features
--------

Space efficient storage
    Variable block size `deduplication`_ is used to reduce the number of bytes 
    stored by detecting redundant data. Each file is split into a number of
    variable length chunks and only chunks that have never been seen before
    are compressed and added to the repository.

Optional data encryption
    All data can be protected using 256-bit AES_ encryption and data integrity
    and authenticity is verified using `HMAC-SHA256`_.

Off-site backups
    |project_name| can store data on any remote host accessible over SSH as
    long as |project_name| is installed.

Backups mountable as filesystems
    Backup archives are :ref:`mountable <borg_mount>` as
    `userspace filesystems`_ for easy backup verification and restores.


Glossary
--------

.. _deduplication_def:

Deduplication
    Deduplication is a technique for improving storage utilization by
    eliminating redundant data. 

.. _archive_def:

Archive
    An archive is a collection of files along with metadata that include file
    permissions, directory structure and various file attributes.
    Since each archive in a repository must have a unique name a good naming
    convention is ``hostname-YYYY-MM-DD``.

.. _repository_def:

Repository
    A repository is a filesystem directory storing data from zero or more
    archives. The data in a repository is both deduplicated and 
    optionally encrypted making it both efficient and safe. Repositories are
    created using :ref:`borg_init` and the contents can be listed using
    :ref:`borg_list`.

Key file
    When a repository is initialized a key file containing a password
    protected encryption key is created. It is vital to keep this file safe
    since the repository data is totally inaccessible without it.

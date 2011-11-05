Welcome to Darc's documentation!
================================

Darc is a Deduplicating ARChiver written in Python.
The main goal of Darc is to provide an efficient and secure way to backup data.

Features
--------
Space efficient storage
   Variable block size `deduplication <http://en.wikipedia.org/wiki/Data_deduplication>`_
   is used to reduce the number of bytes stored by detecting redundant data.
   Each file is split into a number of variable length chunks and only chunks
   that have never been seen before are added to the store.

Secure
    All data is encrypted using `AES256 <http://en.wikipedia.org/wiki/Advanced_Encryption_Standard>`_
    and the data integrity and authenticity is verified using
    `HMAC-SHA256 <http://en.wikipedia.org/wiki/HMAC>`_.

Definitions
-----------
Deduplication
    Deduplication is a technique for improving storage utilization by eliminating
    redundant data. 

Archive
    A Darc archive is a collection of files along with metadata that include file
    permissions, directory structure and various file attributes.

Store
    A Darc store is a filesystem directory storing data from zero or more archives.
    The data in a store is both deduplicated and encrypted making it both 
    efficient and safe.

Key file
    When a Darc store is initialized a key file containing a password protected
    encryption key is created. It is vital to keep this file safe since the store
    data is totally inaccessible without it.


Requirements
------------
* Python >= 2.5
* pycrypto
* msgpack-python
* paramiko (for remote store support)

Installation
------------

Usage
-----

Before the first archive can be created a store needs to be initialized.
A store is directory containing

Initialize a new empty store::

    $ darc init /data/my-backup.darc
    Initializing store "/data/my-backup.darc"
    Key file password (Leave blank for no password): *****
    Key file password again: *****
    Key file "/Users/jonas/.darc/keys/data_my_backup_darc" created.
    Remember that this file (and password) is needed to access your data. Keep it safe!

Create an archive::

    darc create -v /data/my-backup.darc::backup-2011-09-10 ~/Documents ~/src

Extract an archive::

    darc extract -v /data/my-backup.darc::backup-2011-09-10

Delete an archive::

    darc delete /data/my-backup.darc::backup-2011-09-10

List store contents::

    darc list /data/my-backup.darc

List archive contents::

    darc list /data/my-backup.darc::backup-2011-09-10

Indices and tables
==================

* :ref:`genindex`
* :ref:`search`


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

Remote stores
    Darc can store data on remote hosts over SSH as long as Darc is installed on
    the remote host. The following syntax is used to specify a remote store::

    $ darc list hostname:path
    $ darc extract hostname:path::archive-name
    $ darc extract username@hostname:path::archive-name


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

The following instructions will install Darc in ``/usr/local/darc/`` without interfering
with the rest of the system.

1. Initialize a new python environment::

    $ virtualenv /usr/local/darc

2. Extract the source code using GIT or a release tarball::

    $ mkdir /usr/local/darc/src/
    $ cd /usr/local/darc/src/
    $ tar -xvzf darc-x.y.tar.gz
    OR
    $ git clone git://github.com/jborg/darc.git

3. Install Darc::

    $ cd darc-x.y/
    $ ../../bin/python setup.py install

4. Add /usr/local/darc/bin to $PATH


Basic Usage
===========

Initializing a store
--------------------
Before the first archive can be created a store needs to be initialized::

    $ darc init /data/my-backup.darc
    Initializing store "/data/my-backup.darc"
    Key file password (Leave blank for no password): *****
    Key file password again: *****
    Key file "/home/YOU/.darc/keys/data_my_backup_darc" created.
    Remember that this file (and password) is needed to access your data. Keep it safe!


Archive creation
----------------
The following command will create a new archive called ``backup-2011-09-10`` containing
all files in ``~/Documents`` and ``~/src``::

    $ darc create -v /data/my-backup.darc::backup-2011-09-10 ~/Documents ~/src

Extract an archive
------------------
The following command will extract the archive ``backup-2011-09-10``::

    $ darc extract -v /data/my-backup.darc::backup-2011-09-10

Delete an archive
-----------------
The following command will delete archive ``backup-2011-09-10``::

    $ darc delete /data/my-backup.darc::backup-2011-09-10

List store contents
-------------------
The following command will list the names of all archives in the store::

    $ darc list /data/my-backup.darc
    backup-2011-09-09
    backup-2011-09-10
    ...

List archive contents
---------------------
The following command will list the contents of the ``backup-2011-09-10`` archive::

    $ darc list /data/my-backup.darc::backup-2011-09-10
    -rw-r--r-- YOU    users       280 May 14  2010 home/YOU/Documents/something.txt
    -rw-r--r-- YOU    users       280 May 14  2010 home/YOU/Documents/something-else.pdf
    ...

Prune old archives
------------------
When performing automatic backups it is important to periodically prune old backup
archives to stop the store from growing too big.

The following command will prune old archives and only keep the
seven latest end of day archives and the five latest end of week archives::

    $ darc prune --daily=7 --weekly=5 /data/my-backup.darc


Indices and tables
==================

* :ref:`genindex`
* :ref:`search`


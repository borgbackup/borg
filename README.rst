What is Attic?
--------------
Attic is a deduplicating backup program. The main goal of attic is to provide
an efficient and secure way to backup data. The data deduplication
technique used makes Attic suitable for daily backups since only actual changes
are stored.

Easy to use
~~~~~~~~~~~
Initialze backup repository and create a backup archive::

    $ attic init /usbdrive/my-backup.attic
    $ attic create -v /usbdrive/my-backup.attic::documents ~/Documents

Main features
~~~~~~~~~~~~~
Space efficient storage
  Variable block size deduplication is used to reduce the number of bytes 
  stored by detecting redundant data. Each file is split into a number of
  variable length chunks and only chunks that have never been seen before are
  compressed and added to the repository.

Optional data encryption
    All data can be protected using 256-bit AES encryption and data integrity
    and authenticity is verified using HMAC-SHA256.

Off-site backups
    attic can store data on any remote host accessible over SSH as long as
    attic is installed.

Backups mountable as filesystems
    Backup archives are mountable as userspace filesystems for easy backup
    verification and restores.

What do I need?
---------------
Attic requires Python 3.2 or above to work. Besides Python attic also requires 
msgpack-python and sufficiently recent OpenSSL (>= 1.0.0).

How do I install it?
--------------------
::

  $ pip install Attic

Where are the docs?
-------------------
Go to https://pythonhosted.org/Attic/ for a prebuilt version of the docs. You
can also build them yourself form the docs folder.

Where are the tests?
--------------------
The tests are in the attic/testsuite package. To run the test suite use the
following command::

  $ python -m attic.testsuite.run

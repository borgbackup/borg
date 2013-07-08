What is darc?
-------------
Darc is a Deduplicating ARChiver written in Python. The main goal of darc is
to provide an efficient and secure way to backup data. The data deduplication
technique used makes darc suitable for daily backups since only actual changes
are stored.

Easy to use
~~~~~~~~~~~
Initialze backup repository and create a backup archive::

    $ darc init /usbdrive/my-backup.darc
    $ darc create -v /usbdrive/my-backup.darc::documents ~/Documents

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
    darc can store data on any remote host accessible over SSH as long as
    darc is installed.

What do I need?
---------------
Darc requires Python 3.2 or above to work. Besides Python darc also requires 
msgpack-python and sufficiently recent OpenSSL (>= 1.0.0).

How do I install it?
--------------------

::
  $ pip install darc

Where are the docs?
-------------------
Go to https://pythonhosted.org/darc/ for a prebuilt version of the docs. You
can also build them yourself form the docs folder.

Where are the tests?
--------------------
The tests are in the darc/testsuite package. To run the test suite use the
following command::

  $ python -m darc.testsuite.run

Contribute
----------
Found a bug? Have any ideas to improve darc? Add bug reports and feature
requests to the `issue tracker <https://github.com/jborg/darc/issues>`_.

You can also ask the author a question directly by
`email <mailto:jonas@borgstrom.se>`_.

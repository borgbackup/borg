.. include:: global.rst.inc

Darc
====
|project_name| is a Deduplicating ARChiver written in Python.
The main goal of |project_name| is to provide an efficient and secure way
to backup data. The data deduplication technique used makes |project_name|
suitable for daily backups since only actual changes are stored.

Main Features
-------------
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

Easy to use
-----------
Initialize a new backup :ref:`repository <repository_def>` and create your
first backup :ref:`archive <archive_def>` in two lines::

    $ darc init /usbdrive/my-backup.darc
    $ darc create -v /usbdrive/my-backup.darc::documents ~/Documents

See the :ref:`generalusage` section for more detailed examples.

Easy installation
-----------------
You can use pip to install |project_name| quickly and easily::

    $ pip install darc

Need more help with installing? See :ref:`installation`

User's Guide
============

.. toctree::
   :maxdepth: 2

   installation
   generalusage
   detailedusage
   faq
   terminology

Contribute
==========

Found a bug? Have any ideas to improve |project_name|?
Head over to |project_name|'s github_ page and create an issue or a pull
request.

You can also ask the author a question directly by
`email <mailto:jonas@borgstrom.se>`_.

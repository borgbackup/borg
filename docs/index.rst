.. include:: global.rst.inc

Welcome to Attic
================
|project_name| is a deduplicating backup program written in Python.
The main goal of |project_name| is to provide an efficient and secure way
to backup data. The data deduplication technique used makes |project_name|
suitable for daily backups since only actual changes are stored.


Easy to use
-----------
Initialize a new backup :ref:`repository <repository_def>` and create your
first backup :ref:`archive <archive_def>` in two lines::

    $ attic init /usbdrive/my-backup.attic
    $ attic create -v /usbdrive/my-backup.attic::documents ~/Documents

See the :ref:`generalusage` section for a more detailed example.

Easy installation
-----------------
You can use pip to install |project_name| quickly and easily::

    $ pip install attic

Need more help with installing? See :ref:`installation`.

User's Guide
============

.. toctree::
   :maxdepth: 2

   foreword
   installation
   quickstart
   commands
   faq

Contribute
==========

Found a bug? Have any ideas to improve |project_name|? Add bug reports and
feature requests to the `issue tracker`_.

You can also ask the author a question directly by
`email <mailto:jonas@borgstrom.se>`_.

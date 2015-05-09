.. include:: global.rst.inc

Welcome to Borg
================
|project_name| is a deduplicating backup program written in Python.
The main goal of |project_name| is to provide an efficient and secure way
to backup data. The data deduplication technique used makes |project_name|
suitable for daily backups since only the changes are stored.


Easy to use
-----------
Initialize a new backup :ref:`repository <repository_def>` and create your
first backup :ref:`archive <archive_def>` in two lines::

    $ borg init /somewhere/my-repository.borg
    $ borg create /somewhere/my-repository.borg::Monday ~/Documents
    $ borg create --stats /somewhere/my-repository.borg::Tuesday ~/Documents
    Archive name: Tuesday
    Archive fingerprint: 387a5e3f9b0e792e91ce87134b0f4bfe17677d9248cb5337f3fbf3a8e157942a
    Start time: Tue Mar 25 12:00:10 2014
    End time:   Tue Mar 25 12:00:10 2014
    Duration: 0.08 seconds
    Number of files: 358
                           Original size      Compressed size    Deduplicated size
    This archive:               57.16 MB             46.78 MB            151.67 kB
    All archives:              114.02 MB             93.46 MB             44.81 MB

See the :ref:`quickstart` chapter for a more detailed example.

Easy installation
-----------------
You can use pip to install |project_name| quickly and easily::

    $ pip3 install borgbackup

Need more help with installing? See :ref:`installation`.

User's Guide
============

.. toctree::
   :maxdepth: 2

   foreword
   installation
   quickstart
   usage
   faq
   internals

Getting help
============

If you've found a bug or have a concrete feature request, you can add your bug
report or feature request directly to the project's `issue tracker`_. For more
general questions or discussions, a post to the mailing list is preferred.

IRC
---
Join us on channel ##borgbackup on chat.freenode.net. As usual on IRC, just
ask or tell directly and then patiently wait for replies. Stay connected.

Mailing list
------------

There is a mailing list for Borg on librelist_ that you can use for feature
requests and general discussions about Borg. A mailing list archive is
available `here <http://librelist.com/browser/borgbackup/>`_.

To subscribe to the list, send an email to borgbackup@librelist.com and reply
to the confirmation mail. Likewise, to unsubscribe, send an email to 
borgbackup-unsubscribe@librelist.com and reply to the confirmation mail.

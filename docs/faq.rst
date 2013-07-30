.. _faq:
.. include:: global.rst.inc

Frequently asked questions
==========================

Which platforms are supported?
------------------------------

Currently Linux, FreeBSD and MacOS X are supported.


Can I backup VM disk images?
----------------------------

Yes, the :ref:`deduplication <deduplication_def>` technique used by |project_name|
makes sure only the modified parts of the file are stored.


Which file attributes are preserved?
------------------------------------

The following attributes are preserved:

* Name
* Contents
* Time of last modification (nanosecond precision with Python >= 3.3)
* User ID of owner
* Group ID of owner
* Unix Permission
* Extended attributes (xattrs)

.. Note::
    POSIX Access Control Lists (ACL_) are not yet preserved.


How can I specify the encryption passphrase programmatically?
-------------------------------------------------------------

The encryption passphrase can be specified programmatically using the
`ATTIC_PASSPHRASE` environment variable. This is convenient when setting up
automated encrypted backups. Another option is to use
key file based encryption with a blank passphrase. For more details see
:ref:encrypted_repos

.. _faq:
.. include:: global.rst.inc

Frequently asked questions
==========================

Which platforms are supported?
------------------------------

Currently Linux and MacOS X are supported.

Can I backup VM disk images?
----------------------------

Yes, the :ref:`deduplication <deduplication_def>` technique used by darc
will make sure only the modified parts of the file is stored.

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

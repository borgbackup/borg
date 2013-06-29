.. _definitions:
.. include:: global.rst.inc

Definitions
===========

.. _deduplication_def:

Deduplication
    Deduplication is a technique for improving storage utilization by eliminating
    redundant data. 

.. _archive_def:

Archive
    An archive is a collection of files along with metadata that include file
    permissions, directory structure and various file attributes.
    Since each archive in a repository must have a unique name a good naming
    convention is ``hostname-YYYY-MM-DD``.

.. _repository_def:

Repository
    A repository is a filesystem directory storing data from zero or more archives.
    The data in a repository is both deduplicated and encrypted making it both 
    efficient and safe.

Key file
    When a repository is initialized a key file containing a password protected
    encryption key is created. It is vital to keep this file safe since the repository
    data is totally inaccessible without it.

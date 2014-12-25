.. _faq:
.. include:: global.rst.inc

Frequently asked questions
==========================

Which platforms are supported?
    Currently Linux, FreeBSD and MacOS X are supported.


Can I backup VM disk images?
    Yes, the :ref:`deduplication <deduplication_def>` technique used by |project_name|
    makes sure only the modified parts of the file are stored.

Which file attributes are preserved?
    The following attributes are preserved:

    * Name
    * Contents
    * Time of last modification (nanosecond precision with Python >= 3.3)
    * User ID of owner
    * Group ID of owner
    * Unix Permission
    * Extended attributes (xattrs)
    * Access Control Lists (ACL_) on Linux, OS X and FreeBSD
    * BSD flags on OS X and FreeBSD

How can I specify the encryption passphrase programmatically?
    The encryption passphrase can be specified programmatically using the
    `ATTIC_PASSPHRASE` environment variable. This is convenient when setting up
    automated encrypted backups. Another option is to use
    key file based encryption with a blank passphrase. See
    :ref:`encrypted_repos` for more details.

When backing up to remote servers, is data encrypted before leaving the local machine, or do I have to trust that the remote server isn't malicious?
    Yes, everything is encrypted before leaving the local machine.

If a backup stops mid-way, does the already-backed-up data stay there? I.e. does Attic resume backups?
    Yes, during a backup a special checkpoint archive named ``<archive-name>.checkpoint`` is saved every 5 minutes
    containing all the data backed-up until that point. This means that at most 5 minutes worth of data needs to be
    retransmitted if a backup needs to be restarted.

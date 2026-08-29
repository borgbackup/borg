.. include:: copy.rst.inc

Examples
~~~~~~~~
::

    # create an archive, then keep a copy of it under a stable name:
    $ borg create backup-2016-02-15 ~
    $ borg copy backup-2016-02-15 known-good
    $ borg repo-list
    d7b79fd3  Sat, 2026-08-29 14:39:27 +0200  backup-2016-02-15              tw          MacBook-Pro
    f81040e3  Sat, 2026-08-29 14:39:27 +0200  known-good                   tw          MacBook-Pro

    # the copy is an independent archive:
    # after deleting (and compacting away) the original, the copy is still complete.
    $ borg delete backup-2016-02-15
    $ borg compact
    $ borg extract known-good

    # if the archive name is not unique, address the archive by its ID:
    $ borg copy aid:d7b79fd3 known-good

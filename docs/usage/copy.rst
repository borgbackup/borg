.. include:: copy.rst.inc

Examples
~~~~~~~~
::

    # create an archive, then keep a copy of it under a stable name:
    $ borg create backup-2016-02-15 ~
    $ borg copy backup-2016-02-15 known-good
    $ borg repo-list
    e6a2b1c4  Mon, 2016-02-15 19:50:19 +0100  backup-2016-02-15  tw          MacBook-Pro
    9f3d0a77  Mon, 2016-02-15 19:50:19 +0100  known-good         tw          MacBook-Pro

    # the copy is an independent archive:
    # after deleting (and compacting away) the original, the copy is still complete.
    $ borg delete backup-2016-02-15
    $ borg compact
    $ borg extract known-good

    # if the archive name is not unique, address the archive by its ID:
    $ borg copy aid:e6a2b1c4 known-good

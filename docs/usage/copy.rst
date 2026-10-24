.. include:: copy.rst.inc

Examples
~~~~~~~~
::

    # create an archive, then copy it to an archive with a different name:
    $ borg create home ~
    $ borg copy home known-good
    $ borg repo-list
    d7b79fd3  Sat, 2026-08-29 14:39:27 +0200  home                         tw          MacBook-Pro
    f81040e3  Sat, 2026-08-29 14:39:27 +0200  known-good                   tw          MacBook-Pro

    # the copy is an independent archive:
    # after deleting (and compacting away) the original, the copy is still complete.
    $ borg delete home
    $ borg compact
    $ borg extract known-good

    # if the archive name is not unique, address the archive by its ID:
    $ borg copy aid:d7b79fd3 known-good

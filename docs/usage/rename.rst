.. include:: rename.rst.inc

Examples
~~~~~~~~
::

    $ borg create archivename ~
    $ borg repo-list
    516c2a16  Sat, 2026-08-29 14:39:58 +0200  archivename                  tw          MacBook-Pro

    # renaming rewrites the archive metadata, so the archive ID changes:
    $ borg rename archivename newname
    $ borg repo-list
    3aaef11e  Sat, 2026-08-29 14:39:58 +0200  newname                      tw          MacBook-Pro


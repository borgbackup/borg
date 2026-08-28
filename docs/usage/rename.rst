.. include:: rename.rst.inc

Examples
~~~~~~~~
::

    $ borg create archivename ~
    $ borg repo-list
    8df049de  Mon, 2016-02-15 19:50:19 +0100  archivename      tw          MacBook-Pro

    # renaming rewrites the archive metadata, so the archive ID changes:
    $ borg rename archivename newname
    $ borg repo-list
    69ea925b  Mon, 2016-02-15 19:50:19 +0100  newname          tw          MacBook-Pro


.. include:: rename.rst.inc

Examples
~~~~~~~~
::

    $ borg create archivename ~
    $ borg repo-list
    archivename                          Mon, 2016-02-15 19:50:19

    $ borg rename archivename newname
    $ borg repo-list
    newname                              Mon, 2016-02-15 19:50:19


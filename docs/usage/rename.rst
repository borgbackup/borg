.. include:: rename.rst.inc

Examples
~~~~~~~~
::

    $ borg create archivename ~
    $ borg rlist
    archivename                          Mon, 2016-02-15 19:50:19

    $ borg rename archivename newname
    $ borg rlist
    newname                              Mon, 2016-02-15 19:50:19


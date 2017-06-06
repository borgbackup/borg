.. include:: rename.rst.inc

Examples
~~~~~~~~
::

    $ borg create /path/to/repo::archivename ~
    $ borg list /path/to/repo
    archivename                          Mon, 2016-02-15 19:50:19

    $ borg rename /path/to/repo::archivename newname
    $ borg list /path/to/repo
    newname                              Mon, 2016-02-15 19:50:19

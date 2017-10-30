.. include:: delete.rst.inc

Examples
~~~~~~~~
::

    # delete a single backup archive:
    $ borg delete /path/to/repo::Monday

    # delete the whole repository and the related local cache:
    $ borg delete /path/to/repo
    You requested to completely DELETE the repository *including* all archives it contains:
    repo                                 Mon, 2016-02-15 19:26:54
    root-2016-02-15                      Mon, 2016-02-15 19:36:29
    newname                              Mon, 2016-02-15 19:50:19
    Type 'YES' if you understand this and want to continue: YES

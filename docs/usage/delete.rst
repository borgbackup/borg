.. include:: delete.rst.inc

Examples
~~~~~~~~
::

    # delete a single backup archive:
    $ borg delete /path/to/repo::Monday
    # actually free disk space:
    $ borg compact /path/to/repo

    # delete all archives whose names begin with the machine's hostname followed by "-"
    $ borg delete --prefix '{hostname}-' /path/to/repo

    # delete all archives whose names contain "-2012-"
    $ borg delete --glob-archives '*-2012-*' /path/to/repo

    # see what would be deleted if delete was run without --dry-run
    $ borg delete -v --dry-run -a '*-May-*' /path/to/repo

    # delete the whole repository and the related local cache:
    $ borg delete /path/to/repo
    You requested to completely DELETE the repository *including* all archives it contains:
    repo                                 Mon, 2016-02-15 19:26:54
    root-2016-02-15                      Mon, 2016-02-15 19:36:29
    newname                              Mon, 2016-02-15 19:50:19
    Type 'YES' if you understand this and want to continue: YES

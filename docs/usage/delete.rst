.. include:: delete.rst.inc

Examples
~~~~~~~~
::

    # delete a single backup archive:
    $ borg delete Monday
    # actually free disk space:
    $ borg compact

    # delete all archives whose names begin with the machine's hostname followed by "-"
    $ borg delete -a '{hostname}-*'

    # delete all archives whose names contain "-2012-"
    $ borg delete -a '*-2012-*'

    # see what would be deleted if delete was run without --dry-run
    $ borg delete --list --dry-run -a '*-May-*'


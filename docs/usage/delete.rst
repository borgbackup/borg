.. include:: delete.rst.inc

Examples
~~~~~~~~
::

    # delete all backup archives named "kenny-files":
    $ borg delete -a kenny-files
    # actually free disk space:
    $ borg compact

    # delete a specific backup archive using its unique archive ID prefix
    $ borg delete aid:d34db33f

    # delete all archives whose names begin with the machine's hostname followed by "-"
    $ borg delete -a 'sh:{hostname}-*'

    # delete all archives whose names contain "-2012-"
    $ borg delete -a 'sh:*-2012-*'

    # see what would be deleted if delete was run without --dry-run
    $ borg delete --list --dry-run -a 'sh:*-May-*'


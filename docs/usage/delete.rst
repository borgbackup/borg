.. include:: delete.rst.inc

Examples
~~~~~~~~
::

    # Delete all backup archives named "kenny-files":
    $ borg delete -a kenny-files
    # Actually free disk space:
    $ borg compact

    # Delete a specific backup archive using its unique archive ID prefix
    $ borg delete aid:d34db33f

    # Delete all archives whose names begin with the machine's hostname followed by "-"
    $ borg delete -a 'sh:{hostname}-*'

    # Delete all archives whose names contain "-2012-"
    $ borg delete -a 'sh:*-2012-*'

    # See what would be deleted if delete was run without --dry-run
    $ borg delete --list --dry-run -a 'sh:*-May-*'


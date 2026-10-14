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

    # Delete all archives created on this machine
    $ borg delete -a 'host:{hostname}'

    # Delete all archives created in 2012
    $ borg delete -a 'date:2012'

    # See what would be deleted if delete was run without --dry-run
    $ borg delete --list --dry-run -a 'date:2012-05'


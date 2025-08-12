.. include:: compact.rst.inc

Examples
~~~~~~~~
::

    # compact segments and free repo disk space
    $ borg compact /path/to/repo

    # same as above plus clean up 17-byte commit-only segments
    $ borg compact --cleanup-commits /path/to/repo



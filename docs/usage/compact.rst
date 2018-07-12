.. include:: compact.rst.inc

Examples
~~~~~~~~
::

    # compact segments and free repo disk space
    $ borg compact /path/to/repo

    # same as above plus clean up 17byte commit-only segments,
    # use this one time after upgrading borg (server) to 1.2+
    # to clean up the tiny segments files created by borg 1.1:
    $ borg compact --cleanup-commits /path/to/repo



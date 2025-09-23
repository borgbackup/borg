.. include:: prune.rst.inc

Examples
~~~~~~~~

Be careful: prune is a potentially dangerous command that removes backup
archives.

By default, prune applies to **all archives in the repository** unless you
restrict its operation to a subset of the archives.

The recommended way to name archives (with ``borg create``) is to use the
identical archive name within a series of archives. Then you can simply give
that name to prune as well, so it operates only on that series of archives.

Alternatively, you can use ``-a``/``--match-archives`` to match archive names
and select a subset of them.
When using ``-a``, be careful to choose a good pattern — for example, do not use a
prefix "foo" if you do not also want to match "foobar".

It is strongly recommended to always run ``prune -v --list --dry-run ...``
first, so you will see what it would do without it actually doing anything.

Do not forget to run ``borg compact -v`` after prune to actually free disk space.

::

    # Keep 7 end of day and 4 additional end of week archives.
    # Do a dry-run without actually deleting anything.
    $ borg prune -v --list --dry-run --keep-daily=7 --keep-weekly=4

    # Similar to the above, but only apply to the archive series named '{hostname}':
    $ borg prune -v --list --keep-daily=7 --keep-weekly=4 '{hostname}'

    # Similar to the above, but apply to archive names starting with the hostname
    # of the machine followed by a '-' character:
    $ borg prune -v --list --keep-daily=7 --keep-weekly=4 -a 'sh:{hostname}-*'

    # Keep 7 end of day, 4 additional end of week archives,
    # and an end of month archive for every month:
    $ borg prune -v --list --keep-daily=7 --keep-weekly=4 --keep-monthly=-1

    # Keep all backups in the last 10 days, 4 additional end of week archives,
    # and an end of month archive for every month:
    $ borg prune -v --list --keep-within=10d --keep-weekly=4 --keep-monthly=-1

There is also a visualized prune example in ``docs/misc/prune-example.txt``:

.. highlight:: none
.. include:: ../misc/prune-example.txt
    :literal:

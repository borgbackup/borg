.. include:: prune.rst.inc

Examples
~~~~~~~~

Be careful, prune is a potentially dangerous command, it will remove backup
archives.

The default of prune is to apply to **all archives in the repository** unless
you restrict its operation to a subset of the archives using ``--prefix``.
When using ``--prefix``, be careful to choose a good prefix - e.g. do not use a
prefix "foo" if you do not also want to match "foobar".

It is strongly recommended to always run ``prune -v --list --dry-run ...``
first so you will see what it would do without it actually doing anything.

::

    # Keep 7 end of day and 4 additional end of week archives.
    # Do a dry-run without actually deleting anything.
    $ borg prune -v --list --dry-run --keep-daily=7 --keep-weekly=4 /path/to/repo

    # Same as above but only apply to archive names starting with the hostname
    # of the machine followed by a "-" character:
    $ borg prune -v --list --keep-daily=7 --keep-weekly=4 --prefix='{hostname}-' /path/to/repo

    # Keep 7 end of day, 4 additional end of week archives,
    # and an end of month archive for every month:
    $ borg prune -v --list --keep-daily=7 --keep-weekly=4 --keep-monthly=-1 /path/to/repo

    # Keep all backups in the last 10 days, 4 additional end of week archives,
    # and an end of month archive for every month:
    $ borg prune -v --list --keep-within=10d --keep-weekly=4 --keep-monthly=-1 /path/to/repo

There is also a visualized prune example in ``docs/misc/prune-example.txt``:

.. highlight:: none
.. include:: ../misc/prune-example.txt
    :literal:

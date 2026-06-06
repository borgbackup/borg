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

The ``--keep-*`` options accept either a **count** (e.g. ``--keep-daily 7``) or
a **time interval** (e.g. ``--keep-daily 7d``). A count keeps up to *N* archives
per period (e.g. the last 7 daily archives), while an interval keeps one
archive per period within that time span (e.g. one daily archive per day in the
last 7-day window). When using intervals, you may also specify ``--since`` to
set the reference timestamp for interval calculation.

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
    $ borg prune -v --list --keep=10d --keep-weekly=4 --keep-monthly=-1

    # Keep daily archives from the last 7 days:
    $ borg prune -v --list --dry-run --keep-daily=7d

    # Same as above, but with a fixed reference timestamp:
    $ borg prune -v --list --dry-run --since 2025-12-01T00:00:00+02:00 --keep-daily=7d

    # Keep the last 14 archives using `--keep`:
    $ borg prune -v --list --dry-run --keep 14

    # Keep all archives from the last 30 days using `--keep`:
    $ borg prune -v --list --dry-run --keep 30d

There are also visualized prune examples in ``docs/misc/prune-example.txt`` and
``docs/misc/prune-example-interval.txt``:

.. highlight:: none
.. include:: ../misc/prune-example.txt
    :literal:

.. include:: ../misc/prune-example-interval.txt
    :literal:

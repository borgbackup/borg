.. _borg_prune:

borg prune
----------

Prune repository archives according to specified rules

Synopsis
~~~~~~~~

::

    borg prune [-h] [-v] [--show-rc] [--no-files-cache] [--umask M]
                      [--remote-path PATH] [-n] [-s] [--keep-within WITHIN]
                      [-H HOURLY] [-d DAILY] [-w WEEKLY] [-m MONTHLY] [-y YEARLY]
                      [-p PREFIX]
                      [REPOSITORY]
    
positional arguments
~~~~~~~~~~~~~~~~~~~~
::
      REPOSITORY            repository to prune
    
optional arguments
~~~~~~~~~~~~~~~~~~
::
      -h, --help            show this help message and exit
      -v, --verbose         verbose output
      --show-rc             show/log the return code (rc)
      --no-files-cache      do not load/update the file metadata cache used to
                            detect unchanged files
      --umask M             set umask to M (local and remote, default: 63)
      --remote-path PATH    set remote path to executable (default: "borg")
      -n, --dry-run         do not change repository
      -s, --stats           print statistics for the deleted archive
      --keep-within WITHIN  keep all archives within this time interval
      -H HOURLY, --keep-hourly HOURLY
                            number of hourly archives to keep
      -d DAILY, --keep-daily DAILY
                            number of daily archives to keep
      -w WEEKLY, --keep-weekly WEEKLY
                            number of weekly archives to keep
      -m MONTHLY, --keep-monthly MONTHLY
                            number of monthly archives to keep
      -y YEARLY, --keep-yearly YEARLY
                            number of yearly archives to keep
      -p PREFIX, --prefix PREFIX
                            only consider archive names starting with this prefix
    
Description
~~~~~~~~~~~

The prune command prunes a repository by deleting archives not matching
any of the specified retention options. This command is normally used by
automated backup scripts wanting to keep a certain number of historic backups.

As an example, "-d 7" means to keep the latest backup on each day for 7 days.
Days without backups do not count towards the total.
The rules are applied from hourly to yearly, and backups selected by previous
rules do not count towards those of later rules. The time that each backup
completes is used for pruning purposes. Dates and times are interpreted in
the local timezone, and weeks go from Monday to Sunday. Specifying a
negative number of archives to keep means that there is no limit.

The "--keep-within" option takes an argument of the form "<int><char>",
where char is "H", "d", "w", "m", "y". For example, "--keep-within 2d" means
to keep all archives that were created within the past 48 hours.
"1m" is taken to mean "31d". The archives kept with this option do not
count towards the totals specified by any other options.

If a prefix is set with -p, then only archives that start with the prefix are
considered for deletion and only those archives count towards the totals
specified by the rules.
Otherwise, *all* archives in the repository are candidates for deletion!

Examples
~~~~~~~~


Be careful, prune is potentially dangerous command, it will remove backup
archives.

The default of prune is to apply to **all archives in the repository** unless
you restrict its operation to a subset of the archives using `--prefix`.
When using --prefix, be careful to choose a good prefix - e.g. do not use a
prefix "foo" if you do not also want to match "foobar".

It is strongly recommended to always run `prune --dry-run ...` first so you
will see what it would do without it actually doing anything.

::

    # Keep 7 end of day and 4 additional end of week archives.
    # Do a dry-run without actually deleting anything.
    $ borg prune /mnt/backup --dry-run --keep-daily=7 --keep-weekly=4

    # Same as above but only apply to archive names starting with "foo":
    $ borg prune /mnt/backup --keep-daily=7 --keep-weekly=4 --prefix=foo

    # Keep 7 end of day, 4 additional end of week archives,
    # and an end of month archive for every month:
    $ borg prune /mnt/backup --keep-daily=7 --keep-weekly=4 --keep-monthly=-1

    # Keep all backups in the last 10 days, 4 additional end of week archives,
    # and an end of month archive for every month:
    $ borg prune /mnt/backup --keep-within=10d --keep-weekly=4 --keep-monthly=-1

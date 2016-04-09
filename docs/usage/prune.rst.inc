.. _borg_prune:

borg prune
----------
::

    borg prune <options> REPOSITORY

positional arguments
    REPOSITORY
        repository to prune

optional arguments
    ``-n``, ``--dry-run``
        | do not change repository
    ``-s``, ``--stats``
        | print statistics for the deleted archive
    ``--list``
        | output verbose list of archives it keeps/prunes
    ``--keep-within WITHIN``
        | keep all archives within this time interval
    ``-H``, ``--keep-hourly``
        | number of hourly archives to keep
    ``-d``, ``--keep-daily``
        | number of daily archives to keep
    ``-w``, ``--keep-weekly``
        | number of weekly archives to keep
    ``-m``, ``--keep-monthly``
        | number of monthly archives to keep
    ``-y``, ``--keep-yearly``
        | number of yearly archives to keep
    ``-P``, ``--prefix``
        | only consider archive names starting with this prefix
    ``--save-space``
        | work slower, but using less space

`Common options`_
    |

Description
~~~~~~~~~~~

The prune command prunes a repository by deleting archives not matching
any of the specified retention options. This command is normally used by
automated backup scripts wanting to keep a certain number of historic backups.

As an example, "-d 7" means to keep the latest backup on each day, up to 7
most recent days with backups (days without backups do not count).
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

If a prefix is set with -P, then only archives that start with the prefix are
considered for deletion and only those archives count towards the totals
specified by the rules.
Otherwise, *all* archives in the repository are candidates for deletion!

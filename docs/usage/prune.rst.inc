.. _borg_prune:

borg prune
----------
::

    usage: borg prune [-h] [--critical] [--error] [--warning] [--info] [--debug]
                      [--lock-wait N] [--show-rc] [--no-files-cache] [--umask M]
                      [--remote-path PATH] [-n] [-s] [--list]
                      [--keep-within WITHIN] [-H HOURLY] [-d DAILY] [-w WEEKLY]
                      [-m MONTHLY] [-y YEARLY] [-P PREFIX] [--save-space]
                      [REPOSITORY]
    
    Prune repository archives according to specified rules
    
    positional arguments:
      REPOSITORY            repository to prune
    
    optional arguments:
      -h, --help            show this help message and exit
      --critical            work on log level CRITICAL
      --error               work on log level ERROR
      --warning             work on log level WARNING (default)
      --info, -v, --verbose
                            work on log level INFO
      --debug               work on log level DEBUG
      --lock-wait N         wait for the lock, but max. N seconds (default: 1).
      --show-rc             show/log the return code (rc)
      --no-files-cache      do not load/update the file metadata cache used to
                            detect unchanged files
      --umask M             set umask to M (local and remote, default: 0077)
      --remote-path PATH    set remote path to executable (default: "borg")
      -n, --dry-run         do not change repository
      -s, --stats           print statistics for the deleted archive
      --list                output verbose list of archives it keeps/prunes
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
      -P PREFIX, --prefix PREFIX
                            only consider archive names starting with this prefix
      --save-space          work slower, but using less space
    
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

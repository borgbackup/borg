.. _attic_prune:

attic prune
-----------
::


    usage: attic prune [-h] [-v] [-H HOURLY] [-d DAILY] [-w WEEKLY] [-m MONTHLY]
                       [-y YEARLY] [-p PREFIX]
                       REPOSITORY
    
    Prune repository archives according to specified rules
    
    positional arguments:
      REPOSITORY            repository to prune
    
    optional arguments:
      -h, --help            show this help message and exit
      -v, --verbose         verbose output
      -H HOURLY, --hourly HOURLY
                            number of hourly archives to keep
      -d DAILY, --daily DAILY
                            number of daily archives to keep
      -w WEEKLY, --weekly WEEKLY
                            number of daily archives to keep
      -m MONTHLY, --monthly MONTHLY
                            number of monthly archives to keep
      -y YEARLY, --yearly YEARLY
                            number of yearly archives to keep
      -p PREFIX, --prefix PREFIX
                            only consider archive names starting with this prefix
    
    The prune command prunes a repository by deleting archives not matching any of
    the specified retention options. This command is normally used by automated
    backup scripts wanting to keep a certain number of historic backups. As an
    example, "-d 7" means to keep the latest backup on each day for 7 days. Days
    without backups do not count towards the total. The rules are applied from
    hourly to yearly, and backups selected by previous rules do not count towards
    those of later rules. Dates and times are interpreted in the local timezone,
    and weeks go from Monday to Sunday. Specifying a negative number of archives
    to keep means that there is no limit. If a prefix is set with -p, then only
    archives that start with the prefix are considered for deletion and only those
    archives count towards the totals specified by the rules.

Description
~~~~~~~~~~~



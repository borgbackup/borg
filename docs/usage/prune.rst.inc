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

Description
~~~~~~~~~~~



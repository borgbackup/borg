.. include:: info.rst.inc

Examples
~~~~~~~~
::

    $ borg info Tuesday2022-06-25T20:51:39
    Archive name: Tuesday2022-06-25T20:51:39
    Archive fingerprint: f7dea0788dfc026cc2be1c0f5b94beb4e4084eb3402fc40c38d8719b1bf2d943
    Comment:
    Hostname: mba2020
    Username: tw
    Time (start): Sat, 2022-06-25 20:51:40
    Time (end): Sat, 2022-06-25 20:51:40
    Duration: 0.03 seconds
    Command line: /Users/tw/w/borg-env/bin/borg -r path/to/repo create --stats 'Tuesday{now}' src --progress
    Utilization of maximum supported archive size: 0%
    Number of files: 244
    Original size: 13.80 MB
    Deduplicated size: 531 B


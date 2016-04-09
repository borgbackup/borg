    ``-h``, ``--help``
        | show this help message and exit
    ``--critical``
        | work on log level CRITICAL
    ``--error``
        | work on log level ERROR
    ``--warning``
        | work on log level WARNING (default)
    ``--info``, ``-v``, ``--verbose``
        | work on log level INFO
    ``--debug``
        | enable debug output, work on log level DEBUG
    ``--lock-wait N``
        | wait for the lock, but max. N seconds (default: 1).
    ``--show-version``
        | show/log the borg version
    ``--show-rc``
        | show/log the return code (rc)
    ``--no-files-cache``
        | do not load/update the file metadata cache used to detect unchanged files
    ``--umask M``
        | set umask to M (local and remote, default: 0077)
    ``--remote-path PATH``
        | set remote path to executable (default: "borg")
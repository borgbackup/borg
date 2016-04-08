.. _borg_serve:

borg serve
----------
::

    usage: borg serve [-h] [--critical] [--error] [--warning] [--info] [--debug]
                      [--lock-wait N] [--show-rc] [--no-files-cache] [--umask M]
                      [--remote-path PATH] [--restrict-to-path PATH]
    
    Start in server mode. This command is usually not used manually.
            
    
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
      --restrict-to-path PATH
                            restrict repository access to PATH
    
Description
~~~~~~~~~~~

This command starts a repository server process. This command is usually not used manually.

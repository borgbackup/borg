.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_debug-info:

borg debug-info
---------------
::

    usage: borg debug-info [-h] [--critical] [--error] [--warning] [--info]
                           [--debug] [--lock-wait N] [--show-rc]
                           [--no-files-cache] [--umask M] [--remote-path PATH]
    
    display system information for debugging / bug reports
    
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
    
Description
~~~~~~~~~~~

This command displays some system information that might be useful for bug
reports and debugging problems. If a traceback happens, this information is
already appended at the end of the traceback.

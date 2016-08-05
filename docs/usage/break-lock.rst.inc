.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_break-lock:

borg break-lock
---------------
::

    usage: borg break-lock [-h] [--critical] [--error] [--warning] [--info]
                           [--debug] [--lock-wait N] [--show-rc]
                           [--no-files-cache] [--umask M] [--remote-path PATH]
                           [REPOSITORY]
    
    Break the repository lock (e.g. in case it was left by a dead borg.
    
    positional arguments:
      REPOSITORY            repository for which to break the locks
    
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

This command breaks the repository and cache locks.
Please use carefully and only while no borg process (on any machine) is
trying to access the Cache or the Repository.

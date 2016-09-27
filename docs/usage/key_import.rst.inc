.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_key_import:

borg key import
---------------
::

    usage: borg key import [-h] [--critical] [--error] [--warning] [--info]
                           [--debug] [--lock-wait N] [--show-rc]
                           [--no-files-cache] [--umask M] [--remote-path PATH]
                           [--paper]
                           [REPOSITORY] [PATH]
    
    Import the repository key from backup
    
    positional arguments:
      REPOSITORY
      PATH                  path to the backup
    
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
      --paper               interactively import from a backup done with --paper
    
Description
~~~~~~~~~~~

This command allows to restore a key previously backed up with the
export command.

If the ``--paper`` option is given, the import will be an interactive
process in which each line is checked for plausibility before
proceeding to the next line. For this format PATH must not be given.

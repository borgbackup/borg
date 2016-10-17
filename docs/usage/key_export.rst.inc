.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_key_export:

borg key export
---------------
::

    usage: borg key export [-h] [--critical] [--error] [--warning] [--info]
                           [--debug] [--lock-wait N] [--show-rc]
                           [--no-files-cache] [--umask M] [--remote-path PATH]
                           [--paper]
                           [REPOSITORY] [PATH]
    
    Export the repository key for backup
    
    positional arguments:
      REPOSITORY
      PATH                  where to store the backup
    
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
      --paper               Create an export suitable for printing and later type-
                            in
    
Description
~~~~~~~~~~~

If repository encryption is used, the repository is inaccessible
without the key. This command allows to backup this essential key.

There are two backup formats. The normal backup format is suitable for
digital storage as a file. The ``--paper`` backup format is optimized
for printing and typing in while importing, with per line checks to
reduce problems with manual input.

For repositories using keyfile encryption the key is saved locally
on the system that is capable of doing backups. To guard against loss
of this key, the key needs to be backed up independently of the main
data backup.

For repositories using the repokey encryption the key is saved in the
repository in the config file. A backup is thus not strictly needed,
but guards against the repository becoming inaccessible if the file
is damaged for some reason.

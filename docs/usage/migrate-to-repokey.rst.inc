.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_migrate-to-repokey:

borg migrate-to-repokey
-----------------------
::

    usage: borg migrate-to-repokey [-h] [--critical] [--error] [--warning]
                                   [--info] [--debug] [--lock-wait N] [--show-rc]
                                   [--no-files-cache] [--umask M]
                                   [--remote-path PATH]
                                   [REPOSITORY]
    
    Migrate passphrase -> repokey
    
    positional arguments:
      REPOSITORY
    
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

This command migrates a repository from passphrase mode (not supported any
more) to repokey mode.

You will be first asked for the repository passphrase (to open it in passphrase
mode). This is the same passphrase as you used to use for this repo before 1.0.

It will then derive the different secrets from this passphrase.

Then you will be asked for a new passphrase (twice, for safety). This
passphrase will be used to protect the repokey (which contains these same
secrets in encrypted form). You may use the same passphrase as you used to
use, but you may also use a different one.

After migrating to repokey mode, you can change the passphrase at any time.
But please note: the secrets will always stay the same and they could always
be derived from your (old) passphrase-mode passphrase.

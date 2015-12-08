.. _borg_upgrade:

borg upgrade
------------
::

    usage: borg upgrade [-h] [-v] [--debug] [--lock-wait N] [--show-rc]
                        [--no-files-cache] [--umask M] [--remote-path PATH] [-n]
                        [-i]
                        [REPOSITORY]
    
    upgrade a repository from a previous version
    
    positional arguments:
      REPOSITORY            path to the repository to be upgraded
    
    optional arguments:
      -h, --help            show this help message and exit
      -v, --verbose, --info
                            enable informative (verbose) output, work on log level
                            INFO
      --debug               enable debug output, work on log level DEBUG
      --lock-wait N         wait for the lock, but max. N seconds (default: 1).
      --show-rc             show/log the return code (rc)
      --no-files-cache      do not load/update the file metadata cache used to
                            detect unchanged files
      --umask M             set umask to M (local and remote, default: 0077)
      --remote-path PATH    set remote path to executable (default: "borg")
      -n, --dry-run         do not change repository
      -i, --inplace         rewrite repository in place, with no chance of going
                            back to older versions of the repository.
    
Description
~~~~~~~~~~~

upgrade an existing Borg repository. this currently
only support converting an Attic repository, but may
eventually be extended to cover major Borg upgrades as well.

it will change the magic strings in the repository's segments
to match the new Borg magic strings. the keyfiles found in
$ATTIC_KEYS_DIR or ~/.attic/keys/ will also be converted and
copied to $BORG_KEYS_DIR or ~/.borg/keys.

the cache files are converted, from $ATTIC_CACHE_DIR or
~/.cache/attic to $BORG_CACHE_DIR or ~/.cache/borg, but the
cache layout between Borg and Attic changed, so it is possible
the first backup after the conversion takes longer than expected
due to the cache resync.

upgrade should be able to resume if interrupted, although it
will still iterate over all segments. if you want to start
from scratch, use `borg delete` over the copied repository to
make sure the cache files are also removed:

    borg delete borg

unless ``--inplace`` is specified, the upgrade process first
creates a backup copy of the repository, in
REPOSITORY.upgrade-DATETIME, using hardlinks. this takes
longer than in place upgrades, but is much safer and gives
progress information (as opposed to ``cp -al``). once you are
satisfied with the conversion, you can safely destroy the
backup copy.

WARNING: running the upgrade in place will make the current
copy unusable with older version, with no way of going back
to previous versions. this can PERMANENTLY DAMAGE YOUR
REPOSITORY!  Attic CAN NOT READ BORG REPOSITORIES, as the
magic strings have changed. you have been warned.
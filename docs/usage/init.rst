.. include:: init.rst.inc

Examples
~~~~~~~~
::

    # Local repository, repokey encryption, BLAKE2b (often faster, since Borg 1.1)
    $ borg init --encryption=repokey-blake2 /path/to/repo

    # Local repository (no encryption)
    $ borg init --encryption=none /path/to/repo

    # Remote repository (accesses a remote borg via ssh)
    # repokey: stores the (encrypted) key into <REPO_DIR>/config
    $ borg init --encryption=repokey-blake2 user@hostname:backup

    # Remote repository (accesses a remote borg via ssh)
    # keyfile: stores the (encrypted) key into ~/.config/borg/keys/
    $ borg init --encryption=keyfile user@hostname:backup

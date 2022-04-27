.. include:: init.rst.inc

Examples
~~~~~~~~
::

    # Local repository, recommended repokey AEAD crypto modes
    $ borg init --encryption=repokey-aes-ocb /path/to/repo
    $ borg init --encryption=repokey-chacha20-poly1305 /path/to/repo
    $ borg init --encryption=repokey-blake2-aes-ocb /path/to/repo
    $ borg init --encryption=repokey-blake2-chacha20-poly1305 /path/to/repo

    # Local repository (no encryption), not recommended
    $ borg init --encryption=none /path/to/repo

    # Remote repository (accesses a remote borg via ssh)
    # repokey: stores the (encrypted) key into <REPO_DIR>/config
    $ borg init --encryption=repokey-aes-ocb user@hostname:backup

    # Remote repository (accesses a remote borg via ssh)
    # keyfile: stores the (encrypted) key into ~/.config/borg/keys/
    $ borg init --encryption=keyfile-aes-ocb user@hostname:backup

.. _borg_repo_create:

.. include:: repo-create.rst.inc

Examples
~~~~~~~~
::

    # Local repository
    $ export BORG_REPO=/path/to/repo
    # Recommended repokey AEAD cryptographic modes
    $ borg repo-create --encryption=repokey-aes-ocb
    $ borg repo-create --encryption=repokey-chacha20-poly1305
    $ borg repo-create --encryption=repokey-blake2-aes-ocb
    $ borg repo-create --encryption=repokey-blake2-chacha20-poly1305
    # No encryption (not recommended)
    $ borg repo-create --encryption=authenticated
    $ borg repo-create --encryption=authenticated-blake2
    $ borg repo-create --encryption=none

    # Remote repository (accesses a remote Borg via SSH)
    $ export BORG_REPO=ssh://user@hostname/~/backup
    # repokey: stores the encrypted key in <REPO_DIR>/config
    $ borg repo-create --encryption=repokey-aes-ocb
    # keyfile: stores the encrypted key in ~/.config/borg/keys/
    $ borg repo-create --encryption=keyfile-aes-ocb


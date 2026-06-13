.. _borg_repo_create:

.. include:: repo-create.rst.inc

Examples
~~~~~~~~
::

    # Local repository
    $ export BORG_REPO=/path/to/repo
    # Recommended AEAD cryptographic modes (key stored in the repository by default)
    $ borg repo-create --encryption=aes-ocb
    $ borg repo-create --encryption=chacha20-poly1305
    $ borg repo-create --encryption=blake3-aes-ocb
    $ borg repo-create --encryption=blake3-chacha20-poly1305
    # No encryption (not recommended)
    $ borg repo-create --encryption=authenticated
    $ borg repo-create --encryption=authenticated-blake3
    $ borg repo-create --encryption=none

    # The crypto suite (--encryption) and where the key is stored (--key-location) are
    # chosen independently. --key-location defaults to repokey.
    # repokey: stores the encrypted key inside the repository
    $ borg repo-create --encryption=aes-ocb --key-location=repokey
    # keyfile: stores the encrypted key in the config dir's keys/ subdir
    # (e.g. ~/.config/borg/keys/ on Linux, ~/Library/Application Support/borg/keys/ on macOS)
    $ borg repo-create --encryption=aes-ocb --key-location=keyfile


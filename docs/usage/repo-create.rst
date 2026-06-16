.. _borg_repo_create:

.. include:: repo-create.rst.inc

Examples
~~~~~~~~
::

    # Local repository
    $ export BORG_REPO=/path/to/repo
    # Recommended AEAD cryptographic modes (key stored in the repository by default)
    $ borg repo-create --encryption=aes256-ocb
    $ borg repo-create --encryption=chacha20-poly1305
    # No encryption (not recommended)
    $ borg repo-create --encryption=authenticated
    $ borg repo-create --encryption=none

    # --encryption (the cipher / AE algorithm) and --id-hash (the id hash function) are
    # chosen independently. --id-hash defaults to sha256; use blake3 if it is faster on
    # your hardware (run 'borg benchmark cpu' to find out). The 'none' encryption only
    # supports the sha256 id hash.
    $ borg repo-create --encryption=aes256-ocb --id-hash=blake3
    $ borg repo-create --encryption=chacha20-poly1305 --id-hash=blake3
    $ borg repo-create --encryption=authenticated --id-hash=blake3

    # Where the key is stored (--key-location) is also chosen independently.
    # --key-location defaults to repokey.
    # repokey: stores the encrypted key inside the repository
    $ borg repo-create --encryption=aes256-ocb --key-location=repokey
    # keyfile: stores the encrypted key in the config dir's keys/ subdir
    # (e.g. ~/.config/borg/keys/ on Linux, ~/Library/Application Support/borg/keys/ on macOS)
    $ borg repo-create --encryption=aes256-ocb --key-location=keyfile


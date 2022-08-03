.. _borg-rcreate:

.. include:: rcreate.rst.inc

Examples
~~~~~~~~
::

    # Local repository
    $ export BORG_REPO=/path/to/repo
    # recommended repokey AEAD crypto modes
    $ borg rcreate --encryption=repokey-aes-ocb
    $ borg rcreate --encryption=repokey-chacha20-poly1305
    $ borg rcreate --encryption=repokey-blake2-aes-ocb
    $ borg rcreate --encryption=repokey-blake2-chacha20-poly1305
    # no encryption, not recommended
    $ borg rcreate --encryption=authenticated
    $ borg rcreate --encryption=authenticated-blake2
    $ borg rcreate --encryption=none

    # Remote repository (accesses a remote borg via ssh)
    $ export BORG_REPO=ssh://user@hostname/~/backup
    # repokey: stores the (encrypted) key into <REPO_DIR>/config
    $ borg rcreate --encryption=repokey-aes-ocb
    # keyfile: stores the (encrypted) key into ~/.config/borg/keys/
    $ borg rcreate --encryption=keyfile-aes-ocb


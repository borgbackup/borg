.. include:: upgrade.rst.inc

Examples
~~~~~~~~
::

    # Upgrade the borg repository to the most recent version.
    $ borg upgrade -v /path/to/repo
    making a hardlink copy in /path/to/repo.upgrade-2016-02-15-20:51:55
    opening attic repository with borg and converting
    no key file found for repository
    converting repo index /path/to/repo/index.0
    converting 1 segments...
    converting borg 0.xx to borg current
    no key file found for repository

.. _borg_key_migrate-to-repokey:

Upgrading a passphrase encrypted attic repo
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

attic offered a "passphrase" encryption mode, but this was removed in borg 1.0
and replaced by the "repokey" mode (which stores the passphrase-protected
encryption key into the repository config).

Thus, to upgrade a "passphrase" attic repo to a "repokey" borg repo, 2 steps
are needed, in this order:

- borg upgrade repo
- borg key migrate-to-repokey repo

.. _borg-change-passphrase:

.. include:: key_change-passphrase.rst.inc

Examples
~~~~~~~~
::

    # Create a key file protected repository
    $ borg init --encryption=keyfile -v /path/to/repo
    Initializing repository at "/path/to/repo"
    Enter new passphrase:
    Enter same passphrase again:
    Remember your passphrase. Your data will be inaccessible without it.
    Key in "/root/.config/borg/keys/mnt_backup" created.
    Keep this key safe. Your data will be inaccessible without it.
    Synchronizing chunks cache...
    Archives: 0, w/ cached Idx: 0, w/ outdated Idx: 0, w/o cached Idx: 0.
    Done.

    # Change key file passphrase
    $ borg key change-passphrase -v /path/to/repo
    Enter passphrase for key /root/.config/borg/keys/mnt_backup:
    Enter new passphrase:
    Enter same passphrase again:
    Remember your passphrase. Your data will be inaccessible without it.
    Key updated

Fully automated using environment variables:

::

    $ BORG_NEW_PASSPHRASE=old borg init -e=repokey repo
    # now "old" is the current passphrase.
    $ BORG_PASSPHRASE=old BORG_NEW_PASSPHRASE=new borg key change-passphrase repo
    # now "new" is the current passphrase.


.. include:: key_export.rst.inc

.. include:: key_import.rst.inc

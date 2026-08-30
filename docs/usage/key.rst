.. include:: key_change-location.rst.inc

.. _borg-change-passphrase:

.. include:: key_change-passphrase.rst.inc

Examples
~~~~~~~~
::

    # Create a key file protected repository
    $ borg repo-create --encryption=aes256-ocb --key-location=keyfile -v
    Initializing repository at "/path/to/repo"
    Enter new passphrase:
    Enter same passphrase again:
    Do you want your passphrase to be displayed for verification? [yN]: n
    Remember your passphrase. Your data will be inaccessible without it.
    Key in "/root/.config/borg/keys/f23b5f0703c06dc7d9d889b5867496d8cb8ef5b42a5005221d3c7373ec6d6353" created.
    Keep this key safe. Your data will be inaccessible without it.
    ...

    # Change key file passphrase
    $ borg key change-passphrase -v
    Enter passphrase for key /root/.config/borg/keys/f23b5f0703c06dc7d9d889b5867496d8cb8ef5b42a5005221d3c7373ec6d6353:
    Enter new passphrase:
    Enter same passphrase again:
    Do you want your passphrase to be displayed for verification? [yN]: n
    Remember your passphrase. Your data will be inaccessible without it.
    Key updated
    Key location: /root/.config/borg/keys/4881c2f73d9f173bd4c4d30a9f397a596bc742bfa1f652fac3f83cee3f26cb00

.. note::

    Automatically placed key files are named after the SHA-256 hash of their own
    contents, not after the repository directory name. Because changing the
    passphrase re-encrypts the key, the key file is rewritten under a new name and
    the previous one is removed — that is why the two paths above differ. Use
    ``BORG_KEY_FILE`` if you want to choose the key file name yourself.

    The key file paths shown above are the defaults for Linux (``~/.config/borg/keys/``).
    On macOS, key files are stored in ``~/Library/Application Support/borg/keys/``.
    On Windows, they are stored in ``C:\Users\<user>\AppData\Roaming\borg\keys\``.
    See :ref:`env_vars` for details.

::

    # Import a previously-exported key into a key file, using BORG_KEY_FILE to
    # choose the output key file (creating or overwriting it).
    # --key-location=keyfile is required: "borg key import" defaults to
    # --key-location=repokey, which stores the key in the repository and
    # ignores BORG_KEY_FILE.
    $ BORG_KEY_FILE=/path/to/output-key borg key import --key-location=keyfile /path/to/exported

Fully automated using environment variables:

::

    $ BORG_NEW_PASSPHRASE=old borg repo-create --encryption=aes256-ocb
    # now "old" is the current passphrase.
    $ BORG_PASSPHRASE=old BORG_NEW_PASSPHRASE=new borg key change-passphrase
    # now "new" is the current passphrase.


.. include:: key_export.rst.inc

Examples
~~~~~~~~
::

    borg key export > encrypted-key-backup
    borg key export --paper > encrypted-key-backup.txt
    borg key export --qr-html > encrypted-key-backup.html
    # Or pass the output file as an argument instead of redirecting stdout:
    borg key export encrypted-key-backup
    borg key export --paper encrypted-key-backup.txt
    borg key export --qr-html encrypted-key-backup.html

.. include:: key_import.rst.inc

.. include:: key_add.rst.inc

.. include:: key_list.rst.inc

.. include:: key_remove.rst.inc

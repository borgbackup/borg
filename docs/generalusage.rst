.. include:: global.rst.inc
.. _generalusage:

General Usage
=============

The following examples showcases how to use |project_name| to backup some
important files from a users home directory (for more detailed information
about each subcommand see the :ref:`detailed_usage` section).

Initialize a local :ref:`repository <repository_def>` to store backup
:ref:`archives <archive_def>` in (See :ref:`encrypted_repos` and
:ref:`remote_repos` for more details)::

    $ darc init /somewhere/my-backup.darc

Create an archive containing the ``~/src`` and ``~/Documents`` directories::

    $ darc create -v /somwhere/my-backup.darc::first-backup ~/src ~/Documents

Create another archive the next day. This backup will be a lot quicker since
only new data is stored. The ``--stats`` option tells |project_name| to print
statistics about the newly created archive such as the amount of unique data
(not shared with other archives)::

    $ darc create -v --stats /somwhere/my-backup.darc::second-backup ~/src ~/Documents

List all archives in the repository::

    $ darc list /somewhere/my-backup.darc

List the files in the *first-backup* archive::

    $ darc list /somewhere/my-backup.darc::first-backup

Restore the *first-backup* archive::

    $ darc extract -v /somwhere/my-backup.darc::first-backup

Recover disk space by manually deleting the *first-backup* archive::

    $ darc delete /somwhere/my-backup.darc::first-backup

Use the ``prune`` subcommand to delete all archives except a given number of
*daily*, *weekly*, *monthly* and *yearly* archives::

    $ darc prune /somwhere/my-backup.darc --daily=7 --weekly=2 --monthly=6


.. _encrypted_repos:

Repository encryption
---------------------

Repository encryption is enabled at repository encryption time::

    $ darc init --passphrase | --key-file

When repository encryption is enabled all data is encrypted using 256-bit AES_
encryption and the integrity and authenticity is verified using `HMAC-SHA256`_.

|project_name| supports two different methods to derive the AES and HMAC keys.

Passphrase based encryption
    This method uses a user supplied passphrase to derive the keys using the
    PBKDF2_ key derivation function. This method is convenient to use and
    secure as long as a *strong* passphrase is used.

Key file based encryption
    This method generates random keys at repository initialization time that
    are stored in a password protected file in the ``~/.darc/keys/`` directory.
    This method is secure and suitable for automated backups.

    .. Note::
        The repository data is totally inaccessible without the key file
        so it must be kept **safe**.


.. _remote_repos:

Remote repositories
-------------------

|project_name| can initialize and access repositories on remote hosts as the
host is accessible using SSH and |project_name| is installed.

The following syntax is used to address remote repositories::

  $ darc init user@hostname:repository.darc

or::

  $ darc init ssh://user@hostname:port/repository.darc

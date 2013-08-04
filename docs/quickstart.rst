.. include:: global.rst.inc
.. _quickstart:

Quick Start
===========

This chapter will get you started with |project_name|. The first section
presents a simple step by step example that uses |project_name| to backup data.
The next section continues by showing how backups can be automated.

A step by step example
----------------------

1. Before any backup can be taken a repository has to be initialized::

    $ attic init /somewhere/my-backup.attic

2. Backup the ``~/src`` and ``~/Documents`` directories into an archive called
   *first-backup*::

    $ attic create -v /somwhere/my-backup.attic::first-backup ~/src ~/Documents

3. The next day create a new archive called *second-backup*::

    $ attic create -v --stats /somwhere/my-backup.attic::second-backup ~/src ~/Documents

   This backup will be a lot quicker and a lot smaller since only new never
   before seen data is stored. The ``--stats`` causes |project_name| to output
   statistics about the newly created archive such as the amount of unique
   data (not shared with other archives).

4. List all archives in the repository::

    $ attic list /somewhere/my-backup.attic

5. List the contents of the *first-backup* archive::

    $ attic list /somewhere/my-backup.attic::first-backup

6. Restore the *first-backup* archive::

    $ attic extract -v /somwhere/my-backup.attic::first-backup

7. Recover disk space by manually deleting the *first-backup* archive::

    $ attic delete /somwhere/my-backup.attic::first-backup


Automating backups
------------------

The following example script backups up ``/home`` and
``/var/www`` to a remote server. The script also uses the
:ref:`attic_prune` subcommand to maintain a certain number
of old archives::

    #!/bin/sh
    REPOSITORY=username@remoteserver.com:backup.attic

    # Backup all of /home and /var/www except a few
    # excluded directories
    attic create --stats                            \
        $REPOSITORY::hostname-`date +%Y-%m-%d`      \
        /home                                       \
        /var/www                                    \
        --exclude /home/*/.cache                    \
        --exclude /home/Ben/Music/Justin\ Bieber    \
        --exclude *.pyc

    # Use the `prune` subcommand to maintain 7 daily, 4 weekly
    # and 6 monthly archives.
    attic prune -v $REPOSITORY --daily=7 --weekly=4 --monthly=6

.. Note::
    This script assumes the repository has already been initalized with
    :ref:`attic_init`.

.. _encrypted_repos:

Repository encryption
---------------------

Repository encryption is enabled at repository encryption time::

    $ attic init --passphrase | --key-file

When repository encryption is enabled all data is encrypted using 256-bit AES_
encryption and the integrity and authenticity is verified using `HMAC-SHA256`_.

|project_name| supports two different methods to derive the AES and HMAC keys.

Passphrase based encryption
    This method uses a user supplied passphrase to derive the keys using the
    PBKDF2_ key derivation function. This method is convenient to use and
    secure as long as a *strong* passphrase is used.

    .. Note::
        For automated backups the passphrase can be specified using the
        `ATTIC_PASSPHRASE` environment variable.

Key file based encryption
    This method generates random keys at repository initialization time that
    are stored in a password protected file in the ``~/.attic/keys/`` directory.
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

  $ attic init user@hostname:repository.attic

or::

  $ attic init ssh://user@hostname:port/repository.attic

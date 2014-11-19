.. include:: global.rst.inc
.. _quickstart:

Quick Start
===========

This chapter will get you started with |project_name|. The first section
presents a simple step by step example that uses |project_name| to backup data.
The next section continues by showing how backups can be automated.

A step by step example
----------------------

1. Before a backup can be made a repository has to be initialized::

    $ attic init /somewhere/my-repository.attic

2. Backup the ``~/src`` and ``~/Documents`` directories into an archive called
   *Monday*::

    $ attic create /somewhere/my-repository.attic::Monday ~/src ~/Documents

3. The next day create a new archive called *Tuesday*::

    $ attic create --stats /somewhere/my-repository.attic::Tuesday ~/src ~/Documents

   This backup will be a lot quicker and a lot smaller since only new never
   before seen data is stored. The ``--stats`` option causes |project_name| to
   output statistics about the newly created archive such as the amount of unique
   data (not shared with other archives)::

    Archive name: Tuesday
    Archive fingerprint: 387a5e3f9b0e792e91ce87134b0f4bfe17677d9248cb5337f3fbf3a8e157942a
    Start time: Tue Mar 25 12:00:10 2014
    End time:   Tue Mar 25 12:00:10 2014
    Duration: 0.08 seconds
    Number of files: 358
                           Original size      Compressed size    Deduplicated size
    This archive:               57.16 MB             46.78 MB            151.67 kB
    All archives:              114.02 MB             93.46 MB             44.81 MB


4. List all archives in the repository::

    $ attic list /somewhere/my-repository.attic
    Monday                               Mon Mar 24 11:59:35 2014
    Tuesday                              Tue Mar 25 12:00:10 2014

5. List the contents of the *Monday* archive::

    $ attic list /somewhere/my-repository.attic::Monday
    drwxr-xr-x user  group         0 Jan 06 15:22 home/user/Documents
    -rw-r--r-- user  group      7961 Nov 17  2012 home/user/Documents/Important.doc
    ...

6. Restore the *Monday* archive::

    $ attic extract /somwhere/my-repository.attic::Monday

7. Recover disk space by manually deleting the *Monday* archive::

    $ attic delete /somwhere/my-backup.attic::Monday

.. Note::
    Attic is quiet by default. Add the ``-v`` or ``--verbose`` option to
    get progress reporting during command execution.

Automating backups
------------------

The following example script backs up ``/home`` and
``/var/www`` to a remote server. The script also uses the
:ref:`attic_prune` subcommand to maintain a certain number
of old archives::

    #!/bin/sh
    REPOSITORY=username@remoteserver.com:repository.attic

    # Backup all of /home and /var/www except a few
    # excluded directories
    attic create --stats                            \
        $REPOSITORY::hostname-`date +%Y-%m-%d`      \
        /home                                       \
        /var/www                                    \
        --exclude /home/*/.cache                    \
        --exclude /home/Ben/Music/Justin\ Bieber    \
        --exclude '*.pyc'

    # Use the `prune` subcommand to maintain 7 daily, 4 weekly
    # and 6 monthly archives.
    attic prune -v $REPOSITORY --keep-daily=7 --keep-weekly=4 --keep-monthly=6

.. _encrypted_repos:

Repository encryption
---------------------

Repository encryption is enabled at repository creation time::

    $ attic init --encryption=passphrase|keyfile PATH

When repository encryption is enabled all data is encrypted using 256-bit AES_
encryption and the integrity and authenticity is verified using `HMAC-SHA256`_.

All data is encrypted before being written to the repository. This means that
an attacker that manages to compromise the host containing an encrypted
archive will not be able to access any of the data.

|project_name| supports two different methods to derive the AES and HMAC keys.

Passphrase based encryption
    This method uses a user supplied passphrase to derive the keys using the
    PBKDF2_ key derivation function. This method is convenient to use since
    there is no key file to keep track of and secure as long as a *strong*
    passphrase is used.

    .. Note::
        For automated backups the passphrase can be specified using the
        `ATTIC_PASSPHRASE` environment variable.

Key file based encryption
    This method generates random keys at repository initialization time that
    are stored in a password protected file in the ``~/.attic/keys/`` directory.
    The key file is a printable text file. This method is secure and suitable
    for automated backups.

    .. Note::
        The repository data is totally inaccessible without the key file
        so it must be kept **safe**.


.. _remote_repos:

Remote repositories
-------------------

|project_name| can initialize and access repositories on remote hosts if the
host is accessible using SSH.  This is fastest and easiest when |project_name|
is installed on the remote host, in which case the following syntax is used::

  $ attic init user@hostname:repository.attic

or::

  $ attic init ssh://user@hostname:port/repository.attic

If it is not possible to install |project_name| on the remote host, 
it is still possible to use the remote host to store a repository by
mounting the remote filesystem, for example, using sshfs::

  $ sshfs user@hostname:/path/to/folder /tmp/mymountpoint
  $ attic init /tmp/mymountpoint/repository.attic
  $ fusermount -u /tmp/mymountpoint

However, be aware that sshfs doesn't fully implement POSIX locks, so
you must be sure to not have two processes trying to access the same
repository at the same time.

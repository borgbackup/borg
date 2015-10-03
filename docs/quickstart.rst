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

    $ borg init /mnt/backup

2. Backup the ``~/src`` and ``~/Documents`` directories into an archive called
   *Monday*::

    $ borg create /mnt/backup::Monday ~/src ~/Documents

3. The next day create a new archive called *Tuesday*::

    $ borg create --stats /mnt/backup::Tuesday ~/src ~/Documents

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

    $ borg list /mnt/backup
    Monday                               Mon Mar 24 11:59:35 2014
    Tuesday                              Tue Mar 25 12:00:10 2014

5. List the contents of the *Monday* archive::

    $ borg list /mnt/backup::Monday
    drwxr-xr-x user  group         0 Jan 06 15:22 home/user/Documents
    -rw-r--r-- user  group      7961 Nov 17  2012 home/user/Documents/Important.doc
    ...

6. Restore the *Monday* archive::

    $ borg extract /mnt/backup::Monday

7. Recover disk space by manually deleting the *Monday* archive::

    $ borg delete /mnt/backup::Monday

.. Note::
    Borg is quiet by default. Add the ``-v`` or ``--verbose`` option to
    get progress reporting during command execution.

Automating backups
------------------

The following example script backs up ``/home`` and ``/var/www`` to a remote
server. The script also uses the :ref:`borg_prune` subcommand to maintain a
certain number of old archives::

    #!/bin/sh
    REPOSITORY=username@remoteserver.com:backup

    # Backup all of /home and /var/www except a few
    # excluded directories
    borg create --stats                             \
        $REPOSITORY::`hostname`-`date +%Y-%m-%d`    \
        /home                                       \
        /var/www                                    \
        --exclude /home/*/.cache                    \
        --exclude /home/Ben/Music/Justin\ Bieber    \
        --exclude '*.pyc'

    # Use the `prune` subcommand to maintain 7 daily, 4 weekly and 6 monthly
    # archives of THIS machine. --prefix `hostname`- is very important to
    # limit prune's operation to this machine's archives and not apply to
    # other machine's archives also.
    borg prune -v $REPOSITORY --prefix `hostname`- \
        --keep-daily=7 --keep-weekly=4 --keep-monthly=6

.. backup_compression:

Backup compression
------------------

Default is no compression, but we support different methods with high speed
or high compression:

If you have a quick repo storage and you want a little compression:

    $ borg create --compression lz4 /mnt/backup::repo ~

If you have a medium fast repo storage and you want a bit more compression (N=0..9,
0 means no compression, 9 means high compression):

    $ borg create --compression zlib,N /mnt/backup::repo ~

If you have a very slow repo storage and you want high compression (N=0..9, 0 means
low compression, 9 means high compression):

    $ borg create --compression lzma,N /mnt/backup::repo ~

You'll need to experiment a bit to find the best compression for your use case.
Keep an eye on CPU load and throughput.

.. _encrypted_repos:

Repository encryption
---------------------

Repository encryption is enabled at repository creation time::

    $ borg init --encryption=repokey|keyfile PATH

When repository encryption is enabled all data is encrypted using 256-bit AES_
encryption and the integrity and authenticity is verified using `HMAC-SHA256`_.

All data is encrypted before being written to the repository. This means that
an attacker who manages to compromise the host containing an encrypted
archive will not be able to access any of the data.

|project_name| supports different methods to store the AES and HMAC keys.

``repokey`` mode
    The key is stored inside the repository (in its "config" file).
    Use this mode if you trust in your good passphrase giving you enough
    protection.

``keyfile`` mode
    The key is stored on your local disk (in ``~/.borg/keys/``).
    Use this mode if you want "passphrase and having-the-key" security.

In both modes, the key is stored in encrypted form and can be only decrypted
by providing the correct passphrase.

For automated backups the passphrase can be specified using the
`BORG_PASSPHRASE` environment variable.

**The repository data is totally inaccessible without the key:**
    Make a backup copy of the key file (``keyfile`` mode) or repo config
    file (``repokey`` mode) and keep it at a safe place, so you still have
    the key in case it gets corrupted or lost.
    The backup that is encrypted with that key won't help you with that,
    of course.

.. _remote_repos:

Remote repositories
-------------------

|project_name| can initialize and access repositories on remote hosts if the
host is accessible using SSH.  This is fastest and easiest when |project_name|
is installed on the remote host, in which case the following syntax is used::

  $ borg init user@hostname:/mnt/backup

or::

  $ borg init ssh://user@hostname:port//mnt/backup

Remote operations over SSH can be automated with SSH keys. You can restrict the
use of the SSH keypair by prepending a forced command to the SSH public key in
the remote server's authorized_keys file. Only the forced command will be run
when the key authenticates a connection. This example will start |project_name| in server
mode, and limit the |project_name| server to a specific filesystem path::

  command="borg serve --restrict-to-path /mnt/backup" ssh-rsa AAAAB3[...]

If it is not possible to install |project_name| on the remote host,
it is still possible to use the remote host to store a repository by
mounting the remote filesystem, for example, using sshfs::

  $ sshfs user@hostname:/mnt /mnt
  $ borg init /mnt/backup
  $ fusermount -u /mnt


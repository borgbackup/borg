.. include:: global.rst.inc
.. highlight:: bash
.. _quickstart:

Quick Start
===========

This chapter will get you started with |project_name|. The first section
presents a simple step by step example that uses |project_name| to backup data.
The next section continues by showing how backups can be automated.

Important note about free space
-------------------------------

Before you start creating backups, please make sure that there is *always*
a good amount of free space on the filesystem that has your backup repository
(and also on ~/.cache). A few GB should suffice for most hard-drive sized
repositories. See also :ref:`cache-memory-usage`.

If |project_name| runs out of disk space, it tries to free as much space as it
can while aborting the current operation safely, which allows to free more space
by deleting/pruning archives. This mechanism is not bullet-proof though.
If you *really* run out of disk space, it can be hard or impossible to free space,
because |project_name| needs free space to operate - even to delete backup
archives. There is a ``--save-space`` option for some commands, but even with
that |project_name| will need free space to operate.

You can use some monitoring process or just include the free space information
in your backup log files (you check them regularly anyway, right?).

Also helpful:

- create a big file as a "space reserve", that you can delete to free space
- if you use LVM: use a LV + a filesystem that you can resize later and have
  some unallocated PEs you can add to the LV.
- consider using quotas
- use `prune` regularly


A step by step example
----------------------

1. Before a backup can be made a repository has to be initialized::

    $ borg init /path/to/repo

2. Backup the ``~/src`` and ``~/Documents`` directories into an archive called
   *Monday*::

    $ borg create /path/to/repo::Monday ~/src ~/Documents

3. The next day create a new archive called *Tuesday*::

    $ borg create -v --stats /path/to/repo::Tuesday ~/src ~/Documents

   This backup will be a lot quicker and a lot smaller since only new never
   before seen data is stored. The ``--stats`` option causes |project_name| to
   output statistics about the newly created archive such as the amount of unique
   data (not shared with other archives)::

    ------------------------------------------------------------------------------
    Archive name: Tuesday
    Archive fingerprint: bd31004d58f51ea06ff735d2e5ac49376901b21d58035f8fb05dbf866566e3c2
    Time (start): Tue, 2016-02-16 18:15:11
    Time (end):   Tue, 2016-02-16 18:15:11

    Duration: 0.19 seconds
    Number of files: 127
    ------------------------------------------------------------------------------
                          Original size      Compressed size    Deduplicated size
    This archive:                4.16 MB              4.17 MB             26.78 kB
    All archives:                8.33 MB              8.34 MB              4.19 MB

                          Unique chunks         Total chunks
    Chunk index:                     132                  261
    ------------------------------------------------------------------------------

4. List all archives in the repository::

    $ borg list /path/to/repo
    Monday                               Mon, 2016-02-15 19:14:44
    Tuesday                              Tue, 2016-02-16 19:15:11

5. List the contents of the *Monday* archive::

    $ borg list /path/to/repo::Monday
    drwxr-xr-x user   group          0 Mon, 2016-02-15 18:22:30 home/user/Documents
    -rw-r--r-- user   group       7961 Mon, 2016-02-15 18:22:30 home/user/Documents/Important.doc
    ...

6. Restore the *Monday* archive::

    $ borg extract /path/to/repo::Monday

7. Recover disk space by manually deleting the *Monday* archive::

    $ borg delete /path/to/repo::Monday

.. Note::
    Borg is quiet by default (it works on WARNING log level).
    Add the ``-v`` (or ``--verbose`` or ``--info``) option to adjust the log
    level to INFO and also use options like ``--progress`` or ``--list`` to
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
    borg create -v --stats                          \
        $REPOSITORY::'{hostname}-{now:%Y-%m-%d}'    \
        /home                                       \
        /var/www                                    \
        --exclude '/home/*/.cache'                  \
        --exclude /home/Ben/Music/Justin\ Bieber    \
        --exclude '*.pyc'

    # Use the `prune` subcommand to maintain 7 daily, 4 weekly and 6 monthly
    # archives of THIS machine. The '{hostname}-' prefix is very important to
    # limit prune's operation to this machine's archives and not apply to
    # other machine's archives also.
    borg prune -v $REPOSITORY --prefix '{hostname}-' \
        --keep-daily=7 --keep-weekly=4 --keep-monthly=6

Pitfalls with shell variables and environment variables
-------------------------------------------------------

This applies to all environment variables you want borg to see, not just
``BORG_PASSPHRASE``. The short explanation is: always ``export`` your variable,
and use single quotes if you're unsure of the details of your shell's expansion
behavior. E.g.::

    export BORG_PASSPHRASE='complicated & long'

This is because ``export`` exposes variables to subprocesses, which borg may be
one of. More on ``export`` can be found in the "ENVIRONMENT" section of the
bash(1) man page.

Beware of how ``sudo`` interacts with environment variables. For example, you
may be surprised that the following ``export`` has no effect on your command::

   export BORG_PASSPHRASE='complicated & long'
   sudo ./yourborgwrapper.sh  # still prompts for password

For more information, see sudo(8) man page. Hint: see ``env_keep`` in
sudoers(5), or try ``sudo BORG_PASSPHRASE='yourphrase' borg`` syntax.

.. Tip::
    To debug what your borg process is actually seeing, find its PID
    (``ps aux|grep borg``) and then look into ``/proc/<PID>/environ``.

.. backup_compression:

Backup compression
------------------

Default is no compression, but we support different methods with high speed
or high compression:

If you have a fast repo storage and you want some compression: ::

    $ borg create --compression lz4 /path/to/repo::arch ~

If you have a less fast repo storage and you want a bit more compression (N=0..9,
0 means no compression, 9 means high compression): ::

    $ borg create --compression zlib,N /path/to/repo::arch ~

If you have a very slow repo storage and you want high compression (N=0..9, 0 means
low compression, 9 means high compression): ::

    $ borg create --compression lzma,N /path/to/repo::arch ~

You'll need to experiment a bit to find the best compression for your use case.
Keep an eye on CPU load and throughput.

.. _encrypted_repos:

Repository encryption
---------------------

Repository encryption can be enabled or disabled at repository creation time
(the default is enabled, with `repokey` method)::

    $ borg init --encryption=none|repokey|keyfile PATH

When repository encryption is enabled all data is encrypted using 256-bit AES_
encryption and the integrity and authenticity is verified using `HMAC-SHA256`_.

All data is encrypted on the client before being written to the repository. This
means that an attacker who manages to compromise the host containing an
encrypted archive will not be able to access any of the data, even while the backup
is being made.

|project_name| supports different methods to store the AES and HMAC keys.

``repokey`` mode
    The key is stored inside the repository (in its "config" file).
    Use this mode if you trust in your good passphrase giving you enough
    protection. The repository server never sees the plaintext key.

``keyfile`` mode
    The key is stored on your local disk (in ``~/.config/borg/keys/``).
    Use this mode if you want "passphrase and having-the-key" security.

In both modes, the key is stored in encrypted form and can be only decrypted
by providing the correct passphrase.

For automated backups the passphrase can be specified using the
`BORG_PASSPHRASE` environment variable.

.. note:: Be careful about how you set that environment, see
          :ref:`this note about password environments <password_env>`
          for more information.

.. warning:: The repository data is totally inaccessible without the key
    and the key passphrase.

    Make a backup copy of the key file (``keyfile`` mode) or repo config
    file (``repokey`` mode) and keep it at a safe place, so you still have
    the key in case it gets corrupted or lost. Also keep your passphrase
    at a safe place.

    You can make backups using :ref:`borg_key_export` subcommand.

    If you want to print a backup of your key to paper use the ``--paper``
    option of this command and print the result.

    A backup inside of the backup that is encrypted with that key/passphrase
    won't help you with that, of course.

.. _remote_repos:

Remote repositories
-------------------

|project_name| can initialize and access repositories on remote hosts if the
host is accessible using SSH.  This is fastest and easiest when |project_name|
is installed on the remote host, in which case the following syntax is used::

  $ borg init user@hostname:/path/to/repo

or::

  $ borg init ssh://user@hostname:port//path/to/repo

Remote operations over SSH can be automated with SSH keys. You can restrict the
use of the SSH keypair by prepending a forced command to the SSH public key in
the remote server's `authorized_keys` file. This example will start |project_name|
in server mode and limit it to a specific filesystem path::

  command="borg serve --restrict-to-path /path/to/repo",no-pty,no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc ssh-rsa AAAAB3[...]

If it is not possible to install |project_name| on the remote host,
it is still possible to use the remote host to store a repository by
mounting the remote filesystem, for example, using sshfs::

  $ sshfs user@hostname:/path/to /path/to
  $ borg init /path/to/repo
  $ fusermount -u /path/to

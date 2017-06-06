.. include:: global.rst.inc
.. highlight:: bash
.. _quickstart:

Quick Start
===========

This chapter will get you started with |project_name| and covers
various use cases.

A step by step example
----------------------

.. include:: quickstart_example.rst.inc

Important note about free space
-------------------------------

Before you start creating backups, please make sure that there is *always*
a good amount of free space on the filesystem that has your backup repository
(and also on ~/.cache). A few GB should suffice for most hard-drive sized
repositories. See also :ref:`cache-memory-usage`.

Borg doesn't use space reserved for root on repository disks (even when run as root),
on file systems which do not support this mechanism (e.g. XFS) we recommend to
reserve some space in Borg itself just to be safe by adjusting the
``additional_free_space`` setting in the ``[repository]`` section of a repositories
``config`` file. A good starting point is ``2G``.

If |project_name| runs out of disk space, it tries to free as much space as it
can while aborting the current operation safely, which allows to free more space
by deleting/pruning archives. This mechanism is not bullet-proof in some
circumstances [1]_.

If you *really* run out of disk space, it can be hard or impossible to free space,
because |project_name| needs free space to operate - even to delete backup
archives.

You can use some monitoring process or just include the free space information
in your backup log files (you check them regularly anyway, right?).

Also helpful:

- create a big file as a "space reserve", that you can delete to free space
- if you use LVM: use a LV + a filesystem that you can resize later and have
  some unallocated PEs you can add to the LV.
- consider using quotas
- use `prune` regularly

.. [1] This failsafe can fail in these circumstances:

    - The underlying file system doesn't support statvfs(2), or returns incorrect
      data, or the repository doesn't reside on a single file system
    - Other tasks fill the disk simultaneously
    - Hard quotas (which may not be reflected in statvfs(2))

Automating backups
------------------

The following example script is meant to be run daily by the ``root`` user on
different local machines. It backs up a machine's important files (but not the
complete operating system) to a repository ``~/backup/main``  on a remote server.
Some files which aren't necessarily needed in this backup are excluded. See
:ref:`borg_patterns` on how to add more exclude options.

After the backup this script also uses the :ref:`borg_prune` subcommand to keep
only a certain number of old archives and deletes the others in order to preserve
disk space.

Before running, make sure that the repository is initialized as documented in
:ref:`remote_repos` and that the script has the correct permissions to be executable
by the root user, but not executable or readable by anyone else, i.e. root:root 0700.

You can use this script as a starting point and modify it where it's necessary to fit
your setup.

Do not forget to test your created backups to make sure everything you need is being
backed up and that the ``prune`` command is keeping and deleting the correct backups.

::

    #!/bin/sh

    # Setting this, so the repo does not need to be given on the commandline:
    export BORG_REPO=ssh://username@example.com:2022/~/backup/main

    # Setting this, so you won't be asked for your repository passphrase:
    export BORG_PASSPHRASE='XYZl0ngandsecurepa_55_phrasea&&123'
    # or this to ask an external program to supply the passphrase:
    export BORG_PASSCOMMAND='pass show backup'

    # some helpers and error handling:
    function info  () { echo -e "\n"`date` $@"\n" >&2; }
    trap "echo `date` Backup interrupted >&2; exit 2" SIGINT SIGTERM

    info "Starting backup"

    # Backup the most important directories into an archive named after
    # the machine this script is currently running on:

    borg create                         \
        --verbose                       \
        --filter AME                    \
        --list                          \
        --stats                         \
        --show-rc                       \
        --compression lz4               \
        --exclude-caches                \
        --exclude '/home/*/.cache/*'    \
        --exclude '/var/cache/*'        \
        --exclude '/var/tmp/*'          \
                                        \
        ::'{hostname}-{now}'            \
        /etc                            \
        /home                           \
        /root                           \
        /var                            \

    backup_exit=$?

    info "Pruning repository"

    # Use the `prune` subcommand to maintain 7 daily, 4 weekly and 6 monthly
    # archives of THIS machine. The '{hostname}-' prefix is very important to
    # limit prune's operation to this machine's archives and not apply to
    # other machines' archives also:

    borg prune                          \
        --list                          \
        --prefix '{hostname}-'          \
        --show-rc                       \
        --keep-daily    7               \
        --keep-weekly   4               \
        --keep-monthly  6               \

    prune_exit=$?

    global_exit=$(( ${backup_exit} >  ${prune_exit} ? ${backup_exit} : ${prune_exit} ))

    if [ ${global_exit} -eq 1 ];
    then
        info "Backup and/or Prune finished with a warning"
    fi

    if [ ${global_exit} -gt 1 ];
    then
        info "Backup and/or Prune finished with an error"
    fi

    exit ${global_exit}

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

For more information, refer to the sudo(8) man page and ``env_keep`` in
the sudoers(5) man page.

.. Tip::
    To debug what your borg process is actually seeing, find its PID
    (``ps aux|grep borg``) and then look into ``/proc/<PID>/environ``.

.. backup_compression:

Backup compression
------------------

The default is lz4 (very fast, but low compression ratio), but other methods are
supported for different situations.

If you have a fast repo storage and you want minimum CPU usage, no compression::

    $ borg create --compression none /path/to/repo::arch ~

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
    option of this command and print the result, or this print `template`_
    if you need a version with QR-Code.

    A backup inside of the backup that is encrypted with that key/passphrase
    won't help you with that, of course.

.. _template: paperkey.html

.. _remote_repos:

Remote repositories
-------------------

|project_name| can initialize and access repositories on remote hosts if the
host is accessible using SSH.  This is fastest and easiest when |project_name|
is installed on the remote host, in which case the following syntax is used::

  $ borg init user@hostname:/path/to/repo

Note: please see the usage chapter for a full documentation of repo URLs.

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

You can also use other remote filesystems in a similar way. Just be careful,
not all filesystems out there are really stable and working good enough to
be acceptable for backup usage.

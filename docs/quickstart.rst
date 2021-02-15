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

Archives and repositories
-------------------------

A *Borg archive* is the result of a single backup (``borg create``). An archive
stores a snapshot of the data of the files "inside" it. One can later extract or
mount an archive to restore from a backup.

*Repositories* are filesystem directories acting as self-contained stores of archives.
Repositories can be accessed locally via path or remotely via ssh. Under the hood,
repositories contain data blocks and a manifest tracking which blocks are in each
archive. If some data hasn't changed from one backup to another, Borg can simply
reference an already uploaded data chunk (deduplication).

Important note about free space
-------------------------------

Before you start creating backups, please make sure that there is *always*
a good amount of free space on the filesystem that has your backup repository
(and also on ~/.cache). A few GB should suffice for most hard-drive sized
repositories. See also :ref:`cache-memory-usage`.

Borg doesn't use space reserved for root on repository disks (even when run as root),
on file systems which do not support this mechanism (e.g. XFS) we recommend to reserve
some space in Borg itself just to be safe by adjusting the ``additional_free_space``
setting (a good starting point is ``2G``)::

    borg config /path/to/repo additional_free_space 2G

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

Important note about permissions
--------------------------------

Using root likely will be required if you want to backup files of other users
or the operating system. If you only back up your own files, you neither need
nor want to use root.

Avoid to create a mixup of users and permissions in your repository (or cache).

This can easily happen if you run borg using different user accounts (e.g. your
non-privileged user and root) while accessing the same repo.

Of course, a non-root user will have no permission to work with the files
created by root (or another user) and borg operations will just fail with
`Permission denied`.

The easy way to avoid this is to always access the repo as the same user:

For a local repository just always invoke borg as same user.

For a remote repository: always use e.g. borg@remote_host. You can use this
from different local users, the remote user accessing the repo will always be
borg.

If you need to access a local repository from different users, you can use the
same method by using ssh to borg@localhost.

Important note about files changing during the backup process
-------------------------------------------------------------

Borg does not do anything about the internal consistency of the data
it backs up.  It just reads and backs up each file in whatever state
that file is when Borg gets to it.  On an active system, this can lead
to two kinds of inconsistency:

- By the time Borg backs up a file, it might have changed since the backup process was initiated
- A file could change while Borg is backing it up, making the file internally inconsistent

If you have a set of files and want to ensure that they are backed up
in a specific or consistent state, you must take steps to prevent
changes to those files during the backup process.  There are a few
common techniques to achieve this.

- Avoid running any programs that might change the files.

- Snapshot files, filesystems, container storage volumes, or logical volumes.  LVM or ZFS might be useful here.

- Dump databases or stop the database servers.

- Shut down virtual machines before backing up their images.

- Shut down containers before backing up their storage volumes.

For some systems Borg might work well enough without these
precautions.  If you are simply backing up the files on a system that
isn't very active (e.g. in a typical home directory), Borg usually
works well enough without further care for consistency.  Log files and
caches might not be in a perfect state, but this is rarely a problem.

For databases, virtual machines, and containers, there are specific
techniques for backing them up that do not simply use Borg to backup
the underlying filesystem.  For databases, check your database
documentation for techniques that will save the database state between
transactions.  For virtual machines, consider running the backup on
the VM itself or mounting the filesystem while the VM is shut down.
For Docker containers, perhaps docker's "save" command can help.

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

.. note::

    Please see the :ref:`software` section for related tooling for automating
    backups.

::

    #!/bin/sh

    # Setting this, so the repo does not need to be given on the commandline:
    export BORG_REPO=ssh://username@example.com:2022/~/backup/main

    # See the section "Passphrase notes" for more infos.
    export BORG_PASSPHRASE='XYZl0ngandsecurepa_55_phrasea&&123'

    # some helpers and error handling:
    info() { printf "\n%s %s\n\n" "$( date )" "$*" >&2; }
    trap 'echo $( date ) Backup interrupted >&2; exit 2' INT TERM

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

    # use highest exit code as global exit code
    global_exit=$(( backup_exit > prune_exit ? backup_exit : prune_exit ))

    if [ ${global_exit} -eq 0 ]; then
        info "Backup and Prune finished successfully"
    elif [ ${global_exit} -eq 1 ]; then
        info "Backup and/or Prune finished with warnings"
    else
        info "Backup and/or Prune finished with errors"
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

.. passphrase_notes:

Passphrase notes
----------------

If you use encryption (or authentication), Borg will interactively ask you
for a passphrase to encrypt/decrypt the keyfile / repokey.

A passphrase should be a single line of text, a trailing linefeed will be
stripped.

For your own safety, you maybe want to avoid empty passphrases as well
extremely long passphrase (much more than 256 bits of entropy).

Also avoid passphrases containing non-ASCII characters.
Borg is technically able to process all unicode text, but you might get into
trouble reproducing the same encoded utf-8 bytes or with keyboard layouts,
so better just avoid non-ASCII stuff.

If you want to automate, you can alternatively supply the passphrase
directly or indirectly using some environment variables.

You can directly give a passphrase::

    # use this passphrase (use safe permissions on the script!):
    export BORG_PASSPHRASE='my super secret passphrase'

Or ask an external program to supply the passphrase::

    # use the "pass" password manager to get the passphrase:
    export BORG_PASSCOMMAND='pass show backup'

    # use GPG to get the passphrase contained in a gpg-encrypted file:
    export BORG_PASSCOMMAND='gpg --decrypt borg-passphrase.gpg'

Or read the passphrase from an open file descriptor::

    export BORG_PASSPHRASE_FD=42

Using hardware crypto devices (like Nitrokey, Yubikey and others) is not
directly supported by borg, but you can use these indirectly.
E.g. if your crypto device supports GPG and borg calls ``gpg`` via
``BORG_PASSCOMMAND``, it should just work.

.. backup_compression:

Backup compression
------------------

The default is lz4 (very fast, but low compression ratio), but other methods are
supported for different situations.

You can use zstd for a wide range from high speed (and relatively low
compression) using N=1 to high compression (and lower speed) using N=22.

zstd is a modern compression algorithm and might be preferable over zlib and
lzma, except if you need compatibility to older borg versions (< 1.1.4) that
did not yet offer zstd.::

    $ borg create --compression zstd,N /path/to/repo::arch ~

Other options are:

If you have a fast repo storage and you want minimum CPU usage, no compression::

    $ borg create --compression none /path/to/repo::arch ~

If you have a less fast repo storage and you want a bit more compression (N=0..9,
0 means no compression, 9 means high compression):

::

    $ borg create --compression zlib,N /path/to/repo::arch ~

If you have a very slow repo storage and you want high compression (N=0..9, 0 means
low compression, 9 means high compression):

::

    $ borg create --compression lzma,N /path/to/repo::arch ~

You'll need to experiment a bit to find the best compression for your use case.
Keep an eye on CPU load and throughput.

.. _encrypted_repos:

Repository encryption
---------------------

You can choose the repository encryption mode at repository creation time::

    $ borg init --encryption=MODE PATH

For a list of available encryption MODEs and their descriptions, please refer
to :ref:`borg_init`.

If you use encryption, all data is encrypted on the client before being written
to the repository.
This means that an attacker who manages to compromise the host containing an
encrypted repository will not be able to access any of the data, even while the
backup is being made.

Key material is stored in encrypted form and can be only decrypted by providing
the correct passphrase.

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

  command="borg serve --restrict-to-path /path/to/repo",restrict ssh-rsa AAAAB3[...]

If it is not possible to install |project_name| on the remote host,
it is still possible to use the remote host to store a repository by
mounting the remote filesystem, for example, using sshfs::

  $ sshfs user@hostname:/path/to /path/to
  $ borg init /path/to/repo
  $ fusermount -u /path/to

You can also use other remote filesystems in a similar way. Just be careful,
not all filesystems out there are really stable and working good enough to
be acceptable for backup usage.


Restoring a backup
------------------

Please note that we are only describing the most basic commands and options
here - please refer to the command reference to see more.

For restoring, you usually want to work **on the same machine as the same user**
that was also used to create the backups of the wanted files. Doing it like
that avoids quite some issues:

- no confusion relating to paths
- same mapping of user/group names to user/group IDs
- no permission issues
- you likely already have a working borg setup there,

  - maybe including a environment variable for the key passphrase (for encrypted repos),
  - maybe including a keyfile for the repo (not needed for repokey mode),
  - maybe including a ssh key for the repo server (not needed for locally mounted repos),
  - maybe including a valid borg cache for that repo (quicker than cache rebuild).

The **user** might be:

- root (if full backups, backups including system stuff or multiple
  users' files were made)
- some specific user using sudo to execute borg as root
- some specific user (if backups of that user's files were made)

A borg **backup repository** can be either:

- in a local directory (like e.g. a locally mounted USB disk)
- on a remote backup server machine that is reachable via ssh (client/server)

If the repository is encrypted, you will also need the **key** and the **passphrase**
(which is protecting the key).

The **key** can be located:

- in the repository (**repokey** mode).

  Easy, this will usually "just work".
- in the home directory of the user who did the backup (**keyfile** mode).

  This may cause a bit more effort:

  - if you have just lost that home directory and you first need to restore the
    borg key (e.g. from the separate backup you have made of it or from another
    user or machine accessing the same repository).
  - if you first must find out the correct machine / user / home directory
    (where the borg client was run to make the backups).

The **passphrase** for the key has been either:

- entered interactively at backup time
  (not practical if backup is automated / unattended).
- acquired via some environment variable driven mechanism in the backup script
  (look there for BORG_PASSPHRASE, BORG_PASSCOMMAND, etc. and just do it like
  that).

There are **2 ways to restore** files from a borg backup repository:

- **borg mount** - use this if:

  - you don't precisely know what files you want to restore
  - you don't know which archive contains the files (in the state) you want
  - you need to look into files / directories before deciding what you want
  - you need a relatively low volume of data restored
  - you don't care for restoring stuff that the FUSE mount is not implementing yet
    (like special fs flags, ACLs)
  - you have a client with good resources (RAM, CPU, temp. disk space)
  - you want to rather use some filemanager to restore (copy) files than borg
    extract shell commands

- **borg extract** - use this if:

  - you precisely know what you want (repo, archive, path)
  - you need a high volume of files restored (best speed)
  - you want a as-complete-as-it-gets reproduction of file metadata
    (like special fs flags, ACLs)
  - you have a client with low resources (RAM, CPU, temp. disk space)


Example with **borg mount**:

::

    # open a new, separate terminal (this terminal will be blocked until umount)

    # now we find out the archive names we have in the repo:
    borg list /mnt/backup/borg_repo

    # mount one archive from a borg repo:
    borg mount /mnt/backup/borg_repo::myserver-system-2019-08-11 /mnt/borg

    # alternatively, mount all archives from a borg repo (slower):
    borg mount /mnt/backup/borg_repo /mnt/borg

    # it may take a while until you will see stuff in /mnt/borg.

    # now use another terminal or file browser and look into /mnt/borg.
    # when finished, umount to unlock the repo and unblock the terminal:
    borg umount /mnt/borg


Example with **borg extract**:

::

    # borg extract always extracts into current directory and that directory
    # should be empty (borg does not support transforming a non-empty dir to
    # the state as present in your backup archive).
    mkdir borg_restore
    cd borg_restore

    # now we find out the archive names we have in the repo:
    borg list /mnt/backup/borg_repo

    # we could find out the archive contents, esp. the path layout:
    borg list /mnt/backup/borg_repo::myserver-system-2019-08-11

    # we extract only some specific path (note: no leading / !):
    borg extract /mnt/backup/borg_repo::myserver-system-2019-08-11 path/to/extract

    # alternatively, we could fully extract the archive:
    borg extract /mnt/backup/borg_repo::myserver-system-2019-08-11

    # now move the files to the correct place...


Difference when using a **remote borg backup server**:

It is basically all the same as with the local repository, but you need to
refer to the repo using a ``ssh://`` URL.

In the given example, ``borg`` is the user name used to log into the machine
``backup.example.org`` which runs ssh on port ``2222`` and has the borg repo
in ``/path/to/repo``.

Instead of giving a FQDN or a hostname, you can also give an IP address.

As usual, you either need a password to log in or the backup server might
have authentication set up via ssh ``authorized_keys`` (which is likely the
case if unattended, automated backups were done).

::

    borg mount ssh://borg@backup.example.org:2222/path/to/repo /mnt/borg
    # or
    borg extract ssh://borg@backup.example.org:2222/path/to/repo

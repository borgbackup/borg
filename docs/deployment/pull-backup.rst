.. include:: ../global.rst.inc
.. highlight:: none
.. _pull_backup:

Backing up in pull mode
=======================

Assuming you have a pull backup system set up with borg, where a backup server
pulls the data from the target via SSHFS. In this mode, the backup client's file
system is mounted remotely on the backup server. Pull mode is even possible if
the SSH connection must be established by the client via a remote tunnel. Other
network file systems like NFS or SMB could be used as well, but SSHFS is very
simple to set up and probably the most secure one.

There are some restrictions caused by SSHFS. For example, unless you define UID
and GID mappings when mounting via ``sshfs``, owners and groups of the mounted
file system will probably change, and you may not have access to those files if
BorgBackup is not run with root privileges.

SSHFS is a FUSE file system and uses the SFTP protocol, so there may be also
other unsupported features that the actual implementations of sshfs, libfuse and
sftp on the backup server do not support, like file name encodings, ACLs, xattrs
or bsdflags. So there is no guarantee that you are able to restore a system
completely in every aspect from such a backup.

.. warning::

    To mount the client's root file system you will need root access to the
    client. This contradicts to the usual threat model of BorgBackup, where
    clients don't need to trust the backup server (data is encrypted). In pull
    mode the server (when logged in as root) could cause unlimited damage to the
    client. Therefore, pull mode should be used only from servers you do fully
    trust!

.. warning::

    Additionally, while being chrooted into the client's root file system,
    code from the client will be executed. Thus, you should only do that when
    fully trusting the client.

.. warning::

    The chroot method was chosen to get the right user and group name-id
    mappings, assuming they only come from files (/etc/passwd and group).
    This assumption might be wrong, e.g. if users/groups also come from
    ldap or other providers.
    Thus, it might be better to use ``--numeric-owner`` and not archive any
    user or group names (but just the numeric IDs) and not use chroot.

Creating a backup
-----------------

Generally, in a pull backup situation there is no direct way for borg to know
the client's original UID:GID name mapping of files, because Borg would use
``/etc/passwd`` and ``/etc/group`` of the backup server to map the names. To
derive the right names, Borg needs to have access to the client's passwd and
group files and use them in the backup process.

The solution to this problem is chrooting into an sshfs mounted directory. In
this example the whole client root file system is mounted. We use the
stand-alone BorgBackup executable and copy it into the mounted file system to
make Borg available after entering chroot; this can be skipped if Borg is
already installed on the client.

::

    # Mount client root file system.
    mkdir /tmp/sshfs
    sshfs root@host:/ /tmp/sshfs
    # Mount BorgBackup repository inside it.
    mkdir /tmp/sshfs/borgrepo
    mount --bind /path/to/repo /tmp/sshfs/borgrepo
    # Make borg executable available.
    cp /usr/local/bin/borg /tmp/sshfs/usr/local/bin/borg
    # Mount important system directories and enter chroot.
    cd /tmp/sshfs
    for i in dev proc sys; do mount --bind /$i $i; done
    chroot /tmp/sshfs

Now we are on the backup system but inside a chroot with the client's root file
system. We have a copy of Borg binary in ``/usr/local/bin`` and the repository
in ``/borgrepo``. Borg will back up the client's user/group names, and we can
create the backup, retaining the original paths, excluding the repository:

::

    borg create --exclude /borgrepo --files-cache ctime,size /borgrepo::archive /

For the sake of simplicity only ``/borgrepo`` is excluded here. You may want to
set up an exclude file with additional files and folders to be excluded. Also
note that we have to modify Borg's file change detection behaviour – SSHFS
cannot guarantee stable inode numbers, so we have to supply the
``--files-cache`` option.

Finally, we need to exit chroot, unmount all the stuff and clean up:

::

    exit # exit chroot
    rm /tmp/sshfs/usr/local/bin/borg
    cd /tmp/sshfs
    for i in dev proc sys borgrepo; do umount ./$i; done
    rmdir borgrepo
    cd ~
    umount /tmp/sshfs
    rmdir /tmp/sshfs

Thanks to secuser on IRC for this how-to!

Restore methods
---------------

The counterpart of a pull backup is a push restore. Depending on the type of
restore – full restore or partial restore – there are different methods to make
sure the correct IDs are restored.

Partial restore
~~~~~~~~~~~~~~~

In case of a partial restore, using the archived UIDs/GIDs might lead to wrong
results if the name-to-ID mapping on the target system has changed compared to
backup time (might be the case e.g. for a fresh OS install).

The workaround again is chrooting into an sshfs mounted directory, so Borg is
able to map the user/group names of the backup files to the actual IDs on the
client. This example is similar to the backup above – only the Borg command is
different:

::

    # Mount client root file system.
    mkdir /tmp/sshfs
    sshfs root@host:/ /tmp/sshfs
    # Mount BorgBackup repository inside it.
    mkdir /tmp/sshfs/borgrepo
    mount --bind /path/to/repo /tmp/sshfs/borgrepo
    # Make borg executable available.
    cp /usr/local/bin/borg /tmp/sshfs/usr/local/bin/borg
    # Mount important system directories and enter chroot.
    cd /tmp/sshfs
    for i in dev proc sys; do mount --bind /$i $i; done
    chroot /tmp/sshfs

Now we can run

::

    borg extract /borgrepo::archive PATH

to partially restore whatever we like. Finally, do the clean-up:

::

    exit # exit chroot
    rm /tmp/sshfs/usr/local/bin/borg
    cd /tmp/sshfs
    for i in dev proc sys borgrepo; do umount ./$i; done
    rmdir borgrepo
    cd ~
    umount /tmp/sshfs
    rmdir /tmp/sshfs

Full restore
~~~~~~~~~~~~

When doing a full restore, we restore all files (including the ones containing
the ID-to-name mapping, ``/etc/passwd`` and ``/etc/group``). Everything will be
consistent automatically if we restore the numeric IDs stored in the archive. So
there is no need for a chroot environment; we just mount the client file system
and extract a backup, utilizing the ``--numeric-owner`` option:

::

    sshfs root@host:/ /mnt/sshfs
    cd /mnt/sshfs
    borg extract --numeric-owner /path/to/repo::archive
    cd ~
    umount /mnt/sshfs

Simple (lossy) full restore
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Using ``borg export-tar`` it is possible to stream a backup to the client and
directly extract it without the need of mounting with SSHFS:

::

    borg export-tar /path/to/repo::archive - | ssh root@host 'tar -C / -x'

Note that in this scenario the tar format is the limiting factor – it cannot
restore all the advanced features that BorgBackup supports. See
:ref:`borg_export-tar` for limitations.

ssh-agent
=========

In this scenario *borg-server* initiates an SSH connection to *borg-client* and forwards the authentication
agent connection.

After that, it works similar to the push mode:
*borg-client* initiates another SSH connection back to *borg-server* using the forwarded authentication agent
connection to authenticate itself, starts ``borg serve`` and communicates with it.

Using this method requires ssh access of user *borgs* to *borgc@borg-client*, where:

* *borgs* is the user on the server side with read/write access to local borg repository.
* *borgc* is the user on the client side with read access to files meant to be backed up.

Applying this method for automated backup operations
----------------------------------------------------

Assume that the borg-client host is untrusted.
Therefore we do some effort to prevent a hostile user on the borg-client side to do something harmful.
In case of a fully trusted borg-client the method could be simplified.

Preparing the server side
~~~~~~~~~~~~~~~~~~~~~~~~~

Do this once for each client on *borg-server* to allow *borgs* to connect itself on *borg-server* using a
dedicated ssh key:

::

  borgs@borg-server$ install -m 700 -d ~/.ssh/
  borgs@borg-server$ ssh-keygen -N '' -t rsa  -f ~/.ssh/borg-client_key
  borgs@borg-server$ { echo -n 'command="borg serve --append-only --restrict-to-repo ~/repo",restrict '; cat ~/.ssh/borg-client_key.pub; } >> ~/.ssh/authorized_keys
  borgs@borg-server$ chmod 600 ~/.ssh/authorized_keys

``install -m 700 -d ~/.ssh/``

  Create directory ~/.ssh with correct permissions if it does not exist yet.

``ssh-keygen -N '' -t rsa  -f ~/.ssh/borg-client_key``

  Create an ssh key dedicated to communication with borg-client.

.. note::
  Another more complex approach is using a unique ssh key for each pull operation.
  This is more secure as it guarantees that the key will not be used for other purposes.

``{ echo -n 'command="borg serve --append-only --restrict-to-repo ~/repo",restrict '; cat ~/.ssh/borg-client_key.pub; } >> ~/.ssh/authorized_keys``

  Add borg-client's ssh public key to ~/.ssh/authorized_keys with forced command and restricted mode.
  The borg client is restricted to use one repo at the specified path and to append-only operation.
  Commands like *delete*, *prune* and *compact* have to be executed another way, for example directly on *borg-server*
  side or from a privileged, less restricted client (using another authorized_keys entry).

``chmod 600 ~/.ssh/authorized_keys``

  Fix permissions of ~/.ssh/authorized_keys.

Pull operation
~~~~~~~~~~~~~~

Initiating borg command execution from *borg-server* (e.g. init)::

  borgs@borg-server$ (
    eval $(ssh-agent) > /dev/null
    ssh-add -q ~/.ssh/borg-client_key
    echo 'your secure borg key passphrase' | \
      ssh -A -o StrictHostKeyChecking=no borgc@borg-client "BORG_PASSPHRASE=\$(cat) borg --rsh 'ssh -o StrictHostKeyChecking=no' init --encryption repokey ssh://borgs@borg-server/~/repo"
    kill "${SSH_AGENT_PID}"
  )

Parentheses around commands are needed to avoid interference with a possibly already running ssh-agent.
Parentheses are not needed when using a dedicated bash process.

``eval $(ssh-agent) > /dev/null``

  Run the SSH agent in the background and export related environment variables to the current bash session.

``ssh-add -q ~/.ssh/borg-client_key``

  Load the SSH private key dedicated to communication with the borg-client into the SSH agent.
  Look at ``man 1 ssh-add`` for a more detailed explanation.

.. note::
  Care needs to be taken when loading keys into the SSH agent. Users on the *borg-client* having read/write permissions
  to the agent's UNIX-domain socket (at least borgc and root in our case) can access the agent on *borg-server* through
  the forwarded connection and can authenticate using any of the identities loaded into the agent
  (look at ``man 1 ssh`` for more detailed explanation). Therefore there are some security considerations:

  * Private keys loaded into the agent must not be used to enable access anywhere else.
  * The keys meant to be loaded into the agent must be specified explicitly, not from default locations.
  * The *borg-client*'s entry in *borgs@borg-server:~/.ssh/authorized_keys* must be as restrictive as possible.

``echo 'your secure borg key passphrase' | ssh -A -o StrictHostKeyChecking=no borgc@borg-client "BORG_PASSPHRASE=\$(cat) borg --rsh 'ssh -o StrictHostKeyChecking=no' init --encryption repokey ssh://borgs@borg-server/~/repo"``

  Run the *borg init* command on *borg-client*.

  *ssh://borgs@borg-server/~/repo* refers to the repository *repo* within borgs's home directory on *borg-server*.

  *StrictHostKeyChecking=no* is used to automatically add host keys to *~/.ssh/known_hosts* without user intervention.

``kill "${SSH_AGENT_PID}"``

  Kill ssh-agent with loaded keys when it is not needed anymore.

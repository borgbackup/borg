.. include:: ../global.rst.inc
.. highlight:: none

=======================
Backing up in pull mode
=======================

Typically the borg client connects to a backup server using SSH as a transport
when initiating a backup. This is referred to as push mode.

If you however require the backup server to initiate the connection or prefer
it to initiate the backup run, one of the following workarounds is required to
allow such a pull mode setup.

A common use case for pull mode is to backup a remote server to a local personal
computer.

SSHFS
=====

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
other unsupported features that the actual implementations of ssfs, libfuse and
sftp on the backup server do not support, like file name encodings, ACLs, xattrs
or flags. So there is no guarantee that you are able to restore a system
completely in every aspect from such a backup.

.. warning::

    To mount the client's root file system you will need root access to the
    client. This contradicts to the usual threat model of BorgBackup, where
    clients don't need to trust the backup server (data is encrypted). In pull
    mode the server (when logged in as root) could cause unlimited damage to the
    client. Therefore, pull mode should be used only from servers you do fully
    trust!

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

socat
=====

In this setup a SSH connection from the backup server to the client is
established that uses SSH reverse port forwarding to transparently
tunnel data between UNIX domain sockets on the client and server and the socat
tool to connect these with the borg client and server processes, respectively.

The program socat has to be available on the backup server and on the client
to be backed up.

When **pushing** a backup the borg client (holding the data to be backed up)
connects to the backup server via ssh, starts ``borg serve`` on the backup
server and communicates via standard input and output (transported via SSH)
with the process on the backup server.

With the help of socat this process can be reversed. The backup server will
create a connection to the client (holding the data to be backed up) and will
**pull** the data.

In the following example *borg-server* connects to *borg-client* to pull a backup.

To provide a secure setup sockets should be stored in ``/run/borg``, only
accessible to the users that run the backup process. So on both systems,
*borg-server* and *borg-client* the folder ``/run/borg`` has to be created::

   sudo mkdir -m 0700 /run/borg

On *borg-server* the socket file is opened by the user running the ``borg
serve`` process writing to the repository
so the user has to have read and write permissions on ``/run/borg``::

   borg-server:~$ sudo chown borgs /run/borg

On *borg-client* the socket file is created by ssh, so the user used to connect
to *borg-client* has to have read and write permissions on ``/run/borg``::

   borg-client:~$ sudo chown borgc /run/borg

On *borg-server*, we have to start the command ``borg serve`` and make its
standard input and output available to a unix socket::

   borg-server:~$ socat UNIX-LISTEN:/run/borg/reponame.sock,fork EXEC:"borg serve --append-only --restrict-to-path /path/to/repo"

Socat will wait until a connection is opened. Then socat will execute the
command given, redirecting Standard Input and Output to the unix socket. The
optional arguments for ``borg serve`` are not necessary but a sane default.

.. note::
   When used in production you may also use systemd socket-based activation
   instead of socat on the server side. You would wrap the ``borg serve`` command
   in a `service unit`_ and configure a matching `socket unit`_
   to start the service whenever a client connects to the socket.

   .. _service unit: https://www.freedesktop.org/software/systemd/man/systemd.service.html
   .. _socket unit: https://www.freedesktop.org/software/systemd/man/systemd.socket.html

Now we need a way to access the unix socket on *borg-client* (holding the
data to be backed up), as we created the unix socket on *borg-server*
Opening a SSH connection from the *borg-server* to the *borg-client* with reverse port
forwarding can do this for us::

   borg-server:~$ ssh -R /run/borg/reponame.sock:/run/borg/reponame.sock borgc@borg-client

.. note::

   As the default value of OpenSSH for ``StreamLocalBindUnlink`` is ``no``, the
   socket file created by sshd is not removed. Trying to connect a second time,
   will print a short warning, and the forwarding does **not** take place::

      Warning: remote port forwarding failed for listen path /run/borg/reponame.sock

   When you are done, you have to manually remove the socket file, otherwise
   you may see an error like this when trying to execute borg commands::

      Remote: YYYY/MM/DD HH:MM:SS socat[XXX] E connect(5, AF=1 "/run/borg/reponame.sock", 13): Connection refused
      Connection closed by remote host. Is borg working on the server?


When a process opens the socket on *borg-client*, SSH will forward all
data to the socket on *borg-server*.

The next step is to tell borg on *borg-client* to use the unix socket to communicate with the
``borg serve`` command on *borg-server* via the socat socket instead of SSH::

   borg-client:~$ export BORG_RSH="sh -c 'exec socat STDIO UNIX-CONNECT:/run/borg/reponame.sock'"

The default value for ``BORG_RSH`` is ``ssh``. By default Borg uses SSH to create
the connection to the backup server. Therefore Borg parses the repo URL
and adds the server name (and other arguments) to the SSH command. Those
arguments can not be handled by socat. We wrap the command with ``sh`` to
ignore all arguments intended for the SSH command.

All Borg commands can now be executed on *borg-client*. For example to create a
backup execute the ``borg create`` command::

   borg-client:~$ borg create ssh://borg-server/path/to/repo::archive /path_to_backup

When automating backup creation, the
interactive ssh session may seem inappropriate. An alternative way of creating
a backup may be the following command::

   borg-server:~$ ssh \
      -R /run/borg/reponame.sock:/run/borg/reponame.sock \
      borgc@borg-client \
      borg create \
      --rsh "sh -c 'exec socat STDIO UNIX-CONNECT:/run/borg/reponame.sock'" \
      ssh://borg-server/path/to/repo::archive /path_to_backup \
      ';' rm /run/borg/reponame.sock

This command also automatically removes the socket file after the ``borg
create`` command is done.

ssh-agent
=========

In this scenario *borg-server* initiate SSH connection to *borg-client* with forwarding of the authentication agent connection.
Afterwards scenario is similar to the push mode: *borg-client* initiate another SSH connection
back to *borg-server* using forwarded agent connection for authenticate itself,
starts ``borg serve`` and communicate with them.

Using of this method requires ssh access from *borgs* to *borgc@borg-client* and
from *borgs* to *borgs@borg-server* itself. Where:

* *borgs* is the user on the server side with read/write access to local borg repository.
* *borgc* is the user on the client side with read access to files meant to be backed up.

Apply of this method in case of automated backup operations
-----------------------------------------------------------

Do this once on *borg-server* for allowing *borgs* to connect itself on *borg-server*::

  borgs@borg-server$ cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
  borgs@borg-server$ chmod go-w ~/.ssh/authorized_keys

Execute pull operation (init repo in this example) on *borg-server*::

  borgs@borg-server$ (
    eval $(ssh-agent) > /dev/null
    ssh-add -q
    ssh -A borgc@borg-client "borg init -e none --rsh 'ssh -o StrictHostKeyChecking=no' borgs@borg-server:repo"
    kill "${SSH_AGENT_PID}"
  )

Parentheses around commands are needed to exclude interferention with possibly already running ssh-agent.
Parentheses not needed in case of using dedicated bash process.

*eval $(ssh-agent) > /dev/null*

  Run SSH agent in background and export related environment variables to current bash session.

*ssh-add -q*

  Load SSH private key(s) to SSH agent from default locations:
  ~/.ssh/id_rsa, ~/.ssh/id_dsa, ~/.ssh/id_ecdsa and ~/.ssh/id_ed25519.
  Look at ``man 1 ssh-add`` for more detailed explanation.

  Care needs to be taken when loading keys to SSH agent. Users on the *borg-client* having read/write permissions to
  agent's UNIX-domain socket (at least borgc and root in our case) can access the agent on *borg-server* through the
  forwarded connection and use loaded keys for authenticate using the identities loaded into the agent
  (look at ``man 1 ssh`` for more detailed explanation). Therefore there are some security considerations:

  * *borgs*'s private key loaded to agent must not be used to access anywhere else.
  * The keys meant to be loaded to agent must be specified explicitly, not from default locations.
  * The *borgs*'s public key record at *borgs@borg-server:~/.ssh/authorized_keys* must be as restrictive as possible.

*ssh -A borgc@borg-client "borg init -e none --rsh 'ssh -o StrictHostKeyChecking=no' borgs@borg-server:repo"*

  Issue *borg init -e none borgs@borg-server:repo* command to be executed at *borg-client*.
  *StrictHostKeyChecking=no* used for automatically adding host key of
  *borg-server* to *borgc@borg-client:~/.ssh/known_hosts* without user intervention.

*kill "${SSH_AGENT_PID}"*

  Kill ssh-agent with loaded keys as it not needed anymore.

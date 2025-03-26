.. include:: ../global.rst.inc
.. highlight:: none
.. _pull_backup:

=======================
Backing up in pull mode
=======================

Typically the borg client connects to a backup server using SSH as a transport
when initiating a backup. This is referred to as push mode.

If you however require the backup server to initiate the connection or prefer
it to initiate the backup run, one of the following workarounds is required to
allow such a pull mode setup.

A common use case for pull mode is to back up a remote server to a local personal
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
other unsupported features that the actual implementations of sshfs, libfuse and
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

.. warning::

    Additionally, while being chrooted into the client's root file system,
    code from the client will be executed. Thus, you should only do that when
    fully trusting the client.

.. warning::

    The chroot method was chosen to get the right user and group name-id
    mappings, assuming they only come from files (/etc/passwd and group).
    This assumption might be wrong, e.g. if users/groups also come from
    ldap or other providers.
    Thus, it might be better to use ``--numeric-ids`` and not archive any
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

    borg create --exclude borgrepo --files-cache ctime,size --repo /borgrepo archive  /

For the sake of simplicity only ``borgrepo`` is excluded here. You may want to
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

    borg extract --repo /borgrepo archive PATH

to restore whatever we like partially. Finally, do the clean-up:

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
and extract a backup, utilizing the ``--numeric-ids`` option:

::

    sshfs root@host:/ /mnt/sshfs
    cd /mnt/sshfs
    borg extract --numeric-ids --repo /path/to/repo archive
    cd ~
    umount /mnt/sshfs

Simple (lossy) full restore
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Using ``borg export-tar`` it is possible to stream a backup to the client and
directly extract it without the need of mounting with SSHFS:

::

    borg export-tar --repo /path/to/repo archive - | ssh root@host 'tar -C / -x'

Note that in this scenario the tar format is the limiting factor – it cannot
restore all the advanced features that BorgBackup supports. See
:ref:`borg_export-tar` for limitations.

socat
=====

In this setup a SSH connection from the backup server to the client is
established that uses SSH reverse port forwarding to tunnel data
transparently between UNIX domain sockets on the client and server and the socat
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

   When you are done, you have to remove the socket file manually, otherwise
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

   borg-client:~$ borg create --repo ssh://borg-server/path/to/repo archive /path_to_backup

When automating backup creation, the
interactive ssh session may seem inappropriate. An alternative way of creating
a backup may be the following command::

   borg-server:~$ ssh \
      -R /run/borg/reponame.sock:/run/borg/reponame.sock \
      borgc@borg-client \
      borg create \
      --rsh "sh -c 'exec socat STDIO UNIX-CONNECT:/run/borg/reponame.sock'" \
      --repo ssh://borg-server/path/to/repo archive /path_to_backup \
      ';' rm /run/borg/reponame.sock

This command also automatically removes the socket file after the ``borg
create`` command is done.

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

  *StrictHostKeyChecking=no* is used to add host keys automatically to *~/.ssh/known_hosts* without user intervention.

``kill "${SSH_AGENT_PID}"``

  Kill ssh-agent with loaded keys when it is not needed anymore.

Remote forwarding
=================

The standard ssh client allows to create tunnels to forward local ports to a remote server (local forwarding) and also
to allow remote ports to be forwarded to local ports (remote forwarding).

This remote forwarding can be used to allow remote backup clients to access the backup server even if the backup server
cannot be reached by the backup client.

This can even be used in cases where neither the backup server can reach the backup client and the backup client cannot
reach the backup server, but some intermediate host can access both.

A schematic approach is as follows

::

      Backup Server (backup@mybackup)          Intermediate Machine (john@myinter)              Backup Client (bob@myclient)

                                              1. Establish SSH remote forwarding  ----------->  SSH listen on local port

                                                                                                2. Starting ``borg create`` establishes
                                              3. SSH forwards to intermediate machine  <------- SSH connection to the local port
      4. Receives backup connection <-------  and further on to backup server
      via SSH

So for the backup client the backup is done via SSH to a local port and for the backup server there is a normal backup
performed via ssh.

In order to achieve this, the following commands can be used to create the remote port forwarding:

1. On machine ``myinter``

``ssh bob@myclient -v -C -R 8022:mybackup:22 -N``

This will listen for ssh-connections on port ``8022`` on ``myclient`` and forward connections to port 22 on ``mybackup``.

You can also remove the need for machine ``myinter`` and create the port forwarding on the backup server directly by
using ``localhost`` instead of ``mybackup``

2. On machine ``myclient``

``borg create -v --progress --stats ssh://backup@localhost:8022/home/backup/repos/myclient /``

Make sure to use port ``8022`` and ``localhost`` for the repository as this instructs borg on ``myclient`` to use the
remote forwarded ssh connection.

SSH Keys
--------

If you want to automate backups when using this method, the ssh ``known_hosts`` and ``authorized_keys`` need to be set up
to allow connections.

Security Considerations
-----------------------

Opening up SSH access this way can pose a security risk as it effectively opens remote access to your
backup server on the client even if it is located outside of your company network.

To reduce the chances of compromise, you should configure a forced command in ``authorized_keys`` to prevent
anyone from performing any other action on the backup server.

This can be done e.g. by adding the following in ``$HOME/.ssh/authorized_keys`` on ``mybackup`` with proper
path and client-fqdn:

::

  command="cd /home/backup/repos/<client fqdn>;borg serve --restrict-to-path /home/backup/repos/<client fqdn>"


All the additional security considerations for borg should be applied, see :ref:`central-backup-server` for some additional
hints.

More information
----------------

See `remote forwarding`_ and the `ssh man page`_ for more information about remote forwarding.

   .. _remote forwarding: https://linuxize.com/post/how-to-setup-ssh-tunneling/
   .. _ssh man page: https://manpages.debian.org/testing/manpages-de/ssh.1.de.html

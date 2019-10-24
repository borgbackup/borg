.. include:: ../global.rst.inc
.. highlight:: none

Backing up in pull mode
=======================

Assuming you have a pull backup system set up with borg, where a backup server
pulls the data from the target via sshfs. In this mode, the backup client's file
system is mounted remotely on the backup server. Pull mode is even possible if
the SSH connection must be established by the client via a remote tunnel. Other
network file systems like NFS or SMB could be used as well, but sshfs is very
simple to set up and probably the most secure one.

There are some restrictions caused by sshfs. For example, unless you define UID
and GID mappings when mounting via sshfs, owners and groups of the mounted file
system will probably change, and you may not have access to those files if
BorgBackup is not run with root privileges.

The sshfs is a FUSE file system and uses the SFTP protocol, so there may be also
other unsupported features that the actual implementations of sshfs, libfuse and
sftp on the backup server do not support, like file name encodings, ACLs, xattrs
or bsdflags. So there is no guarantee that you are able to restore a system
completely in every aspect from such a backup.

.. warning::

    To mount the client's root file system you will need root access to the client.
    This contradicts to the usual threat model of BorgBackup, where clients don't
    need to trust the backup server (data is encrypted). In pull mode the server
    (when logged in as root) could cause unlimited damage to the client. Therefore,
    pull mode should be used only from servers you do fully trust!

Creating a backup
-----------------

In this approach the client file system is simply mounted and then backed up.
Note that the backup is created from within the mount point so that all files
in the archive have their original paths (otherwise they would be backed up with
the mount point prefix, e.g. /mnt/sshfs/bin/bash instead of /bin/bash).

::

    sshfs root@host:/ /mnt/sshfs
    cd /mnt/sshfs
    borg create /path/to/repo::archive . # note the dot!
    cd ~
    umount /mnt/sshfs

Restore methods
---------------

The counterpart of a pull backup is a push restore. When restoring from a
backup, you might have to take a closer look on the user and group IDs and names
of the backup content. Depending on the type of restore – full restore or
partial restore – there are different methods to make sure the correct IDs are
restored. Generally, there is no direct way for borg to know the correct UID:GID
of files, because it uses the ``/etc/passwd`` and the ``/etc/group`` of the
backup server.

Partial restore
~~~~~~~~~~~~~~~

In case of a partial restore, using the archived UIDs/GIDs might lead to wrong
results, because after a reinstall the name-to-ID mapping might have changed.
The workaround is chrooting into an sshfs mounted directory. In this example the
whole client root file system is mounted. We use the stand-alone BorgBackup
executable and copy it into the mounted file system to make Borg available after
entering chroot; this can be skipped if Borg is already installed on the client.

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

Now we are on the backup system but inside a chroot with the target's root file
system. We have a copy of Borg binary in ``/usr/local/bin`` and the repository
in ``/borgrepo``. Now Borg is able to map the user/group names of the backup
files to the actual IDs on the client, and we can run

::

    borg extract /borgrepo::archive PATH

to partially restore whatever we like. Finally we need to exit chroot, unmount
all the stuff and clean up:

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

Full restore
~~~~~~~~~~~~

In a full restore differences between backup and client do not matter, so there
is no need for a chroot environment. We just mount the client file system and
extract a backup, using the numeric IDs to get a consistent restore:

::

    sshfs root@host:/ /mnt/sshfs
    cd /mnt/sshfs
    borg extract --numeric owner /path/to/repo::archive
    cd ~
    umount /mnt/sshfs

Simple (lossy) full restore
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Using ``borg export-tar`` it is possible to stream a backup to the client and
directly extract it without the need of mounting with SSHFS:

::

    borg export-tar /path/to/repo::archive | ssh root@host 'tar -C / -x'

Note that in this scenario the tar format is the limiting factor – it cannot
restore all the advanced features that BorgBackup supports. See
:ref:`borg_export-tar` for limitations.

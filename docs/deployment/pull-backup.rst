.. include:: ../global.rst.inc
.. highlight:: none

Backing up in pull mode
=======================

Assuming you have a pull backup system set up with borg, where a backup server
pulls the data from the target via sshfs.

In this mode, the backup client's file system is mounted via sshfs on the backup
server. Pull mode is even possible if the SSH connection must be established by
the client via a remote tunnel.

There are some restrictions caused by sshfs. Unless you define UID and GID
mappings when mounting via sshfs, owners and groups of the mounted file system
will probably change, and you may not have access to those files if BorgBackup
is not run with root privileges.

[ADD MORE RESTRICTIONS HERE: filename encoding, xattrs, ACLs, bsdflags...]

To mount the client's root file system you will need root access to the client.
This contradicts to the usual threat model of BorgBackup, where clients don't
need to trust the backup server can encrypt their data. In pull mode the server
(when logged in as root) could cause unlimited damage to the client. Therefore,
pull mode should be used only from servers you own or trust yourself!

Creating a backup
-----------------

In this approach the client file system is simply mounted and then backed up.
Note that the backup is created from within the mount point, so that all files
in the archive have their original paths (otherwise they would be backed up with
the mount point prefix, e.g. /mnt/sshfs/bin/bash instead of /bin/bash).

::

    # Mount client root file system.
    mkdir /mnt/sshfs
    sshfs root@host:/ /mnt/sshfs
    # Change into mount dir and back up.
    cd /mnt/sshfs
    borg create /borg/to/repo::archive
    # Unmount client.
    cd ~
    fusermount -u /mnt/sshfs

Restoring a full backup
-----------------------

In case of a restore there is no direct way for borg to know the correct UID:GID
of files, because it uses the ``/etc/passwd`` and ``/etc/group`` of the backup
server. Using the archived UIDs/GIDs might lead to wrong results, because after
a reinstall the name-to-ID mapping might have changed.

The workaround is chrooting into an sshfs mounted directory. In this example the
whole client root file system is mounted and restored. We use the stand-alone
BorgBackup executable and copy it into the mounted file system to make borg
available after entering chroot; this can be skipped of BorgBackup is already
installed on the client.

::

    # Mount client root file system.
    mkdir /tmp/sshfs
    sshfs root@host:/ /tmp/sshfs
    # Mount BorgBackup repository inside it.
    mkdir /tmp/sshfs/borgrepo
    mount --bind /REPOSITORY /tmp/sshfs/borgrepo
    # Make borg executable available.
    cp /usr/local/bin/borg /tmp/sshfs/usr/local/bin/borg
    # Mount important system directories and enter chroot.
    cd /tmp/sshfs
    for i in dev proc sys; do mount --bind /$i $i; done
    chroot /tmp/sshfs

Now we are on the backup system but inside a chroot with the target's root file
system. We have a copy of BorgBackup binary in ``/usr/local/bin`` and the
repository in ``/borgrepo``, and can run a simple

::

    borg extract /borgrepo::archive

to restore the whole archive. Finally we need to exit chroot and unmount all the
stuff:

::

    exit #ext chroot
    cd /tmp/sshfs
    for i in dev proc sys borgrepo; do umount ./$i; done
    cd ~
    fusermount -u /tmp/sshfs

Thanks to secuser on IRC for this howto.

Simple full restore
-------------------

If you don't care about the correct UIDs/GIDs, or you can guarantee that they
have not changed, a simple full restore can be achieved with

::

    borg export-tar /path/to/repo::archive | ssh root@host 'tar xf -'

(let Borg export the archive in tar format, upload it to the client and directly
extract it in root file system).

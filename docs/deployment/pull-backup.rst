.. include:: ../global.rst.inc
.. highlight:: none

Backing up in pull mode
=======================

Assume you have a pull backup system set up with borg, where a backup server
pulls the data from the target via sshfs.

In this mode, the backup client's file system is mounted via sshfs on the backup
server. Pull mode is even possible if the SSH connection must be established by
the client via remote tunnel.

Creating backup
---------------

In this approach the client file system is simply mounted and then backed up.

::

    mkdir /mnt/sshfs
    sshfs root@TARGET_IP:/ /mnt/sshfs
    borg create /REPOSITORY::archive /mnt/sshfs

Note that this will back up every file with the ``/mnt/sshfs`` prefix. You can
get rid of this prefix by changing the working directory before creating the
backup:

::

    cd /mnt/sshfs
    borg create /REPOSITORY::archive

Restoring a full backup
-----------------------

In case of a restore there is no direct way for borg to know the correct UID:GID
of files, because it uses the ``/etc/passwd`` and ``/etc/group`` of the backup
server. Using the archived UIDs/GIDs might lead to wrong results, because after
a reinstall the name-to-ID mapping might have changed.

The workaround is chrooting into an sshfs mounted directory.

::

    mkdir /tmp/sshfs
    sshfs root@TARGET_IP:/ /tmp/sshfs
    mkdir /tmp/sshfs/borgrepo
    mount --bind /REPOSITORY /tmp/sshfs/borgrepo
    cp /usr/local/bin/borg /tmp/sshfs/usr/local/bin/borg
    cd /tmp/sshfs
    for i in dev proc sys; do mount --bind /$i $i; done
    chroot /tmp/sshfs

Now we are on the backup system but inside a chroot with the target's root file
system. We have a copy of BorgBackup binary in ``/usr/local/bin`` and the
repository in ``/borgrepo``, and can run a simple

::

    borg extract /borgrepo::archive /mnt/sshfs
    exit

in case all files have the ``/mnt/sshfs`` prefix) or just

::

    borg extract /borgrepo::archive
    exit

otherwise. We have now left chroot again and have to unmount all the stuff:

::

    cd /tmp/sshfs
    for i in dev proc sys borgrepo; do umount ./$i; done
    cd /root
    fusermount -uz /tmp/sshfs

Thanks to secuser on IRC for this howto.

Simple full restore
-------------------

If you don't care for the correct UIDs/GIDs or can guarantee that they have not
changed, a simple full restore can be achieved with::

    borg export-tar /REPOSITORY::archive | ssh root@TARGET_IP 'tar xf -'

(let Borg export the archive in tar format, upload it to the client and directly
extract it in root file system). Again, don't forget the ``/mnt/sshfs`` prefix
if used.

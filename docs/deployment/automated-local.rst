.. include:: ../global.rst.inc
.. highlight:: none

Automated backups to a local hard drive
=======================================

This guide shows how to automate backups to a hard drive directly connected
to your computer. If a backup hard drive is connected, backups are automatically
started, and the drive shut-down and disconnected when they are done.

This guide is written for a Linux-based operating system and makes use of
systemd and udev.

Overview
--------

An udev rule is created to trigger on the addition of block devices. The rule contains a tag
that triggers systemd to start a oneshot service. The oneshot service executes a script in
the standard systemd service environment, which automatically captures stdout/stderr and
logs it to the journal.

The script mounts the added block device, if it is a registered backup drive, and creates
backups on it. When done, it optionally unmounts the file system and spins the drive down,
so that it may be physically disconnected.

Configuring the system
----------------------

First, create the ``/etc/backups`` directory (as root).
All configuration goes into this directory.

Find out the ID of the partition table of your backup disk (here assumed to be /dev/sdz):
    lsblk --fs -o +PTUUID /dev/sdz

Then, create ``/etc/backups/80-backup.rules`` with the following content (all on one line)::

    ACTION=="add", SUBSYSTEM=="block", ENV{ID_PART_TABLE_UUID}=="<the PTUUID you just noted>", TAG+="systemd", ENV{SYSTEMD_WANTS}+="automatic-backup.service"

The "systemd" tag in conjunction with the SYSTEMD_WANTS environment variable has systemd
launch the "automatic-backup" service, which we will create next, as the
``/etc/backups/automatic-backup.service`` file:

.. code-block:: ini

    [Service]
    Type=oneshot
    ExecStart=/etc/backups/run.sh

Now, create the main backup script, ``/etc/backups/run.sh``. Below is a template,
modify it to suit your needs (e.g. more backup sets, dumping databases etc.).

.. code-block:: bash

    #!/bin/bash -ue

    # The udev rule is not terribly accurate and may trigger our service before
    # the kernel has finished probing partitions. Sleep for a bit to ensure
    # the kernel is done.
    #
    # This can be avoided by using a more precise udev rule, e.g. matching
    # a specific hardware path and partition.
    sleep 5

    #
    # Script configuration
    #

    # The backup partition is mounted there
    MOUNTPOINT=/mnt/backup

    # This is the location of the Borg repository
    TARGET=$MOUNTPOINT/borg-backups/backup.borg

    # Archive name schema
    DATE=$(date --iso-8601)-$(hostname)

    # This is the file that will later contain UUIDs of registered backup drives
    DISKS=/etc/backups/backup.disks

    # Find whether the connected block device is a backup drive
    for uuid in $(lsblk --noheadings --list --output uuid)
    do
            if grep --quiet --fixed-strings $uuid $DISKS; then
                    break
            fi
            uuid=
    done

    if [ ! $uuid ]; then
            echo "No backup disk found, exiting"
            exit 0
    fi

    echo "Disk $uuid is a backup disk"
    partition_path=/dev/disk/by-uuid/$uuid
    # Mount file system if not already done. This assumes that if something is already
    # mounted at $MOUNTPOINT, it is the backup drive. It won't find the drive if
    # it was mounted somewhere else.
    findmnt $MOUNTPOINT >/dev/null || mount $partition_path $MOUNTPOINT
    drive=$(lsblk --inverse --noheadings --list --paths --output name $partition_path | head --lines 1)
    echo "Drive path: $drive"

    #
    # Create backups
    #

    # Options for borg create
    BORG_OPTS="--stats --one-file-system --compression lz4"

    # Set BORG_PASSPHRASE or BORG_PASSCOMMAND somewhere around here, using export,
    # if encryption is used.

    # No one can answer if Borg asks these questions, it is better to just fail quickly
    # instead of hanging.
    export BORG_RELOCATED_REPO_ACCESS_IS_OK=no
    export BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK=no

    # Log Borg version
    borg --version

    echo "Starting backup for $DATE"

    # This is just an example, change it however you see fit
    borg create $BORG_OPTS \
      --exclude root/.cache \
      --exclude var/lib/docker/devicemapper \
      $TARGET::$DATE-$$-system \
      / /boot

    # /home is often a separate partition / file system.
    # Even if it isn't (add --exclude /home above), it probably makes sense
    # to have /home in a separate archive.
    borg create $BORG_OPTS \
      --exclude 'sh:home/*/.cache' \
      $TARGET::$DATE-$$-home \
      /home/

    echo "Completed backup for $DATE"

    # Just to be completely paranoid
    sync

    if [ -f /etc/backups/autoeject ]; then
            umount $MOUNTPOINT
            hdparm -Y $drive
    fi

    if [ -f /etc/backups/backup-suspend ]; then
            systemctl suspend
    fi

Create the ``/etc/backups/autoeject`` file to have the script automatically eject the drive
after creating the backup. Rename the file to something else (e.g. ``/etc/backups/autoeject-no``)
when you want to do something with the drive after creating backups (e.g running check).

Create the ``/etc/backups/backup-suspend`` file if the machine should suspend after completing
the backup. Don't forget to disconnect the device physically before resuming,
otherwise you'll enter a cycle. You can also add an option to power down instead.

Create an empty ``/etc/backups/backup.disks`` file, you'll register your backup drives
there.

The last part is actually to enable the udev rules and services:

.. code-block:: bash

    ln -s /etc/backups/80-backup.rules /etc/udev/rules.d/80-backup.rules
    ln -s /etc/backups/automatic-backup.service /etc/systemd/system/automatic-backup.service
    systemctl daemon-reload
    udevadm control --reload

Adding backup hard drives
-------------------------

Connect your backup hard drive. Format it, if not done already.
Find the UUID of the file system that backups should be stored on::

    lsblk -o+uuid,label

Note the UUID into the ``/etc/backups/backup.disks`` file.

Mount the drive to /mnt/backup.

Initialize a Borg repository at the location indicated by ``TARGET``::

    borg init --encryption ... /mnt/backup/borg-backups/backup.borg

Unmount and reconnect the drive, or manually start the ``automatic-backup`` service
to start the first backup::

    systemctl start --no-block automatic-backup

See backup logs using journalctl::

    journalctl -fu automatic-backup [-n number-of-lines]

Security considerations
-----------------------

The script as shown above will mount any file system with an UUID listed in
``/etc/backups/backup.disks``. The UUID check is a safety / annoyance-reduction
mechanism to keep the script from blowing up whenever a random USB thumb drive is connected.
It is not meant as a security mechanism. Mounting file systems and reading repository
data exposes additional attack surfaces (kernel file system drivers,
possibly user space services and Borg itself). On the other hand, someone
standing right next to your computer can attempt a lot of attacks, most of which
are easier to do than e.g. exploiting file systems (installing a physical key logger,
DMA attacks, stealing the machine, ...).

Borg ensures that backups are not created on random drives that "just happen"
to contain a Borg repository. If an unknown unencrypted repository is encountered,
then the script aborts (BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK=no).

Backups are only created on hard drives that contain a Borg repository that is
either known (by ID) to your machine or you are using encryption and the
passphrase of the repository has to match the passphrase supplied to Borg.

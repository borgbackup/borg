.. include:: ../global.rst.inc
.. highlight:: none
.. _non_root_user:

================================
Backing up using a non-root user
================================

This section describes how to run Borg as a non-root user and still be able to
back up every file on the system.

Normally, Borg is run as the root user to bypass all filesystem permissions and
be able to read all files. However, in theory this also allows Borg to modify or
delete files on your system (for example, in case of a bug).

To eliminate this possibility, we can run Borg as a non-root user and give it read-only
permissions to all files on the system.


Using Linux capabilities inside a systemd service
=================================================

One way to do so is to use Linux `capabilities
<https://man7.org/linux/man-pages/man7/capabilities.7.html>`_ within a systemd
service.

Linux capabilities allow us to grant parts of the root user’s privileges to
a non-root user. This works on a per-thread level and does not grant permissions
to the non-root user as a whole.

For this, we need to run the backup script from a systemd service and use the `AmbientCapabilities
<https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#AmbientCapabilities=>`_
option added in systemd 229.

A very basic unit file would look like this:

::

    [Unit]
    Description=Borg Backup

    [Service]
    Type=oneshot
    User=borg
    ExecStart=/usr/local/sbin/backup.sh

    AmbientCapabilities=CAP_DAC_READ_SEARCH

The ``CAP_DAC_READ_SEARCH`` capability gives Borg read-only access to all files and directories on the system.

This service can then be started manually using ``systemctl start``, a systemd timer or other methods.

Restore considerations
======================

Use the root user when restoring files. If you use the non-root user, ``borg extract`` will
change ownership of all restored files to the non-root user. Using ``borg mount`` will not allow the
non-root user to access files it would not be able to access on the system itself.

Other than that, you can use the same restore process you would use when running the backup as root.

.. warning::

    When using a local repository and running Borg commands as root, make sure to use only commands that do not
    modify the repository itself, such as extract or mount. Modifying the repository as root will break it for the
    non-root user, since some files inside the repository will then be owned by root.

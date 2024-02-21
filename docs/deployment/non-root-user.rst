.. include:: ../global.rst.inc
.. highlight:: none
.. _non_root_user:

================================
Backing up using a non-root user
================================

This section describes how to run borg as a non-root user and still be able to
backup every file on the system.

Normally borg is run as the root user to bypass all filesystem permissions and
be able to read all files. But in theory this also allows borg to modify or
delete files on your system, in case of a bug for example.

To eliminate this possibility, we can run borg as a non-root user and give it read-only
permissions to all files on the system.


Using Linux capabilities inside a systemd service
=================================================

One way to do so, is to use linux `capabilities
<https://man7.org/linux/man-pages/man7/capabilities.7.html>`_ within a systemd
service.

Linux capabilities allow us to give parts of the privileges the root user has to
a non-root user. This works on a per-thread level and does not give the permission
to the non-root user as a whole.

For this we need to run our backup script from a systemd service and use the `AmbientCapabilities
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

The ``CAP_DAC_READ_SEARCH`` capability gives borg read-only access to all files and directories on the system.

This service can then be started manually using ``systemctl start``, a systemd timer or other methods.

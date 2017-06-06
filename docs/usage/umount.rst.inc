.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_umount:

borg umount
-----------
.. code-block:: none

    borg [common options] umount [options] MOUNTPOINT

positional arguments
    MOUNTPOINT
        mountpoint of the filesystem to umount

:ref:`common_options`
    |

Description
~~~~~~~~~~~

This command un-mounts a FUSE filesystem that was mounted with ``borg mount``.

This is a convenience wrapper that just calls the platform-specific shell
command - usually this is either umount or fusermount -u.
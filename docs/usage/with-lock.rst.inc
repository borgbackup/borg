.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_with-lock:

borg with-lock
--------------
.. code-block:: none

    borg [common options] with-lock [options] REPOSITORY COMMAND ARGS

positional arguments
    REPOSITORY
        repository to lock
    COMMAND
        command to run
    ARGS
        command arguments

:ref:`common_options`
    |

Description
~~~~~~~~~~~

This command runs a user-specified command while the repository lock is held.

It will first try to acquire the lock (make sure that no other operation is
running in the repo), then execute the given command as a subprocess and wait
for its termination, release the lock and return the user command's return
code as borg's return code.

Note: if you copy a repository with the lock held, the lock will be present in
      the copy, obviously. Thus, before using borg on the copy, you need to
      use "borg break-lock" on it.
.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_with-lock:

borg with-lock
--------------
.. code-block:: none

    borg [common options] with-lock [options] COMMAND [ARGS...]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+-------------+-------------------+
    | **positional arguments**                                                                |
    +-------------------------------------------------------+-------------+-------------------+
    |                                                       | ``COMMAND`` | command to run    |
    +-------------------------------------------------------+-------------+-------------------+
    |                                                       | ``ARGS``    | command arguments |
    +-------------------------------------------------------+-------------+-------------------+
    | .. class:: borg-common-opt-ref                                                          |
    |                                                                                         |
    | :ref:`common_options`                                                                   |
    +-------------------------------------------------------+-------------+-------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    COMMAND
        command to run
    ARGS
        command arguments


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

This command runs a user-specified command while locking the repository. For example:

::

    $ BORG_REPO=/mnt/borgrepo borg with-lock rsync -av /mnt/borgrepo /somewhere/else/borgrepo

It first tries to acquire the lock (make sure that no other operation is
running in the repository), then executes the given command as a subprocess and waits
for its termination, releases the lock, and returns the user command's return
code as Borg's return code.

.. note::

    If you copy a repository with the lock held, the lock will be present in
    the copy. Before using Borg on the copy from a different host,
    you need to run ``borg break-lock`` on the copied repository, because
    Borg is cautious and does not automatically remove stale locks made by a different host.
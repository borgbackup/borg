.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_with-lock:

borg with-lock
--------------
.. code-block:: none

    borg [common options] with-lock [options] REPOSITORY COMMAND [ARGS...]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+----------------+--------------------+
    | **positional arguments**                                                                    |
    +-------------------------------------------------------+----------------+--------------------+
    |                                                       | ``REPOSITORY`` | repository to lock |
    +-------------------------------------------------------+----------------+--------------------+
    |                                                       | ``COMMAND``    | command to run     |
    +-------------------------------------------------------+----------------+--------------------+
    |                                                       | ``ARGS``       | command arguments  |
    +-------------------------------------------------------+----------------+--------------------+
    | .. class:: borg-common-opt-ref                                                              |
    |                                                                                             |
    | :ref:`common_options`                                                                       |
    +-------------------------------------------------------+----------------+--------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

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

This command runs a user-specified command while locking the repository. For example:

::

    $ borg with-lock /mnt/borgrepo rsync -av /mnt/borgrepo /somewhere/else/borgrepo

It will first try to acquire the lock (make sure that no other operation is
running in the repository), then execute the given command as a subprocess and wait
for its termination, release the lock, and return the user command's return
code as Borg's return code.

.. note::

    If you copy a repository with the lock held, the lock will be present in
    the copy. Thus, before using Borg on the copy from a different host,
    you need to use "borg break-lock" on the copied repository, because
    Borg is cautious and does not automatically remove stale locks made by a different host.
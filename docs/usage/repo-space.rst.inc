.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_repo-space:

borg repo-space
---------------
.. code-block:: none

    borg [common options] repo-space [options]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+---------------------+----------------------------------------------------------------------+
    | **options**                                                                                                                                        |
    +-------------------------------------------------------+---------------------+----------------------------------------------------------------------+
    |                                                       | ``--reserve SPACE`` | Amount of space to reserve (e.g. 100M, 1G). Default: 0.              |
    +-------------------------------------------------------+---------------------+----------------------------------------------------------------------+
    |                                                       | ``--free``          | Free all reserved space. Do not forget to reserve space again later. |
    +-------------------------------------------------------+---------------------+----------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                     |
    |                                                                                                                                                    |
    | :ref:`common_options`                                                                                                                              |
    +-------------------------------------------------------+---------------------+----------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    options
        --reserve SPACE     Amount of space to reserve (e.g. 100M, 1G). Default: 0.
        --free              Free all reserved space. Do not forget to reserve space again later.


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

This command manages reserved space in a repository.

Borg cannot work in disk-full conditions (it cannot lock a repository and thus cannot
run prune/delete or compact operations to free disk space).

To avoid running into such dead-end situations, you can put some objects into a
repository that take up disk space. If you ever run into a disk-full situation, you
can free that space, and then Borg will be able to run normally so you can free more
disk space by using ``borg prune``/``borg delete``/``borg compact``. After that, do
not forget to reserve space again, in case you run into that situation again later.

Examples::

    # Create a new repository:
    $ borg repo-create ...
    # Reserve approx. 1 GiB of space for emergencies:
    $ borg repo-space --reserve 1G

    # Check the amount of reserved space in the repository:
    $ borg repo-space

    # EMERGENCY! Free all reserved space to get things back to normal:
    $ borg repo-space --free
    $ borg prune ...
    $ borg delete ...
    $ borg compact -v  # only this actually frees space of deleted archives
    $ borg repo-space --reserve 1G  # reserve space again for next time


Reserved space is always rounded up to full reservation blocks of 64 MiB.
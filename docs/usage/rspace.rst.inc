.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_rspace:

borg rspace
-----------
.. code-block:: none

    borg [common options] rspace [options]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+---------------------+---------------------------------------------------------------------+
    | **optional arguments**                                                                                                                            |
    +-------------------------------------------------------+---------------------+---------------------------------------------------------------------+
    |                                                       | ``--reserve SPACE`` | Amount of space to reserve (e.g. 100M, 1G). Default: 0.             |
    +-------------------------------------------------------+---------------------+---------------------------------------------------------------------+
    |                                                       | ``--free``          | Free all reserved space. Don't forget to reserve space later again. |
    +-------------------------------------------------------+---------------------+---------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                    |
    |                                                                                                                                                   |
    | :ref:`common_options`                                                                                                                             |
    +-------------------------------------------------------+---------------------+---------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    optional arguments
        --reserve SPACE     Amount of space to reserve (e.g. 100M, 1G). Default: 0.
        --free              Free all reserved space. Don't forget to reserve space later again.


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

This command manages reserved space in a repository.

Borg can not work in disk-full conditions (can not lock a repo and thus can
not run prune/delete or compact operations to free disk space).

To avoid running into dead-end situations like that, you can put some objects
into a repository that take up some disk space. If you ever run into a
disk-full situation, you can free that space and then borg will be able to
run normally, so you can free more disk space by using prune/delete/compact.
After that, don't forget to reserve space again, in case you run into that
situation again at a later time.

Examples::

    # Create a new repository:
    $ borg rcreate ...
    # Reserve approx. 1GB of space for emergencies:
    $ borg rspace --reserve 1G

    # Check amount of reserved space in the repository:
    $ borg rspace

    # EMERGENCY! Free all reserved space to get things back to normal:
    $ borg rspace --free
    $ borg prune ...
    $ borg delete ...
    $ borg compact -v  # only this actually frees space of deleted archives
    $ borg rspace --reserve 1G  # reserve space again for next time


Reserved space is always rounded up to use full reservation blocks of 64MiB.
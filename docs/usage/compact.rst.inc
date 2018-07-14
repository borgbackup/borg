.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_compact:

borg compact
------------
.. code-block:: none

    borg [common options] compact [options] REPOSITORY

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+-----------------------+-------------------------------------------+
    | **positional arguments**                                                                                                  |
    +-------------------------------------------------------+-----------------------+-------------------------------------------+
    |                                                       | ``REPOSITORY``        | repository to compact                     |
    +-------------------------------------------------------+-----------------------+-------------------------------------------+
    | **optional arguments**                                                                                                    |
    +-------------------------------------------------------+-----------------------+-------------------------------------------+
    |                                                       | ``--cleanup-commits`` | cleanup commit-only 17-byte segment files |
    +-------------------------------------------------------+-----------------------+-------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                            |
    |                                                                                                                           |
    | :ref:`common_options`                                                                                                     |
    +-------------------------------------------------------+-----------------------+-------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    REPOSITORY
        repository to compact


    optional arguments
        --cleanup-commits     cleanup commit-only 17-byte segment files


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

This command frees repository space by compacting segments.

Use this regularly to avoid running out of space - you do not need to use this
after each borg command though.

borg compact does not need a key, so it is possible to invoke it from the
client or also from the server.

Depending on the amount of segments that need compaction, it may take a while.

See :ref:`separate_compaction` in Additional Notes for more details.
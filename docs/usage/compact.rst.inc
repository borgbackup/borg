.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_compact:

borg compact
------------
.. code-block:: none

    borg [common options] compact [options]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+-------------------------+----------------------------------------------------------------+
    | **optional arguments**                                                                                                                           |
    +-------------------------------------------------------+-------------------------+----------------------------------------------------------------+
    |                                                       | ``--threshold PERCENT`` | set minimum threshold for saved space in PERCENT (Default: 10) |
    +-------------------------------------------------------+-------------------------+----------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                   |
    |                                                                                                                                                  |
    | :ref:`common_options`                                                                                                                            |
    +-------------------------------------------------------+-------------------------+----------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    optional arguments
        --threshold PERCENT     set minimum threshold for saved space in PERCENT (Default: 10)


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

This command frees repository space by compacting segments.

Use this regularly to avoid running out of space - you do not need to use this
after each borg command though. It is especially useful after deleting archives,
because only compaction will really free repository space.

borg compact does not need a key, so it is possible to invoke it from the
client or also from the server.

Depending on the amount of segments that need compaction, it may take a while,
so consider using the ``--progress`` option.

A segment is compacted if the amount of saved space is above the percentage value
given by the ``--threshold`` option. If omitted, a threshold of 10% is used.
When using ``--verbose``, borg will output an estimate of the freed space.

See :ref:`separate_compaction` in Additional Notes for more details.
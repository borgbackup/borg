.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_benchmark_cpu:

borg benchmark cpu
------------------
.. code-block:: none

    borg [common options] benchmark cpu [options]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+
    | .. class:: borg-common-opt-ref                        |
    |                                                       |
    | :ref:`common_options`                                 |
    +-------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    :ref:`common_options`
        |

Description
~~~~~~~~~~~

This command benchmarks misc. CPU bound borg operations.

It creates input data in memory, runs the operation and then displays throughput.
To reduce outside influence on the timings, please make sure to run this with:

- an otherwise as idle as possible machine
- enough free memory so there will be no slow down due to paging activity
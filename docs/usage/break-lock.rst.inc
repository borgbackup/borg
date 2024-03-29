.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_break-lock:

borg break-lock
---------------
.. code-block:: none

    borg [common options] break-lock [options]

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

This command breaks the repository and cache locks.
Please use carefully and only while no borg process (on any machine) is
trying to access the Cache or the Repository.
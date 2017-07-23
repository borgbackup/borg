.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_key_change-passphrase:

borg key change-passphrase
--------------------------
.. code-block:: none

    borg [common options] key change-passphrase [options] [REPOSITORY]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+----------------+--+
    | **positional arguments**                                                  |
    +-------------------------------------------------------+----------------+--+
    |                                                       | ``REPOSITORY`` |  |
    +-------------------------------------------------------+----------------+--+
    | .. class:: borg-common-opt-ref                                            |
    |                                                                           |
    | :ref:`common_options`                                                     |
    +-------------------------------------------------------+----------------+--+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    REPOSITORY



    :ref:`common_options`
        |

Description
~~~~~~~~~~~

The key files used for repository encryption are optionally passphrase
protected. This command can be used to change this passphrase.
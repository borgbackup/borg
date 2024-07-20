.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_key_change-location:

borg key change-location
------------------------
.. code-block:: none

    borg [common options] key change-location [options] KEY_LOCATION

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+------------------+----------------------------------------------------------------+
    | **positional arguments**                                                                                                                  |
    +-------------------------------------------------------+------------------+----------------------------------------------------------------+
    |                                                       | ``KEY_LOCATION`` | select key location                                            |
    +-------------------------------------------------------+------------------+----------------------------------------------------------------+
    | **optional arguments**                                                                                                                    |
    +-------------------------------------------------------+------------------+----------------------------------------------------------------+
    |                                                       | ``--keep``       | keep the key also at the current location (default: remove it) |
    +-------------------------------------------------------+------------------+----------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                            |
    |                                                                                                                                           |
    | :ref:`common_options`                                                                                                                     |
    +-------------------------------------------------------+------------------+----------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    KEY_LOCATION
        select key location


    optional arguments
        --keep     keep the key also at the current location (default: remove it)


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

Change the location of a borg key. The key can be stored at different locations:

- keyfile: locally, usually in the home directory
- repokey: inside the repo (in the repo config)

Please note:

This command does NOT change the crypto algorithms, just the key location,
thus you must ONLY give the key location (keyfile or repokey).
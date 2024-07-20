.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_key_import:

borg key import
---------------
.. code-block:: none

    borg [common options] key import [options] [PATH]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+-------------+----------------------------------------------------------+
    | **positional arguments**                                                                                                       |
    +-------------------------------------------------------+-------------+----------------------------------------------------------+
    |                                                       | ``PATH``    | path to the backup ('-' to read from stdin)              |
    +-------------------------------------------------------+-------------+----------------------------------------------------------+
    | **optional arguments**                                                                                                         |
    +-------------------------------------------------------+-------------+----------------------------------------------------------+
    |                                                       | ``--paper`` | interactively import from a backup done with ``--paper`` |
    +-------------------------------------------------------+-------------+----------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                 |
    |                                                                                                                                |
    | :ref:`common_options`                                                                                                          |
    +-------------------------------------------------------+-------------+----------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    PATH
        path to the backup ('-' to read from stdin)


    optional arguments
        --paper     interactively import from a backup done with ``--paper``


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

This command restores a key previously backed up with the export command.

If the ``--paper`` option is given, the import will be an interactive
process in which each line is checked for plausibility before
proceeding to the next line. For this format PATH must not be given.

For repositories using keyfile encryption, the key file which ``borg key
import`` writes to depends on several factors. If the ``BORG_KEY_FILE``
environment variable is set and non-empty, ``borg key import`` creates
or overwrites that file named by ``$BORG_KEY_FILE``. Otherwise, ``borg
key import`` searches in the ``$BORG_KEYS_DIR`` directory for a key file
associated with the repository. If a key file is found in
``$BORG_KEYS_DIR``, ``borg key import`` overwrites it; otherwise, ``borg
key import`` creates a new key file in ``$BORG_KEYS_DIR``.
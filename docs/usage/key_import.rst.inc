.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_key_import:

borg key import
---------------
.. code-block:: none

    borg [common options] key import [options] [PATH]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+-----------------------------+--------------------------------------------------------------------------------------------------------------------+
    | **positional arguments**                                                                                                                                                                                 |
    +-------------------------------------------------------+-----------------------------+--------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``PATH``                    | path to the backup ('-' to read from stdin)                                                                        |
    +-------------------------------------------------------+-----------------------------+--------------------------------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                                              |
    +-------------------------------------------------------+-----------------------------+--------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--paper``                 | interactively import from a backup done with ``--paper``                                                           |
    +-------------------------------------------------------+-----------------------------+--------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--key-location LOCATION`` | where to store the imported key: 'repokey' (in the repository, default) or 'keyfile' (in the local keys directory) |
    +-------------------------------------------------------+-----------------------------+--------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                           |
    |                                                                                                                                                                                                          |
    | :ref:`common_options`                                                                                                                                                                                    |
    +-------------------------------------------------------+-----------------------------+--------------------------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    PATH
        path to the backup ('-' to read from stdin)


    options
        --paper     interactively import from a backup done with ``--paper``
        --key-location LOCATION    where to store the imported key: 'repokey' (in the repository, default) or 'keyfile' (in the local keys directory)


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

This command restores a key previously backed up with the export command.

If the ``--paper`` option is given, the import will be an interactive
process in which each line is checked for plausibility before
proceeding to the next line. For this format PATH must not be given.

Where the imported key is stored is decided by ``--key-location``:

- ``repokey`` (the default): the key is stored **in the repository**, no local
  key file is written.
- ``keyfile``: the key is stored in a local key file.

The key file that ``--key-location=keyfile`` writes to depends on several
factors. If the ``BORG_KEY_FILE`` environment variable is set and non-empty,
``borg key import`` creates or overwrites the file named by ``$BORG_KEY_FILE``.
Otherwise, ``borg key import`` searches the ``$BORG_KEYS_DIR`` directory for a
key file associated with the repository. If one is found there, ``borg key
import`` overwrites it; otherwise it creates a new key file in
``$BORG_KEYS_DIR``.
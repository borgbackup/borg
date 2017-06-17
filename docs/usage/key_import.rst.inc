.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_key_import:

borg key import
---------------
.. code-block:: none

    borg [common options] key import [options] REPOSITORY PATH

positional arguments
    REPOSITORY

    PATH
        path to the backup

optional arguments
    ``--paper``
        | interactively import from a backup done with ``--paper``

:ref:`common_options`
    |

Description
~~~~~~~~~~~

This command allows to restore a key previously backed up with the
export command.

If the ``--paper`` option is given, the import will be an interactive
process in which each line is checked for plausibility before
proceeding to the next line. For this format PATH must not be given.
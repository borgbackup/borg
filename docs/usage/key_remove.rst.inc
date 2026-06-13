.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_key_remove:

borg key remove
---------------
.. code-block:: none

    borg [common options] key remove [options]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+-------------------+------------------------------------------------------------+
    | **options**                                                                                                                            |
    +-------------------------------------------------------+-------------------+------------------------------------------------------------+
    |                                                       | ``--label LABEL`` | remove the borg key with this label                        |
    +-------------------------------------------------------+-------------------+------------------------------------------------------------+
    |                                                       | ``--key ID``      | remove the borg key with this id (or unique id prefix)     |
    +-------------------------------------------------------+-------------------+------------------------------------------------------------+
    |                                                       | ``--passphrase``  | remove the borg key that was used to unlock the repository |
    +-------------------------------------------------------+-------------------+------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                         |
    |                                                                                                                                        |
    | :ref:`common_options`                                                                                                                  |
    +-------------------------------------------------------+-------------------+------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    options
        --label LABEL    remove the borg key with this label
        --key ID         remove the borg key with this id (or unique id prefix)
        --passphrase     remove the borg key that was used to unlock the repository


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

Remove a borg key from the repository.

The borg key to remove is selected by exactly one of: ``--label`` (its label),
``--key`` (its key id or a unique prefix, see ``borg key list``), or
``--passphrase`` (remove the borg key that was used to unlock the repository now).

The ``admin`` borg key is protected and cannot be removed, and the last remaining
borg key of a repository cannot be removed either.
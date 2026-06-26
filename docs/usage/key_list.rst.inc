.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_key_list:

borg key list
-------------
.. code-block:: none

    borg [common options] key list [options]

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

List the borg keys of the repository, showing each borg key's id, mode (``repokey`` or
``keyfile``), label and key derivation/encryption algorithm. The borg key used to
unlock the repository in this invocation is marked with ``*``.
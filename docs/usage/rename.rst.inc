.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_rename:

borg rename
-----------
.. code-block:: none

    borg [common options] rename [options] OLDNAME NEWNAME

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+-------------+------------------------------+
    | **positional arguments**                                                                           |
    +-------------------------------------------------------+-------------+------------------------------+
    |                                                       | ``OLDNAME`` | specify the archive name     |
    +-------------------------------------------------------+-------------+------------------------------+
    |                                                       | ``NEWNAME`` | specify the new archive name |
    +-------------------------------------------------------+-------------+------------------------------+
    | .. class:: borg-common-opt-ref                                                                     |
    |                                                                                                    |
    | :ref:`common_options`                                                                              |
    +-------------------------------------------------------+-------------+------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    OLDNAME
        specify the archive name
    NEWNAME
        specify the new archive name


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

This command renames an archive in the repository.

This results in a different archive ID.
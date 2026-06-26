.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_key_add:

borg key add
------------
.. code-block:: none

    borg [common options] key add [options]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+-------------------+---------------------------------------------+
    | **options**                                                                                                             |
    +-------------------------------------------------------+-------------------+---------------------------------------------+
    |                                                       | ``--label LABEL`` | label for the new borg key (must be unique) |
    +-------------------------------------------------------+-------------------+---------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                          |
    |                                                                                                                         |
    | :ref:`common_options`                                                                                                   |
    +-------------------------------------------------------+-------------------+---------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    options
        --label LABEL     label for the new borg key (must be unique)


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

A repository can be protected by more than one borg key. Each borg key contains the
same secret key material, but is protected by an independent (potentially different)
passphrase, and any of them can be used to unlock the same repository. This is useful
e.g. to give individual users their own passphrase while keeping a separate
admin/recovery passphrase.

This command adds an additional borg key. It does not re-encrypt any repository data
and does not change the existing borg keys. The new passphrase is read from
``BORG_NEW_PASSPHRASE`` or queried interactively.

Each borg key has a label. The first borg key, created at repository creation time, has
the reserved label ``admin`` and is protected from deletion. Additionally added borg
keys require a unique, user-defined ``--label``.
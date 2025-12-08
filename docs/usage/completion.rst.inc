.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_completion:

borg completion
---------------
.. code-block:: none

    borg [common options] completion [options] SHELL

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+-----------+--------------------------------------------------------+
    | **positional arguments**                                                                                                   |
    +-------------------------------------------------------+-----------+--------------------------------------------------------+
    |                                                       | ``SHELL`` | shell to generate completion for (one of: %(choices)s) |
    +-------------------------------------------------------+-----------+--------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                             |
    |                                                                                                                            |
    | :ref:`common_options`                                                                                                      |
    +-------------------------------------------------------+-----------+--------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    SHELL
        shell to generate completion for (one of: %(choices)s)


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

This command prints a shell completion script for the given shell.

Please note that for some dynamic completions (like archive IDs), the shell
completion script will call borg to query the repository. This will work best
if that call can be made without prompting for user input, so you may want to
set BORG_REPO and BORG_PASSPHRASE environment variables.
.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_repo-compress:

borg repo-compress
------------------
.. code-block:: none

    borg [common options] repo-compress [options]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+---------------------------------------------------+--------------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                                                  |
    +-------------------------------------------------------+---------------------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                       | ``-C COMPRESSION``, ``--compression COMPRESSION`` | select compression algorithm, see the output of the "borg help compression" command for details. |
    +-------------------------------------------------------+---------------------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                       | ``-s``, ``--stats``                               | print statistics                                                                                 |
    +-------------------------------------------------------+---------------------------------------------------+--------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                               |
    |                                                                                                                                                                                                              |
    | :ref:`common_options`                                                                                                                                                                                        |
    +-------------------------------------------------------+---------------------------------------------------+--------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    options
        -C COMPRESSION, --compression COMPRESSION    select compression algorithm, see the output of the "borg help compression" command for details.
        -s, --stats     print statistics


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

Repository (re-)compression (and/or re-obfuscation).

Reads all chunks in the repository and recompresses them if they are not already
using the compression type/level and obfuscation level given via ``--compression``.

If the outcome of the chunk processing indicates a change in compression
type/level or obfuscation level, the processed chunk is written to the repository.
Please note that the outcome might not always be the desired compression
type/level - if no compression gives a shorter output, that might be chosen.

Please note that this command can not work in low (or zero) free disk space
conditions.

If the ``borg repo-compress`` process receives a SIGINT signal (Ctrl-C), the repo
will be committed and compacted and borg will terminate cleanly afterwards.

Both ``--progress`` and ``--stats`` are recommended when ``borg repo-compress``
is used interactively.

You do **not** need to run ``borg compact`` after ``borg repo-compress``.
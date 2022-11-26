.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_rcompress:

borg rcompress
--------------
.. code-block:: none

    borg [common options] rcompress [options]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+---------------------------------------------------+--------------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                                                  |
    +-------------------------------------------------------+---------------------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                       | ``-C COMPRESSION``, ``--compression COMPRESSION`` | select compression algorithm, see the output of the "borg help compression" command for details. |
    +-------------------------------------------------------+---------------------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                       | ``-s``, ``--stats``                               | print statistics                                                                                 |
    +-------------------------------------------------------+---------------------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                       | ``-c SECONDS``, ``--checkpoint-interval SECONDS`` | write checkpoint every SECONDS seconds (Default: 1800)                                           |
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
        -c SECONDS, --checkpoint-interval SECONDS    write checkpoint every SECONDS seconds (Default: 1800)


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

Repository (re-)compression (and/or re-obfuscation).

Reads all chunks in the repository (in on-disk order, this is important for
compaction) and recompresses them if they are not already using the compression
type/level and obfuscation level given via ``--compression``.

If the outcome of the chunk processing indicates a change in compression
type/level or obfuscation level, the processed chunk is written to the repository.
Please note that the outcome might not always be the desired compression
type/level - if no compression gives a shorter output, that might be chosen.

Every ``--checkpoint-interval``, progress is committed to the repository and
the repository is compacted (this is to keep temporary repo space usage in bounds).
A lower checkpoint interval means lower temporary repo space usage, but also
slower progress due to higher overhead (and vice versa).

Please note that this command can not work in low (or zero) free disk space
conditions.

If the ``borg rcompress`` process receives a SIGINT signal (Ctrl-C), the repo
will be committed and compacted and borg will terminate cleanly afterwards.

Both ``--progress`` and ``--stats`` are recommended when ``borg rcompress``
is used interactively.

You do **not** need to run ``borg compact`` after ``borg rcompress``.
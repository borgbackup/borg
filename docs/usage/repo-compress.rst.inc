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

Reads all repository objects and recompresses the ones that are not already using
the compression type/level and obfuscation level given via ``--compression``.

The repository is processed one pack file at a time: a pack is read as a whole and,
if it holds objects that need recompression, rewritten as a whole - objects already
using the desired compression are copied into the rewritten pack unchanged. A pack
whose objects all already use the desired compression is not touched at all.
Please note that the outcome of recompressing a chunk might not always be the
desired compression type/level - if no compression gives a shorter output, that
might be chosen; such chunks are kept as they are.

Rewriting a pack invalidates every client's cached chunk index, so the next borg
operation of each client will re-fetch the chunk index from the repository.

This command needs free space in the repository for the rewritten pack files
(roughly one pack file size while running).

If the ``borg repo-compress`` process receives a SIGINT signal (Ctrl-C), it stops
at the next pack boundary, leaving the repository and its chunk index in a
consistent state; running it again later processes the remaining packs.

Both ``--progress`` and ``--stats`` are recommended when ``borg repo-compress``
is used interactively.

You do **not** need to run ``borg compact`` after ``borg repo-compress``.
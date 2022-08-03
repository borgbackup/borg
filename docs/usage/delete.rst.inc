.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_delete:

borg delete
-----------
.. code-block:: none

    borg [common options] delete [options]

.. only:: html

    .. class:: borg-options-table

    +-----------------------------------------------------------------------------+---------------------------------------------------+--------------------------------------------------------------------------------------------------+
    | **optional arguments**                                                                                                                                                                                                             |
    +-----------------------------------------------------------------------------+---------------------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``-n``, ``--dry-run``                             | do not change repository                                                                         |
    +-----------------------------------------------------------------------------+---------------------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``--list``                                        | output verbose list of archives                                                                  |
    +-----------------------------------------------------------------------------+---------------------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``--consider-checkpoints``                        | consider checkpoint archives for deletion (default: not considered).                             |
    +-----------------------------------------------------------------------------+---------------------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``-s``, ``--stats``                               | print statistics for the deleted archive                                                         |
    +-----------------------------------------------------------------------------+---------------------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``--cache-only``                                  | delete only the local cache for the given repository                                             |
    +-----------------------------------------------------------------------------+---------------------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``--force``                                       | force deletion of corrupted archives, use ``--force --force`` in case ``--force`` does not work. |
    +-----------------------------------------------------------------------------+---------------------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``--save-space``                                  | work slower, but using less space                                                                |
    +-----------------------------------------------------------------------------+---------------------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``-c SECONDS``, ``--checkpoint-interval SECONDS`` | write checkpoint every SECONDS seconds (Default: 1800)                                           |
    +-----------------------------------------------------------------------------+---------------------------------------------------+--------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                     |
    |                                                                                                                                                                                                                                    |
    | :ref:`common_options`                                                                                                                                                                                                              |
    +-----------------------------------------------------------------------------+---------------------------------------------------+--------------------------------------------------------------------------------------------------+
    | **Archive filters** — Archive filters can be applied to repository targets.                                                                                                                                                        |
    +-----------------------------------------------------------------------------+---------------------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``-a GLOB``, ``--glob-archives GLOB``             | only consider archive names matching the glob. sh: rules apply, see "borg help patterns".        |
    +-----------------------------------------------------------------------------+---------------------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``--sort-by KEYS``                                | Comma-separated list of sorting keys; valid keys are: timestamp, name, id; default is: timestamp |
    +-----------------------------------------------------------------------------+---------------------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``--first N``                                     | consider first N archives after other filters were applied                                       |
    +-----------------------------------------------------------------------------+---------------------------------------------------+--------------------------------------------------------------------------------------------------+
    |                                                                             | ``--last N``                                      | consider last N archives after other filters were applied                                        |
    +-----------------------------------------------------------------------------+---------------------------------------------------+--------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    optional arguments
        -n, --dry-run    do not change repository
        --list          output verbose list of archives
        --consider-checkpoints    consider checkpoint archives for deletion (default: not considered).
        -s, --stats     print statistics for the deleted archive
        --cache-only    delete only the local cache for the given repository
        --force         force deletion of corrupted archives, use ``--force --force`` in case ``--force`` does not work.
        --save-space    work slower, but using less space
        -c SECONDS, --checkpoint-interval SECONDS    write checkpoint every SECONDS seconds (Default: 1800)


    :ref:`common_options`
        |

    Archive filters
        -a GLOB, --glob-archives GLOB     only consider archive names matching the glob. sh: rules apply, see "borg help patterns".
        --sort-by KEYS                    Comma-separated list of sorting keys; valid keys are: timestamp, name, id; default is: timestamp
        --first N                         consider first N archives after other filters were applied
        --last N                          consider last N archives after other filters were applied


Description
~~~~~~~~~~~

This command deletes archives from the repository.

Important: When deleting archives, repository disk space is **not** freed until
you run ``borg compact``.

When in doubt, use ``--dry-run --list`` to see what would be deleted.

When using ``--stats``, you will get some statistics about how much data was
deleted - the "Deleted data" deduplicated size there is most interesting as
that is how much your repository will shrink.
Please note that the "All archives" stats refer to the state after deletion.

You can delete multiple archives by specifying a matching shell pattern,
using the ``--glob-archives GLOB`` option (for more info on these patterns,
see :ref:`borg_patterns`).

Always first use ``--dry-run --list`` to see what would be deleted.
.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_delete:

borg delete
-----------
.. code-block:: none

    borg [common options] delete [options] [TARGET] [ARCHIVE...]

.. only:: html

    .. class:: borg-options-table

    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **positional arguments**                                                                                                                                                                                                                                                     |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``TARGET``                            | archive or repository to delete                                                                                                                        |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``ARCHIVE``                           | archives to delete                                                                                                                                     |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **optional arguments**                                                                                                                                                                                                                                                       |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-n``, ``--dry-run``                 | do not change repository                                                                                                                               |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-s``, ``--stats``                   | print statistics for the deleted archive                                                                                                               |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--cache-only``                      | delete only the local cache for the given repository                                                                                                   |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--force``                           | force deletion of corrupted archives, use ``--force --force`` in case ``--force`` does not work.                                                       |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--save-space``                      | work slower, but using less space                                                                                                                      |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                                                               |
    |                                                                                                                                                                                                                                                                              |
    | :ref:`common_options`                                                                                                                                                                                                                                                        |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **Archive filters** — Archive filters can be applied to repository targets.                                                                                                                                                                                                  |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-P PREFIX``, ``--prefix PREFIX``    | only consider archive names starting with this prefix.                                                                                                 |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-a GLOB``, ``--glob-archives GLOB`` | only consider archive names matching the glob. sh: rules apply, see "borg help patterns". ``--prefix`` and ``--glob-archives`` are mutually exclusive. |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--sort-by KEYS``                    | Comma-separated list of sorting keys; valid keys are: timestamp, name, id; default is: timestamp                                                       |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--first N``                         | consider first N archives after other filters were applied                                                                                             |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--last N``                          | consider last N archives after other filters were applied                                                                                              |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    TARGET
        archive or repository to delete
    ARCHIVE
        archives to delete


    optional arguments
        -n, --dry-run    do not change repository
        -s, --stats     print statistics for the deleted archive
        --cache-only    delete only the local cache for the given repository
        --force         force deletion of corrupted archives, use ``--force --force`` in case ``--force`` does not work.
        --save-space    work slower, but using less space


    :ref:`common_options`
        |

    Archive filters
        -P PREFIX, --prefix PREFIX        only consider archive names starting with this prefix.
        -a GLOB, --glob-archives GLOB     only consider archive names matching the glob. sh: rules apply, see "borg help patterns". ``--prefix`` and ``--glob-archives`` are mutually exclusive.
        --sort-by KEYS                    Comma-separated list of sorting keys; valid keys are: timestamp, name, id; default is: timestamp
        --first N                         consider first N archives after other filters were applied
        --last N                          consider last N archives after other filters were applied


Description
~~~~~~~~~~~

This command deletes an archive from the repository or the complete repository.

Important: When deleting archives, repository disk space is **not** freed until
you run ``borg compact``.

If you delete the complete repository, the local cache for it (if any) is
also deleted. Alternatively, you can delete just the local cache with the
``--cache-only`` option.

When using ``--stats``, you will get some statistics about how much data was
deleted - the "Deleted data" deduplicated size there is most interesting as
that is how much your repository will shrink.
Please note that the "All archives" stats refer to the state after deletion.

You can delete multiple archives by specifying their common prefix, if they
have one, using the ``--prefix PREFIX`` option. You can also specify a shell
pattern to match multiple archives using the ``--glob-archives GLOB`` option
(for more info on these patterns, see ``borg help patterns``). Note that these
two options are mutually exclusive.

To avoid accidentally deleting archives, especially when using glob patterns,
it might be helpful to use the ``--dry-run`` to test out the command without
actually making any changes to the repository.
.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_delete:

borg delete
-----------
.. code-block:: none

    borg [common options] delete [options] [REPOSITORY_OR_ARCHIVE] [ARCHIVE...]

.. only:: html

    .. class:: borg-options-table

    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **positional arguments**                                                                                                                                                                                                                                                     |
    +-----------------------------------------------------------------------------+---------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``REPOSITORY_OR_ARCHIVE``             | repository or archive to delete                                                                                                                        |
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

    REPOSITORY_OR_ARCHIVE
        repository or archive to delete
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
Disk space is reclaimed accordingly. If you delete the complete repository, the
local cache for it (if any) is also deleted.

When using ``--stats``, you will get some statistics about how much data was
deleted - the "Deleted data" deduplicated size there is most interesting as
that is how much your repository will shrink.
Please note that the "All archives" stats refer to the state after deletion.
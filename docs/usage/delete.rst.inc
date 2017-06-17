.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_delete:

borg delete
-----------
.. code-block:: none

    borg [common options] delete [options] TARGET

positional arguments
    TARGET
        archive or repository to delete

optional arguments
    ``-s``, ``--stats``
        | print statistics for the deleted archive
    ``-c``, ``--cache-only``
        | delete only the local cache for the given repository
    ``--force``
        | force deletion of corrupted archives, use --force --force in case --force does not work.
    ``--save-space``
        | work slower, but using less space

:ref:`common_options`
    |

filters
    ``-P``, ``--prefix``
        | only consider archive names starting with this prefix.
    ``-a``, ``--glob-archives``
        | only consider archive names matching the glob. sh: rules apply, see "borg help patterns". ``--prefix`` and ``--glob-archives`` are mutually exclusive.
    ``--sort-by``
        | Comma-separated list of sorting keys; valid keys are: timestamp, name, id; default is: timestamp
    ``--first N``
        | consider first N archives after other filters were applied
    ``--last N``
        | consider last N archives after other filters were applied

Description
~~~~~~~~~~~

This command deletes an archive from the repository or the complete repository.
Disk space is reclaimed accordingly. If you delete the complete repository, the
local cache for it (if any) is also deleted.
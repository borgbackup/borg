.. _borg_delete:

borg delete
-----------
::

    borg delete <options> TARGET

positional arguments
    TARGET
        archive or repository to delete

optional arguments
    ``-p``, ``--progress``
        | show progress display while deleting a single archive
    ``-s``, ``--stats``
        | print statistics for the deleted archive
    ``-c``, ``--cache-only``
        | delete only the local cache for the given repository
    ``--save-space``
        | work slower, but using less space

`Common options`_
    |

Description
~~~~~~~~~~~

This command deletes an archive from the repository or the complete repository.
Disk space is reclaimed accordingly. If you delete the complete repository, the
local cache for it (if any) is also deleted.

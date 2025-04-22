.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_compact:

borg compact
------------
.. code-block:: none

    borg [common options] compact [options]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+-----------------------+-----------------------------------------+
    | **options**                                                                                                             |
    +-------------------------------------------------------+-----------------------+-----------------------------------------+
    |                                                       | ``-n``, ``--dry-run`` | do nothing                              |
    +-------------------------------------------------------+-----------------------+-----------------------------------------+
    |                                                       | ``-s``, ``--stats``   | print statistics (might be much slower) |
    +-------------------------------------------------------+-----------------------+-----------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                          |
    |                                                                                                                         |
    | :ref:`common_options`                                                                                                   |
    +-------------------------------------------------------+-----------------------+-----------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    options
        -n, --dry-run    do nothing
        -s, --stats     print statistics (might be much slower)


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

Free repository space by deleting unused chunks.

borg compact analyzes all existing archives to find out which repository
objects are actually used (referenced). It then deletes all unused objects
from the repository to free space.

Unused objects may result from:

- borg delete or prune usage
- interrupted backups (maybe retry the backup first before running compact)
- backup of source files that had an I/O error in the middle of their contents
  and that were skipped due to this
- corruption of the repository (e.g. the archives directory having lost
  entries, see notes below)

You usually don't want to run ``borg compact`` after every write operation, but
either regularly (e.g. once a month, possibly together with ``borg check``) or
when disk space needs to be freed.

**Important:**

After compacting it is no longer possible to use ``borg undelete`` to recover
previously soft-deleted archives.

``borg compact`` might also delete data from archives that were "lost" due to
archives directory corruption. Such archives could potentially be restored with
``borg check --find-lost-archives [--repair]``, which is slow. You therefore
might not want to do that unless there are signs of lost archives (e.g. when
seeing fatal errors when creating backups or when archives are missing in
``borg repo-list``).

When giving the ``--stats`` option, borg will internally list all repository
objects to determine their existence AND stored size. It will build a fresh
chunks index from that information and cache it in the repository. For some
types of repositories, this might be very slow. It will tell you the sum of
stored object sizes, before and after compaction.

Without ``--stats``, borg will rely on the cached chunks index to determine
existing object IDs (but there is no stored size information in the index,
thus it can't compute before/after compaction size statistics).
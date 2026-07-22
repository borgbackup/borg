.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_compact:

borg compact
------------
.. code-block:: none

    borg [common options] compact [options]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+-------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                                                                                             |
    +-------------------------------------------------------+-------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``-n``, ``--dry-run``   | do not change the repository, just show what compact would free                                                                                                       |
    +-------------------------------------------------------+-------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``-s``, ``--stats``     | print repository size statistics                                                                                                                                      |
    +-------------------------------------------------------+-------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                       | ``--threshold PERCENT`` | rewrite a pack when at least PERCENT of its bytes are unused; also gates whether to compact at all (see the all-packs gate above), 0 disables that gate (default: 10) |
    +-------------------------------------------------------+-------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                                          |
    |                                                                                                                                                                                                                                                         |
    | :ref:`common_options`                                                                                                                                                                                                                                   |
    +-------------------------------------------------------+-------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex



    options
        -n, --dry-run    do not change the repository, just show what compact would free
        -s, --stats     print repository size statistics
        --threshold PERCENT    rewrite a pack when at least PERCENT of its bytes are unused; also gates whether to compact at all (see the all-packs gate above), 0 disables that gate (default: 10)


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

Free repository space by deleting unused chunks.

``borg compact`` analyzes all existing archives to determine which repository
objects are actually used (referenced). It then deletes all unused objects
from the repository to free space.

Unused objects may result from:

- use of ``borg delete`` or ``borg prune``
- interrupted backups (consider retrying the backup before running compact)
- backups of source files that encountered an I/O error mid-transfer and were skipped
- corruption of the repository (e.g., the archives directory lost entries; see notes below)

``borg compact`` reclaims objects the chunk index knows about, plus redundant copies of
indexed chunks (e.g. written by concurrent backups) that it finds while rewriting a pack.
Other bytes no index entry covers, such as packs left behind by a backup that crashed
before recording its objects, are re-indexed by ``borg check --repair`` and reclaimed by
the next ``borg compact``.

You usually do not want to run ``borg compact`` after every write operation, but
either regularly (e.g., once a month, possibly together with ``borg check``) or
when disk space needs to be freed.

Compacting anything rewrites the whole chunk index and invalidates every client's
cached copy of it, so ``borg compact`` only acts when the gain is worth that cost:

- All-packs gate: it drops or rewrites packs only when the space they would free
  reaches ``--threshold`` divided by 5 percent (2% at the default threshold) of the
  total pack size. Below that floor it leaves the repository (and the chunk index)
  untouched. Use ``--threshold 0`` to disable the gate and always compact.
- Tiny-pack merging: incremental backups tend to leave one small, fully-used pack per
  run. ``borg compact`` combines such tiny packs into larger ones, but only once their
  combined size is large enough to fill at least one full-size pack, so a merge always
  produces a pack that will not be a merge candidate again.

**Important:**

After compacting, it is no longer possible to use ``borg undelete`` to recover
previously soft-deleted archives.

``borg compact`` might also delete data from archives that were "lost" due to
archives directory corruption. Such archives could potentially be restored with
``borg check --find-lost-archives [--repair]``, which is slow. You therefore
might not want to do that unless there are signs of lost archives (e.g., when
seeing fatal errors when creating backups or when archives are missing in
``borg repo-list``).

With ``--stats``, borg additionally reports the on-disk size of the pack files
before and after compaction (the reported compression factor is based on that size).
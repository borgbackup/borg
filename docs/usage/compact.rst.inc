.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_compact:

borg compact
------------
.. code-block:: none

    borg [common options] compact [options] [REPOSITORY]

.. only:: html

    .. class:: borg-options-table

    +-------------------------------------------------------+-------------------------+----------------------------------------------------------------+
    | **positional arguments**                                                                                                                         |
    +-------------------------------------------------------+-------------------------+----------------------------------------------------------------+
    |                                                       | ``REPOSITORY``          | repository to compact                                          |
    +-------------------------------------------------------+-------------------------+----------------------------------------------------------------+
    | **options**                                                                                                                                      |
    +-------------------------------------------------------+-------------------------+----------------------------------------------------------------+
    |                                                       | ``-n``, ``--dry-run``   | do nothing                                                     |
    +-------------------------------------------------------+-------------------------+----------------------------------------------------------------+
    |                                                       | ``--cleanup-commits``   | cleanup commit-only 17-byte segment files                      |
    +-------------------------------------------------------+-------------------------+----------------------------------------------------------------+
    |                                                       | ``--threshold PERCENT`` | set minimum threshold for saved space in PERCENT (Default: 10) |
    +-------------------------------------------------------+-------------------------+----------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                   |
    |                                                                                                                                                  |
    | :ref:`common_options`                                                                                                                            |
    +-------------------------------------------------------+-------------------------+----------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    REPOSITORY
        repository to compact


    options
        -n, --dry-run     do nothing
        --cleanup-commits    cleanup commit-only 17-byte segment files
        --threshold PERCENT    set minimum threshold for saved space in PERCENT (Default: 10)


    :ref:`common_options`
        |

Description
~~~~~~~~~~~

This command frees repository space by compacting segments.

Use this regularly to avoid running out of space - you do not need to use this
after each borg command though. It is especially useful after deleting archives,
because only compaction will really free repository space.

borg compact does not need a key, so it is possible to invoke it from the
client or also from the server.

Depending on the amount of segments that need compaction, it may take a while,
so consider using the ``--progress`` option.

A segment is compacted if the amount of saved space is above the percentage value
given by the ``--threshold`` option. If omitted, a threshold of 10% is used.
When using ``--verbose``, borg will output an estimate of the freed space.

For maximum compaction, use ``--threshold 0``. This will compact whenever any
space can be saved and thus rewrites the most data; it can be much slower on
large repositories. Using ``--threshold 1`` usually achieves nearly the same
result significantly faster. Higher thresholds (e.g. the default 10) trade
compaction thoroughness for speed. Note: ``--threshold 100`` will effectively
compact nothing.

After upgrading borg (server) to 1.2+, you can use ``borg compact --cleanup-commits``
to clean up the numerous 17-byte commit-only segments that borg 1.1 did not clean up
due to a bug. It is enough to do that once per repository. After cleaning up the
commits, borg will also do a normal compaction.

See :ref:`separate_compaction` in Additional Notes for more details.
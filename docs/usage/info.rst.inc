.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_info:

borg info
---------
.. code-block:: none

    borg [common options] info [options] [NAME]

.. only:: html

    .. class:: borg-options-table

    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    | **positional arguments**                                                                                                                                                                                                                                 |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``NAME``                                     | specify the archive name                                                                                                    |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                                                                                              |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--json``                                   | format output as JSON                                                                                                       |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                                           |
    |                                                                                                                                                                                                                                                          |
    | :ref:`common_options`                                                                                                                                                                                                                                    |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    | **Archive filters** — Archive filters can be applied to repository targets.                                                                                                                                                                              |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-a PATTERN``, ``--match-archives PATTERN`` | only consider archives matching all patterns. see "borg help match-archives".                                               |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--sort-by KEYS``                           | Comma-separated list of sorting keys; valid keys are: timestamp, archive, name, id, tags, host, user; default is: timestamp |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--first N``                                | consider first N archives after other filters were applied                                                                  |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--last N``                                 | consider last N archives after other filters were applied                                                                   |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--oldest TIMESPAN``                        | consider archives between the oldest archive's timestamp and (oldest + TIMESPAN), e.g. 7d or 12m.                           |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--newest TIMESPAN``                        | consider archives between the newest archive's timestamp and (newest - TIMESPAN), e.g. 7d or 12m.                           |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--older TIMESPAN``                         | consider archives older than (now - TIMESPAN), e.g. 7d or 12m.                                                              |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--newer TIMESPAN``                         | consider archives newer than (now - TIMESPAN), e.g. 7d or 12m.                                                              |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+

    .. raw:: html

        <script type='text/javascript'>
        $(document).ready(function () {
            $('.borg-options-table colgroup').remove();
        })
        </script>

.. only:: latex

    NAME
        specify the archive name


    options
        --json     format output as JSON


    :ref:`common_options`
        |

    Archive filters
        -a PATTERN, --match-archives PATTERN     only consider archives matching all patterns. see "borg help match-archives".
        --sort-by KEYS                           Comma-separated list of sorting keys; valid keys are: timestamp, archive, name, id, tags, host, user; default is: timestamp
        --first N                                consider first N archives after other filters were applied
        --last N                                 consider last N archives after other filters were applied
        --oldest TIMESPAN                        consider archives between the oldest archive's timestamp and (oldest + TIMESPAN), e.g. 7d or 12m.
        --newest TIMESPAN                        consider archives between the newest archive's timestamp and (newest - TIMESPAN), e.g. 7d or 12m.
        --older TIMESPAN                         consider archives older than (now - TIMESPAN), e.g. 7d or 12m.
        --newer TIMESPAN                         consider archives newer than (now - TIMESPAN), e.g. 7d or 12m.


Description
~~~~~~~~~~~

This command displays detailed information about the specified archive.

Please note that the deduplicated sizes of the individual archives do not add
up to the deduplicated size of the repository ("all archives"), because the two
are meaning different things:

This archive / deduplicated size = amount of data stored ONLY for this archive
= unique chunks of this archive.
All archives / deduplicated size = amount of data stored in the repo
= all chunks in the repository.
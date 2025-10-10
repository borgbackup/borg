.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_prune:

borg prune
----------
.. code-block:: none

    borg [common options] prune [options] [NAME]

.. only:: html

    .. class:: borg-options-table

    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------+
    | **positional arguments**                                                                                                                                                                                                       |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------+
    |                                                                             | ``NAME``                                     | specify the archive name                                                                          |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                                                                    |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------+
    |                                                                             | ``-n``, ``--dry-run``                        | do not change repository                                                                          |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------+
    |                                                                             | ``--list``                                   | output verbose list of archives it keeps/prunes                                                   |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------+
    |                                                                             | ``--short``                                  | use a less wide archive part format                                                               |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------+
    |                                                                             | ``--list-pruned``                            | output verbose list of archives it prunes                                                         |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------+
    |                                                                             | ``--list-kept``                              | output verbose list of archives it keeps                                                          |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------+
    |                                                                             | ``--format FORMAT``                          | specify format for the archive part (default: "{archive:<36} {time} [{id}]")                      |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------+
    |                                                                             | ``--keep-within INTERVAL``                   | keep all archives within this time interval                                                       |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------+
    |                                                                             | ``--keep-last``, ``--keep-secondly``         | number of secondly archives to keep                                                               |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------+
    |                                                                             | ``--keep-minutely``                          | number of minutely archives to keep                                                               |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------+
    |                                                                             | ``-H``, ``--keep-hourly``                    | number of hourly archives to keep                                                                 |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------+
    |                                                                             | ``-d``, ``--keep-daily``                     | number of daily archives to keep                                                                  |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------+
    |                                                                             | ``-w``, ``--keep-weekly``                    | number of weekly archives to keep                                                                 |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------+
    |                                                                             | ``-m``, ``--keep-monthly``                   | number of monthly archives to keep                                                                |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------+
    |                                                                             | ``--keep-13weekly``                          | number of quarterly archives to keep (13 week strategy)                                           |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------+
    |                                                                             | ``--keep-3monthly``                          | number of quarterly archives to keep (3 month strategy)                                           |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------+
    |                                                                             | ``-y``, ``--keep-yearly``                    | number of yearly archives to keep                                                                 |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                 |
    |                                                                                                                                                                                                                                |
    | :ref:`common_options`                                                                                                                                                                                                          |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------+
    | **Archive filters** — Archive filters can be applied to repository targets.                                                                                                                                                    |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------+
    |                                                                             | ``-a PATTERN``, ``--match-archives PATTERN`` | only consider archives matching all patterns. see "borg help match-archives".                     |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------+
    |                                                                             | ``--oldest TIMESPAN``                        | consider archives between the oldest archive's timestamp and (oldest + TIMESPAN), e.g. 7d or 12m. |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------+
    |                                                                             | ``--newest TIMESPAN``                        | consider archives between the newest archive's timestamp and (newest - TIMESPAN), e.g. 7d or 12m. |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------+
    |                                                                             | ``--older TIMESPAN``                         | consider archives older than (now - TIMESPAN), e.g. 7d or 12m.                                    |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------+
    |                                                                             | ``--newer TIMESPAN``                         | consider archives newer than (now - TIMESPAN), e.g. 7d or 12m.                                    |
    +-----------------------------------------------------------------------------+----------------------------------------------+---------------------------------------------------------------------------------------------------+

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
        -n, --dry-run         do not change repository
        --list                output verbose list of archives it keeps/prunes
        --short               use a less wide archive part format
        --list-pruned         output verbose list of archives it prunes
        --list-kept           output verbose list of archives it keeps
        --format FORMAT       specify format for the archive part (default: "{archive:<36} {time} [{id}]")
        --keep-within INTERVAL    keep all archives within this time interval
        --keep-last, --keep-secondly    number of secondly archives to keep
        --keep-minutely       number of minutely archives to keep
        -H, --keep-hourly     number of hourly archives to keep
        -d, --keep-daily      number of daily archives to keep
        -w, --keep-weekly     number of weekly archives to keep
        -m, --keep-monthly    number of monthly archives to keep
        --keep-13weekly       number of quarterly archives to keep (13 week strategy)
        --keep-3monthly       number of quarterly archives to keep (3 month strategy)
        -y, --keep-yearly     number of yearly archives to keep


    :ref:`common_options`
        |

    Archive filters
        -a PATTERN, --match-archives PATTERN     only consider archives matching all patterns. see "borg help match-archives".
        --oldest TIMESPAN                        consider archives between the oldest archive's timestamp and (oldest + TIMESPAN), e.g. 7d or 12m.
        --newest TIMESPAN                        consider archives between the newest archive's timestamp and (newest - TIMESPAN), e.g. 7d or 12m.
        --older TIMESPAN                         consider archives older than (now - TIMESPAN), e.g. 7d or 12m.
        --newer TIMESPAN                         consider archives newer than (now - TIMESPAN), e.g. 7d or 12m.


Description
~~~~~~~~~~~

The prune command prunes a repository by soft-deleting all archives not
matching any of the specified retention options.

Important:

- The prune command will only mark archives for deletion ("soft-deletion"),
  repository disk space is **not** freed until you run ``borg compact``.
- You can use ``borg undelete`` to undelete archives, but only until
  you run ``borg compact``.

This command is normally used by automated backup scripts wanting to keep a
certain number of historic backups. This retention policy is commonly referred to as
`GFS <https://en.wikipedia.org/wiki/Backup_rotation_scheme#Grandfather-father-son>`_
(Grandfather-father-son) backup rotation scheme.

The recommended way to use prune is to give the archive series name to it via the
NAME argument (assuming you have the same name for all archives in a series).
Alternatively, you can also use --match-archives (-a), then only archives that
match the pattern are considered for deletion and only those archives count
towards the totals specified by the rules.
Otherwise, *all* archives in the repository are candidates for deletion!
There is no automatic distinction between archives representing different
contents. These need to be distinguished by specifying matching globs.

If you have multiple series of archives with different data sets (e.g.
from different machines) in one shared repository, use one prune call per
series.

The ``--keep-within`` option takes an argument of the form "<int><char>",
where char is "y", "m", "w", "d", "H", "M", or "S".  For example,
``--keep-within 2d`` means to keep all archives that were created within
the past 2 days.  "1m" is taken to mean "31d". The archives kept with
this option do not count towards the totals specified by any other options.

A good procedure is to thin out more and more the older your backups get.
As an example, ``--keep-daily 7`` means to keep the latest backup on each day,
up to 7 most recent days with backups (days without backups do not count).
The rules are applied from secondly to yearly, and backups selected by previous
rules do not count towards those of later rules. The time that each backup
starts is used for pruning purposes. Dates and times are interpreted in the local
timezone of the system where borg prune runs, and weeks go from Monday to Sunday.
Specifying a negative number of archives to keep means that there is no limit.

Borg will retain the oldest archive if any of the secondly, minutely, hourly,
daily, weekly, monthly, quarterly, or yearly rules was not otherwise able to
meet its retention target. This enables the first chronological archive to
continue aging until it is replaced by a newer archive that meets the retention
criteria.

The ``--keep-13weekly`` and ``--keep-3monthly`` rules are two different
strategies for keeping archives every quarter year.

The ``--keep-last N`` option is doing the same as ``--keep-secondly N`` (and it will
keep the last N archives under the assumption that you do not create more than one
backup archive in the same second).

You can influence how the ``--list`` output is formatted by using the ``--short``
option (less wide output) or by giving a custom format using ``--format`` (see
the ``borg repo-list`` description for more details about the format string).
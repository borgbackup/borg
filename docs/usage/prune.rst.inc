.. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!

.. _borg_prune:

borg prune
----------
.. code-block:: none

    borg [common options] prune [options] [NAME]

.. only:: html

    .. class:: borg-options-table

    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **positional arguments**                                                                                                                                                                                                                                                                                                                                             |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``NAME``                                     | specify the archive name                                                                                                                                                                                                                |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **options**                                                                                                                                                                                                                                                                                                                                                          |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-n``, ``--dry-run``                        | do not change the repository                                                                                                                                                                                                            |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--list``                                   | output a verbose list of archives it keeps/prunes                                                                                                                                                                                       |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--short``                                  | use a less wide archive part format                                                                                                                                                                                                     |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--list-pruned``                            | output verbose list of archives it prunes                                                                                                                                                                                               |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--list-kept``                              | output verbose list of archives it keeps                                                                                                                                                                                                |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--format FORMAT``                          | specify format for the archive part (default: "{archive:<36} {time} [{id}]")                                                                                                                                                            |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--json``                                   | Format output as JSON. The form of ``--format`` is ignored, but keys used in it are added to the JSON output. Some keys are always present. Note: JSON can only represent text.                                                         |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--from TIMESTAMP``                         | only consider archives older than this for pruning                                                                                                                                                                                      |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--group-by KEYS``                          | comma-separated list of archive attributes to group the archives by before applying the retention rules to each group separately; valid keys are: name, host, user, tags; default is: name,host; use "" (or "none") to not group at all |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--keep``                                   | number or time interval of archives to keep                                                                                                                                                                                             |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--keep-secondly``                          | number or time interval of secondly archives to keep                                                                                                                                                                                    |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--keep-minutely``                          | number or time interval of minutely archives to keep                                                                                                                                                                                    |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-H``, ``--keep-hourly``                    | number or time interval of hourly archives to keep                                                                                                                                                                                      |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-d``, ``--keep-daily``                     | number or time interval of daily archives to keep                                                                                                                                                                                       |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-w``, ``--keep-weekly``                    | number or time interval of weekly archives to keep                                                                                                                                                                                      |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-m``, ``--keep-monthly``                   | number or time interval of monthly archives to keep                                                                                                                                                                                     |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--keep-13weekly``                          | number or time interval of quarterly archives to keep (13 week strategy)                                                                                                                                                                |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``--keep-3monthly``                          | number or time interval of quarterly archives to keep (3 month strategy)                                                                                                                                                                |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-y``, ``--keep-yearly``                    | number or time interval of yearly archives to keep                                                                                                                                                                                      |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | .. class:: borg-common-opt-ref                                                                                                                                                                                                                                                                                                                                       |
    |                                                                                                                                                                                                                                                                                                                                                                      |
    | :ref:`common_options`                                                                                                                                                                                                                                                                                                                                                |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | **Archive filters** — Archive filters can be applied to repository targets.                                                                                                                                                                                                                                                                                          |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    |                                                                             | ``-a PATTERN``, ``--match-archives PATTERN`` | only consider archives matching all patterns. See "borg help match-archives".                                                                                                                                                           |
    +-----------------------------------------------------------------------------+----------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

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
        -n, --dry-run         do not change the repository
        --list                output a verbose list of archives it keeps/prunes
        --short               use a less wide archive part format
        --list-pruned         output verbose list of archives it prunes
        --list-kept           output verbose list of archives it keeps
        --format FORMAT       specify format for the archive part (default: "{archive:<36} {time} [{id}]")
        --json                Format output as JSON. The form of ``--format`` is ignored, but keys used in it are added to the JSON output. Some keys are always present. Note: JSON can only represent text.
        --from TIMESTAMP      only consider archives older than this for pruning
        --group-by KEYS       comma-separated list of archive attributes to group the archives by before applying the retention rules to each group separately; valid keys are: name, host, user, tags; default is: name,host; use "" (or "none") to not group at all
        --keep                number or time interval of archives to keep
        --keep-secondly       number or time interval of secondly archives to keep
        --keep-minutely       number or time interval of minutely archives to keep
        -H, --keep-hourly     number or time interval of hourly archives to keep
        -d, --keep-daily      number or time interval of daily archives to keep
        -w, --keep-weekly     number or time interval of weekly archives to keep
        -m, --keep-monthly    number or time interval of monthly archives to keep
        --keep-13weekly       number or time interval of quarterly archives to keep (13 week strategy)
        --keep-3monthly       number or time interval of quarterly archives to keep (3 month strategy)
        -y, --keep-yearly     number or time interval of yearly archives to keep


    :ref:`common_options`
        |

    Archive filters
        -a PATTERN, --match-archives PATTERN     only consider archives matching all patterns. See "borg help match-archives".


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

Two separate mechanisms decide what prune does: the archive *selection* determines
which archives are considered at all, and ``--group-by`` determines how the retention
rules subdivide the selected archives.

Without NAME and without --match-archives (-a), *all* archives in the repository are
selected. Give the archive series name via the NAME argument (assuming you have the
same name for all archives in a series) or use --match-archives (-a) to only consider
a subset. NAME is just another way of saying ``-a NAME``, so it can be combined with
--match-archives (-a). All given patterns must match (they are ANDed), thus giving
both narrows down the selection.

The retention rules are applied to each group of selected archives separately, so
that unrelated backup sets do not compete for the same retention slots. By default,
archives are grouped by their series name and the host they were made on
(``--group-by name,host``): ``--keep-daily 7`` keeps 7 daily archives *per series and
host*. Archive series names are not unique in a repository shared by multiple machines
or users - different machines may well use the same series name for their own,
unrelated data - so grouping by the name alone would let one machine's archives push
another machine's archives out of the retention slots.

``--group-by`` accepts a comma-separated list of the archive attributes ``name``,
``host``, ``user`` and ``tags``. Archives without ``host`` / ``user`` metadata (e.g.
archives transferred from a borg 1.x repository) form their own group. Borg's internal
tags (starting with ``@``) do not affect grouping. Give ``--group-by ""`` to not group
at all and apply the rules to all selected archives at once.

Use ``--group-by name`` if several machines back up the same data to the same archive
series on purpose and you want one retention policy for all of them. Add ``user`` if
one machine backs up the same series as different users and each of them should get
their own retention.

So, to prune every series of every host in one call, the default is all you need::

    borg prune --keep-daily 7 --keep-weekly 4

To only consider your own archives, select them - the grouping then applies to the
selection only::

    borg prune -a host:myhost --keep-daily 7 --keep-weekly 4

Note: the ``host:`` / ``user:`` metadata is what the client wrote into the
archive; it is not a permission mechanism. Any client with delete permission
for the repository can prune any archive in it.

Beware of grouping by an attribute that is not stable over time: if e.g. the hostname
changes for every backup run (as it might for containers), each archive ends up in a
group of its own and the retention rules will keep all of them. Set ``BORG_HOSTNAME``
to a stable value in that case, or use ``--group-by name``. Running prune with
``--info`` shows one summary line per group, which makes such a situation visible.


The ``--keep`` option is the simplest way to specify a basic retention
policy. It accepts a count or a time interval for retention (e.g.
``10`` or ``7d``, ``4w``). With a count it keeps at most that many
recent archives; with an interval it keeps all archives created within
that time window. When ``--from`` is given together with an interval
retention, the interval is measured backwards from that timestamp
instead of from the current time. See ``Date and Time`` docs for exact
INTERVAL format.

The ``--keep-secondly``, ``--keep-minutely``, ``--keep-hourly``,
``--keep-daily``, ``--keep-weekly``, ``--keep-monthly``,
``--keep-13weekly``, ``--keep-3monthly``, and ``--keep-yearly`` options
specify time period retention policies. They accept either a count N for
retention or a time interval INTERVAL for retention, same as for ``--keep``.
With a retention count, they keep at most that many archives (one per
period, e.g. one per day or one per month until the retention count is
met). With a retention interval, they keep one archive per period
within that time span (e.g. at most one per day in a span of seven
days, even if some days had none) -- measured from ``--from`` if given,
otherwise from the current time. Specifying a count of ``-1`` (or the
word ``all``) means no limit. A zero count or zero-length interval
keeps nothing.

The ``--from`` option restricts pruning to archives older than the given
TIMESTAMP. Archives made at or after this timestamp are kept unconditionally
as a pre-filter. When ``--from`` is used together with interval-based
``--keep-*`` options (e.g. ``--keep-daily 7d``), the interval is measured
backwards from the given timestamp rather than from the current time.
Count-based retention does not count the unconditionally kept archives.

The ``--keep-13weekly`` and ``--keep-3monthly`` rules are two different
strategies for keeping archives every quarter year.

The oldest archive is kept as long as the coarsest retention rule covers it --
``--keep-yearly=3`` will keep the oldest archive if it couldn't otherwise find
three candidates, ``--keep-yearly=5y`` will keep the oldest archive as long as
it is at or within the 5y interval. This is useful for rolling tiered backup
schemes, where the earliest backup in a retention window should survive until
the next tier's interval naturally replaces it.

When using interval-based pruning with multiple ``--keep-*`` options,
the intervals must be specified in increasing length matching the
periods chosen. For example, ``--keep-daily 7d --keep-weekly 4w`` is
valid, but ``--keep-daily 30d --keep-weekly 7d`` is not, because the
weekly interval is already covered by the daily one and so the weekly
interval is effectively useless. An error is emitted upon running
``borg prune`` if such a combination of flags is given. The order of
flags on the command line is not significant.


A practical approach for recurring backups is to use rules
with increasing coarseness so that most of recent history is kept and
older history gradually thins out with time. For example,
``--keep-daily 7d --keep-weekly 4w --keep-monthly 6`` keeps an
archive per day for the past week, per week for the past month, and
one per month for six months after that. Combine this with ``--from``
to align time windows to calendar boundaries rather than the exact
moment you run prune for more predictable behavior of coarser rules:
``--keep-daily 7d --keep-weekly 4w --from $(date +%F)``.

Count-based retention keeps archives less bound to time. For instance,
``--keep-yearly 3`` retains 3 yearly archives however far back they
span and ``--keep-daily 20`` keeps 20 archives no matter if you missed
a week in between. This can be useful for less regular archive
creation, or if your use case does not map well to specific time
intervals, or if you simply prefer to think of archive retention in
numbers rather than intervals.

For count-based retention, backups selected by more granular rules do
not count towards those of coarser rules. ``--keep 3 --keep-monthly 2``
will first keep the 3 latest archives and then keep 2 monthly archives,
skipping ones that were already kept by ``--keep 3``.

The time that each archive creation started is used to match archives
to pruning periods. Dates and times are interpreted in the local
timezone of your system. Weeks go from Monday to Sunday.


You can influence how the ``--list`` output is formatted by using the ``--short``
option (less wide output) or by giving a custom format using ``--format`` (see
the ``borg repo-list`` description for more details about the format string).